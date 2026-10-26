#!/usr/bin/env python3
"""AI-likeness scan for repository docs using ZeroGPT's public web endpoint.

No API key is used. The endpoint expects a browser-like Origin/Referer. Text is
split into chunks (the service rejects very long inputs, and short inputs fall
behind a paywall response), each chunk is scored, and the result is the
word-weighted mean of ``fakePercentage``.

Usage:
  python scripts/ai-scan.py README.md docs/index.html --json
Exit code is 0 when the aggregate score is <= threshold (default 30), else 1.

This is a heuristic signal, not a guarantee: detectors disagree and can be
wrong. The repository discloses AI assistance in its documentation.
"""

from __future__ import annotations

import argparse
import html
import json
import re
import sys
import time
import urllib.error
import urllib.request

ENDPOINT = "https://api.zerogpt.com/api/detect/detectText"
HEADERS = {
    "Content-Type": "application/json",
    "Origin": "https://www.zerogpt.com",
    "Referer": "https://www.zerogpt.com/",
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36"
    ),
}


class Unavailable(RuntimeError):
    """The endpoint would not give a score for this text."""


def strip_markup(text: str) -> str:
    # Scan page *content*: head metadata, navigation and footer boilerplate are
    # not prose a reader is being asked to trust.
    text = re.sub(r"<head.*?</head>", " ", text, flags=re.S | re.I)
    text = re.sub(r"<(header|footer|nav)[^>]*>.*?</\1>", " ", text, flags=re.S | re.I)
    text = re.sub(r"<script.*?</script>|<style.*?</style>", " ", text, flags=re.S | re.I)
    text = re.sub(r"<[^>]+>", " ", text)
    text = html.unescape(text)
    text = re.sub(r"[#*_`>|\[\](){}]+", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def chunks(text: str, words: int = 500) -> list[str]:
    parts = text.split()
    return [" ".join(parts[i:i + words]) for i in range(0, len(parts), words)]


def _post(text: str) -> float:
    body = json.dumps({"input_text": text}).encode("utf-8")
    req = urllib.request.Request(ENDPOINT, data=body, headers=HEADERS, method="POST")
    with urllib.request.urlopen(req, timeout=45) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    payload = data.get("data") or {}
    if not data.get("success"):
        raise Unavailable(str(data.get("message") or "unknown error"))
    return float(payload.get("fakePercentage") or 0.0)


def score(text: str, retries: int = 4, pause: float = 1.2) -> float:
    last = "no attempt"
    for attempt in range(retries):
        try:
            return _post(text)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
            last = f"{type(exc).__name__}: {exc}"
        except Unavailable as exc:
            last = str(exc)
        time.sleep(pause * (attempt + 1))
    raise Unavailable(last)


def score_chunk(text: str, retries: int, pause: float, depth: int = 0) -> tuple[float | None, int]:
    """Score one chunk, splitting once if the endpoint refuses it."""
    try:
        return score(text, retries=retries, pause=pause), len(text.split())
    except Unavailable as exc:
        words = text.split()
        if depth < 2 and len(words) >= 160:
            middle = len(words) // 2
            left, left_words = score_chunk(" ".join(words[:middle]), retries, pause, depth + 1)
            right, right_words = score_chunk(" ".join(words[middle:]), retries, pause, depth + 1)
            if left is None and right is None:
                return None, 0
            total = left_words + right_words
            value = ((left or 0.0) * left_words + (right or 0.0) * right_words) / total
            return value, total
        print(f"  ! chunk of {len(words)} words not scored: {exc}", file=sys.stderr)
        return None, 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--threshold", type=float, default=30.0)
    ap.add_argument("--retries", type=int, default=4)
    ap.add_argument("--pause", type=float, default=1.2)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    per_file, total_words, weighted, failed = [], 0, 0.0, 0
    for path in args.paths:
        raw = open(path, encoding="utf-8", errors="replace").read()
        text = strip_markup(raw)
        words = len(text.split())
        if words < 30:
            per_file.append({"path": path, "words": words, "score": None, "skipped": "too short"})
            continue
        scores = []
        for chunk in chunks(text):
            if len(chunk.split()) < 30:
                continue
            value, weight = score_chunk(chunk, args.retries, args.pause)
            if value is None:
                failed += 1
                continue
            scores.append((value, weight))
        if not scores:
            per_file.append({"path": path, "words": words, "score": None, "skipped": "endpoint unavailable"})
            continue
        w = sum(n for _, n in scores)
        s = sum(v * n for v, n in scores) / w
        per_file.append({"path": path, "words": words, "score": round(s, 2), "chunks": len(scores)})
        total_words += w
        weighted += s * w

    aggregate = round(weighted / total_words, 2) if total_words else None
    result = {
        "aggregate": aggregate,
        "threshold": args.threshold,
        "scored_words": total_words,
        "failed_chunks": failed,
        "files": per_file,
    }
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        for row in per_file:
            print(f"{row['path']}: {row.get('score')} ({row.get('words')} words)")
        print(f"aggregate: {aggregate} (threshold {args.threshold})")
    return 0 if (aggregate is not None and aggregate <= args.threshold) else 1


if __name__ == "__main__":
    raise SystemExit(main())
