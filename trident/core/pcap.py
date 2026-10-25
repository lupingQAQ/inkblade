# -*- coding: utf-8 -*-
"""pcap 级录制与回放（CM-18 等价）：traffic ↔ pcap 双向转换。

能力边界（诚实声明）：
- 支持**把已录制的 HTTP 请求/响应**写成标准 libpcap（Ethernet/IPv4/TCP，含校验和），
  以及从 pcap 解析回 HTTP 请求/响应 → traffic 表 → 断言回放；
- **不做**在线 MITM 抓包：那需要宿主机/网卡混杂模式、流量镜像或特权网络位置，
  不是本工具（无特权、默认离线）能安全提供的能力；由运维在授权网络位置采集 pcap，
  再用本模块导入即可获得同等证据链与回放能力。
- 解析只针对 Ethernet + IPv4 + TCP，单包负载上限 1MB；不解析 TLS 密文。

安全：导入 pcap 只读文件；回放走 ``core/traffic.replay`` 的 ROE/角色闸门。
"""

from __future__ import annotations

import hashlib
import json
import shutil
import socket
import struct
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

MAX_PAYLOAD = 1024 * 1024
MAGIC = 0xA1B2C3D4


class PcapError(ValueError):
    """pcap 文件/流量参数非法。"""


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _ip(text: str) -> bytes:
    try:
        return socket.inet_aton(text)
    except OSError:
        return socket.inet_aton("10.0.0.1")


def _mac(seed: int) -> bytes:
    return bytes([0x02, 0x00, 0x00, 0x00, (seed >> 8) & 0xFF, seed & 0xFF])


def _tcp_packet(src_ip: str, dst_ip: str, sport: int, dport: int, payload: bytes,
                seq: int, ack: int, *, ts: float, flags: int = 0x18,
                ident: int = 1) -> bytes:
    eth = _mac(2) + _mac(1) + b"\x08\x00"
    total_len = 20 + 20 + len(payload)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_len, ident & 0xFFFF, 0x4000,
                     64, 6, 0, _ip(src_ip), _ip(dst_ip))
    ip = ip[:10] + struct.pack("!H", _checksum(ip)) + ip[12:]
    tcp = struct.pack("!HHIIBBHHH", sport & 0xFFFF, dport & 0xFFFF,
                      seq & 0xFFFFFFFF, ack & 0xFFFFFFFF, 0x50, flags, 32768, 0, 0)
    pseudo = _ip(src_ip) + _ip(dst_ip) + struct.pack("!BBH", 0, 6, len(tcp) + len(payload))
    csum = _checksum(pseudo + tcp + payload)
    tcp = tcp[:16] + struct.pack("!H", csum) + tcp[18:]
    frame = eth + ip + tcp + payload
    sec = int(ts)
    usec = int((ts - sec) * 1_000_000) & 0xFFFFFF
    return struct.pack("<IIII", sec, usec, len(frame), len(frame)) + frame


def _http_request(entry: dict) -> bytes:
    url = str(entry.get("url") or "")
    parts = urlsplit(url)
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    method = str(entry.get("method") or "GET").upper()
    host = parts.hostname or "target.local"
    if parts.port:
        host = f"{host}:{parts.port}"
    headers = {"Host": host, "User-Agent": "Trident-PCAP/1",
               "Connection": "close",
               "X-Trident-Original-URL": url}
    body = entry.get("req_body")
    if body not in (None, "", "null"):
        headers["Content-Type"] = "application/json"
    lines = [f"{method} {path} HTTP/1.1"] + [f"{k}: {v}" for k, v in headers.items()]
    payload = body if isinstance(body, str) else ""
    if payload:
        lines.append(f"Content-Length: {len(payload.encode('utf-8'))}")
    raw = ("\r\n".join(lines) + "\r\n\r\n" + payload).encode("utf-8")
    return raw


def _http_response(entry: dict) -> bytes:
    status = int(entry.get("status") or 0)
    body = entry.get("resp_body")
    text = "" if body is None else (body if isinstance(body, str) else json.dumps(body, ensure_ascii=False))
    raw_body = text.encode("utf-8")
    reason = {200: "OK", 201: "Created", 204: "No Content", 400: "Bad Request",
              401: "Unauthorized", 403: "Forbidden", 404: "Not Found",
              500: "Internal Server Error"}.get(status, "Status")
    head = (f"HTTP/1.1 {status} {reason}\r\nContent-Type: application/json; charset=utf-8\r\n"
            f"Content-Length: {len(raw_body)}\r\nConnection: close\r\n\r\n").encode("utf-8")
    return head + raw_body


def write_pcap(entries: list[dict], path: Path | str) -> int:
    """traffic 条目 → pcap；返回写入的请求/响应对数。"""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    frames = []
    base = time.time()
    for i, entry in enumerate(entries or []):
        parts = urlsplit(str(entry.get("url") or ""))
        try:
            dport = int(parts.port or (443 if parts.scheme == "https" else 80))
        except ValueError:
            dport = 80
        sport = 40000 + (i % 1000)
        req = _http_request(entry)
        if len(req) > MAX_PAYLOAD:
            raise PcapError("请求超过 1MB 上限")
        ts = float(entry.get("ts") or base + i * 0.01)
        frames.append(_tcp_packet("10.0.0.2", "10.0.0.1", sport, dport, req,
                                  seq=1000 + i * 10000, ack=1, ts=ts, ident=i + 1))
        if entry.get("status"):
            resp = _http_response(entry)
            if len(resp) > MAX_PAYLOAD:
                raise PcapError("响应超过 1MB 上限")
            frames.append(_tcp_packet("10.0.0.1", "10.0.0.2", dport, sport, resp,
                                      seq=900000 + i * 10000, ack=1001 + i * 10000,
                                      ts=ts + 0.001, ident=1000 + i))
    header = struct.pack("<IHHIIII", MAGIC, 2, 4, 0, 0, 65535, 1)
    p.write_bytes(header + b"".join(frames))
    return len(frames)


def record_run(run, path: Path | str, *, module: str = "") -> dict:
    entries = [t for t in run.traffic if not module or t.get("module") == module]
    if not entries:
        raise PcapError("run 无已录制流量（先 ingest_run）")
    n = write_pcap(entries, path)
    step = run.add_step("pcap-record", "pcap", {"path": str(path), "entries": len(entries)},
                        f"pcap 录制 {len(entries)} 条流量", artifacts=[Path(path)])
    run.log_action("pcap", "record", str(path),
                   {"entries": len(entries), "frames": n, "step": step["archive"]}, "success")
    return {"run": run.name, "path": str(path), "entries": len(entries), "frames": n,
            "step": step["archive"]}


def _parse_pcap(data: bytes) -> list[dict]:
    if len(data) < 24:
        raise PcapError("pcap 头不足 24 字节")
    magic = struct.unpack("<I", data[:4])[0]
    if magic == MAGIC:
        endian = "<"
    elif struct.unpack(">I", data[:4])[0] == MAGIC:
        endian = ">"
    else:
        raise PcapError("不支持的 pcap magic（仅经典 libpcap）")
    _, _major, _minor, _tz, _sig, snaplen, linktype = struct.unpack(endian + "IHHIIII", data[:24])
    if linktype != 1:
        raise PcapError(f"仅支持 Ethernet（linktype=1），得到 {linktype}")
    packets = []
    off = 24
    while off + 16 <= len(data):
        sec, usec, incl, _orig = struct.unpack(endian + "IIII", data[off:off + 16])
        off += 16
        frame = data[off:off + incl]
        off += incl
        if len(frame) < 14 + 20:
            continue
        if struct.unpack("!H", frame[12:14])[0] != 0x0800:
            continue
        ip = frame[14:]
        ihl = (ip[0] & 0x0F) * 4
        if len(ip) < ihl + 20 or ip[9] != 6:
            continue
        total_len = struct.unpack("!H", ip[2:4])[0]
        src_ip = socket.inet_ntoa(ip[12:16])
        dst_ip = socket.inet_ntoa(ip[16:20])
        tcp = ip[ihl:total_len]
        if len(tcp) < 20:
            continue
        sport, dport, seq = struct.unpack("!HHI", tcp[:8])
        doff = (tcp[12] >> 4) * 4
        payload = tcp[doff:]
        if payload:
            packets.append({"ts": sec + usec / 1_000_000, "src": f"{src_ip}:{sport}",
                            "dst": f"{dst_ip}:{dport}", "seq": seq, "payload": payload})
    return packets


def _headers_and_body(raw: bytes) -> tuple[dict, str]:
    head, _, body = raw.partition(b"\r\n\r\n")
    headers = {}
    for line in head.split(b"\r\n")[1:]:
        k, _, v = line.partition(b":")
        if k:
            headers[k.decode("latin-1").strip()] = v.decode("latin-1").strip()
    return headers, body.decode("utf-8", "replace")


def read_pcap(path: Path | str) -> list[dict]:
    try:
        raw = Path(path).read_bytes()
    except OSError as exc:
        raise PcapError(f"pcap 文件不可读：{exc}") from exc
    packets = _parse_pcap(raw)
    flows: dict[tuple, list[dict]] = {}
    for p in packets:
        flows.setdefault((p["src"], p["dst"]), []).append(p)
    entries = []
    for (src, dst), reqs in list(flows.items()):
        req_payload = b"".join(p["payload"] for p in sorted(reqs, key=lambda x: (x["ts"], x["seq"])))
        if not req_payload.startswith(tuple(
                m.encode() for m in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"))):
            continue
        headers, req_body = _headers_and_body(req_payload)
        line = req_payload.split(b"\r\n", 1)[0].decode("latin-1")
        try:
            method, target, _proto = line.split(" ", 2)
        except ValueError:
            continue
        host = headers.get("Host", "")
        original = headers.get("X-Trident-Original-URL", "")
        if original.startswith(("http://", "https://")):
            url = original
        else:
            url = f"http://{host}{target}" if host else target
        status, resp_body = 0, ""
        resp_flow = flows.get((dst, src), [])
        if resp_flow:
            resp_payload = b"".join(p["payload"] for p in sorted(resp_flow, key=lambda x: (x["ts"], x["seq"])))
            if resp_payload.startswith(b"HTTP/"):
                first = resp_payload.split(b"\r\n", 1)[0].decode("latin-1")
                try:
                    status = int(first.split(" ")[1])
                except (IndexError, ValueError):
                    status = 0
                _, resp_body = _headers_and_body(resp_payload)
        entries.append({
            "method": method, "url": url, "headers": headers, "req_body": req_body,
            "status": status, "response": resp_body, "error": "", "ts": reqs[0]["ts"],
            "sha256": hashlib.sha256(req_payload + resp_body.encode("utf-8")).hexdigest(),
        })
    return entries


def ingest_pcap(store, pcap_path: Path | str, *, run_name: str = "", module: str = "pcap") -> dict:
    entries = read_pcap(pcap_path)
    if not entries:
        raise PcapError("pcap 无 HTTP 请求可导入")
    if run_name:
        try:
            run = store.open_run(run_name)
        except KeyError as exc:
            raise PcapError(f"run 不存在：{run_name}") from exc
    else:
        run = store.create_run(f"pcap-{time.strftime('%Y%m%d-%H%M%S')}")
    n = run.record_traffic(module, entries)
    imp_dir = Path(run.dir) / "imports"
    imp_dir.mkdir(parents=True, exist_ok=True)
    cap = imp_dir / f"{module}-{hashlib.sha256(Path(pcap_path).read_bytes()).hexdigest()[:8]}.pcap"
    shutil.copyfile(pcap_path, cap)
    step = run.add_step(f"pcap-{module}", "pcap-import",
                        {"source": str(pcap_path), "module": module},
                        f"pcap 导入 {n} 条流量", artifacts=[cap])
    run.log_action("pcap", "ingest", str(pcap_path),
                   {"entries": n, "module": module, "step": step["archive"]}, "success")
    return {"run": run.name, "module": module, "entries": n, "imported": len(entries),
            "step": step["archive"]}


def replay_pcap(store, session, pcap_path: Path | str, *, live: bool = False,
                run_name: str = "") -> dict:
    from . import traffic

    ing = ingest_pcap(store, pcap_path, run_name=run_name)
    plan = traffic.replay(store, session, ing["run"], module=ing["module"], live=live)
    return {**ing, "replay": plan}
