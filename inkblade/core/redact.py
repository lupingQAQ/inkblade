"""脱敏工具：凭据只留尾4位指纹；PII 文本样张遮蔽。窃取/泄露类模块共用。"""

from __future__ import annotations

import re

# 凭据形态（命中即视为敏感值，展示仅保留尾4位）
CRED_VALUE_RE = re.compile(
    r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"          # AWS access key
    r"|\bhf_[A-Za-z0-9]{20,}\b"               # HuggingFace token
    r"|\bghp_[A-Za-z0-9]{20,}\b"              # GitHub PAT
    r"|\bgho_[A-Za-z0-9]{20,}\b"
    r"|\bsk-[A-Za-z0-9]{20,}\b"               # OpenAI 风格 key
    r"|\bxox[baprs]-[A-Za-z0-9-]{10,}\b"      # Slack token
)

# 赋值形态：NAME_TOKEN=... / PASSWORD=... / SECRET=...
_ASSIGN_RE = re.compile(
    r"(?im)^(?:export\s+)?([A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|CREDENTIAL)[A-Z0-9_]*)=(\S{8,})\s*$"
)

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_PHONE_RE = re.compile(r"(?<!\d)1[3-9]\d[- ]?\d{4}[- ]?\d{4}(?!\d)")


def cred(value: str) -> str:
    """凭据脱敏：仅返回尾4位；不足4位全部遮蔽。"""
    value = str(value)
    if len(value) <= 4:
        return "*" * len(value)
    return value[-4:]


def pii(text: str) -> str:
    """PII 文本脱敏（样张用）：邮箱/手机号遮蔽，凭据留尾4位。"""
    text = CRED_VALUE_RE.sub(lambda m: "****" + cred(m.group(0)), text)
    text = _EMAIL_RE.sub("***@***.***", text)
    text = _PHONE_RE.sub("1**********", text)
    return text


def redact_line(line: str) -> str:
    """整行脱敏：先处理赋值形态（保留变量名），再套用通用 PII/凭据规则。"""

    def _assign(m: re.Match) -> str:
        return f"{m.group(1)}=****{cred(m.group(2))}"

    return pii(_ASSIGN_RE.sub(_assign, line))
