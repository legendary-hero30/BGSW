"""Secret redaction. Applied before text reaches a model and before it is logged or stored.

Repository files are untrusted and may contain real credentials (AGENTS.md section 2: "Redact
secrets before sending anything to an LLM"). This is pattern-based, so it is a safety net, not a
guarantee: it catches common token shapes, PEM private keys, key=value secrets, and the exact
value of any configured API key found in the environment.
"""

from __future__ import annotations

import os
import re

REDACTED = "[REDACTED]"

PATTERNS = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.DOTALL),
    re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    re.compile(r"\bxox[abprs]-[0-9A-Za-z-]{10,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{16,}"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
)
ASSIGNMENT = re.compile(
    r"""(?ix)
    (\b[\w.-]*(?:password|passwd|secret|token|api[_-]?key|private[_-]?key|credential)[\w.-]*
     ["']?\s*[:=]\s*)
    (?:"[^"\n]{6,}"|'[^'\n]{6,}'|[^\s"',;]{6,})
    """
)
ENV_KEYS = ("DEEPINFRA_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GITHUB_TOKEN")


def _configured_secrets() -> list[str]:
    return [v for k in ENV_KEYS if (v := os.environ.get(k)) and len(v) >= 8]


def redact(text: str) -> str:
    """Return ``text`` with credentials replaced by ``[REDACTED]``."""
    if not text:
        return text
    for secret in _configured_secrets():
        text = text.replace(secret, REDACTED)
    for pattern in PATTERNS:
        text = pattern.sub(REDACTED, text)
    return ASSIGNMENT.sub(lambda m: f"{m.group(1)}{REDACTED}", text)


def redact_obj(value):
    """Recursively redact every string in a JSON-like structure."""
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, dict):
        return {k: redact_obj(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [redact_obj(v) for v in value]
    return value
