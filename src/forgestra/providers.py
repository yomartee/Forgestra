"""Offline provider contracts. No SDK import, credential lookup or network transport."""

from dataclasses import dataclass
from enum import StrEnum

from forgestra_safety import Blocked, require, strict_json_loads

# Candidate contract checked against public vendor documentation, not live access.
ANTHROPIC_MODEL = "claude-sonnet-5-5"
CLAUDE_ACTION_COMMIT = "6b6870e649b5ff408753befeaee5fc7989d4e6a9"


class Status(StrEnum):
    FINDINGS = "SUCCESS_WITH_FINDINGS"
    EMPTY = "SUCCESS_NO_FINDINGS"
    ERROR = "ERROR"
    UNKNOWN = "UNKNOWN"
    BLOCKED = "BLOCKED"


@dataclass(frozen=True)
class ProviderConfig:
    provider: str = "offline"
    model: str | None = None
    credential_env: str | None = None
    timeout_seconds: int = 30
    max_tokens: int = 4096
    retries: int = 0

    def validate(self):
        if (
            not isinstance(self.provider, str)
            or self.provider not in {"offline", "anthropic"}
            or type(self.timeout_seconds) is not int
            or not 1 <= self.timeout_seconds <= 60
            or type(self.max_tokens) is not int
            or not 1 <= self.max_tokens <= 8192
            or type(self.retries) is not int
            or self.retries != 0
        ):
            raise Blocked("BLOCKED: invalid provider configuration")
        if self.provider == "offline":
            if self.model is not None or self.credential_env is not None:
                raise Blocked("BLOCKED: offline provider accepts no model or credential")
        elif self.credential_env != "ANTHROPIC_API_KEY" or self.model != ANTHROPIC_MODEL:
            raise Blocked("BLOCKED: documented candidate model and canonical credential required")


def live(config: ProviderConfig):
    # Authority is checked before validation, credentials or client construction.
    require("paid_provider")
    raise Blocked("BLOCKED: live transport and model compatibility not verified")


_ABSENT = object()


def configuration(document=_ABSENT):
    if document is _ABSENT:
        return ProviderConfig()
    fields = {"provider", "model", "credential_env", "timeout_seconds", "max_tokens", "retries"}
    if not isinstance(document, dict) or set(document) != fields:
        raise Blocked("BLOCKED: invalid provider configuration schema")
    config = ProviderConfig(**document)
    config.validate()
    return config


def sanitized(value):
    """Redact data before JSON escaping; never rewrite schema keys or primitives."""
    from forgestra_safety import redact

    if isinstance(value, str):
        return redact(value)
    if isinstance(value, list):
        return [sanitized(item) for item in value]
    if isinstance(value, dict):
        return {key: sanitized(item) for key, item in value.items()}
    return value


def request_proposal(config: ProviderConfig, prompt: str):
    """Build an inert bounded request contract; never instantiate a transport."""
    config.validate()
    if (
        config.provider != "anthropic"
        or not isinstance(prompt, str)
        or not 1 <= len(prompt) <= 200000
    ):
        raise Blocked("BLOCKED: invalid request proposal")
    return {
        "status": Status.BLOCKED,
        "execution": "DISABLED",
        "credential_env": config.credential_env,
        "timeout_seconds": config.timeout_seconds,
        "retries": config.retries,
        "request": {
            "model": config.model,
            "max_tokens": config.max_tokens,
            "messages": [{"role": "user", "content": sanitized(prompt)}],
        },
    }


def action_proposal(config: ProviderConfig):
    """Pinned interface proposal only; no executable workflow or auth expression."""
    config.validate()
    if config.provider != "anthropic":
        raise Blocked("BLOCKED: action requires explicit provider contract")
    return {
        "status": Status.BLOCKED,
        "execution": "DISABLED",
        "uses": "anthropics/claude-code-action@" + CLAUDE_ACTION_COMMIT,
        "with": {"claude_args": "--model " + ANTHROPIC_MODEL},
        "credential_binding": {"input": "anthropic_api_key", "environment": config.credential_env},
        "live_compatibility": "NOT_RUN",
    }


def replay(document):
    """Parse an explicitly labelled fixture, never a live/provider success claim."""
    if not isinstance(document, dict) or set(document) != {"kind", "response"}:
        return Status.ERROR, None, "INVALID_FIXTURE"
    if document["kind"] != "OFFLINE_REPLAY":
        return Status.ERROR, None, "INVALID_FIXTURE"
    response = document["response"]
    if not isinstance(response, dict):
        return Status.ERROR, None, "INVALID_RESPONSE"
    if response.get("type") == "error":
        # Never forward provider error strings, headers or credentials.
        return Status.ERROR, None, "PROVIDER_ERROR"
    if response.get("type") != "message":
        return Status.ERROR, None, "INVALID_RESPONSE"
    stop = response.get("stop_reason")
    if stop == "refusal":
        return Status.UNKNOWN, None, "PROVIDER_REFUSAL"
    if stop != "end_turn":
        return Status.UNKNOWN, None, "INCOMPLETE_RESPONSE"
    content = response.get("content")
    if (
        not isinstance(content, list)
        or not content
        or any(
            not isinstance(block, dict)
            or set(block) != {"type", "text"}
            or block["type"] != "text"
            or not isinstance(block["text"], str)
            for block in content
        )
    ):
        return Status.ERROR, None, "UNSUPPORTED_CONTENT"
    text = "".join(block["text"] for block in content)
    if len(text) > 1_000_000:
        return Status.ERROR, None, "OVERSIZED_RESPONSE"
    try:
        return None, strict_json_loads(text), None
    except (ValueError, TypeError, RecursionError):
        return Status.ERROR, None, "INVALID_JSON"
