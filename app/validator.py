"""
Input validation layer — prevents command injection.

Only whitelisted tools and flags are allowed through. Targets are validated
to contain only safe characters (hostnames, IPs, URLs).
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

_TOOLS_DIR = Path(__file__).resolve().parent.parent / "tools"

# Target must be a hostname, IPv4/v6, CIDR, or URL — no shell metacharacters.
_TARGET_RE = re.compile(
    r"^[a-zA-Z0-9\.\-\:\/\[\]_%@]+$"
)

# Flags that are never allowed regardless of tool config.
_GLOBAL_DENY = frozenset({
    "--interactive", "-i",
    "--shell", "--exec",
})

# Shell metacharacters that must never appear in any argument.
_SHELL_META = re.compile(r"[;&|`$(){}!><\n\r]")


def load_tool_config(tool: str) -> dict | None:
    """Load a tool's YAML config from /tools/<tool>.yml."""
    path = _TOOLS_DIR / f"{tool}.yml"
    if not path.is_file():
        return None
    with open(path) as fh:
        return yaml.safe_load(fh)


# Keep private alias for internal use.
_load_tool_config = load_tool_config


def validate_target(target: str) -> str | None:
    """Return an error string if the target is unsafe, else None."""
    if _SHELL_META.search(target):
        return f"Target contains forbidden characters: {target!r}"
    if not _TARGET_RE.match(target):
        return f"Target does not match allowed pattern: {target!r}"
    return None


def validate_tool_and_flags(
    tool: str, flags: list[str]
) -> tuple[list[str], str | None]:
    """
    Validate tool existence and flags against its allowlist.

    Returns (resolved_args, error). If error is not None, the request
    must be rejected.
    """
    config = _load_tool_config(tool)
    if config is None:
        return [], f"Unknown or unsupported tool: {tool!r}"

    allowed_flags: set[str] = set(config.get("allowed_flags", []))
    binary: str = config.get("binary", tool)
    default_flags: list[str] = list(config.get("default_flags", []))

    resolved = list(default_flags)

    for flag in flags:
        # Block globally denied flags.
        if flag in _GLOBAL_DENY:
            return [], f"Flag {flag!r} is globally denied"

        # Block any shell metacharacters in flag values.
        if _SHELL_META.search(flag):
            return [], f"Flag contains forbidden characters: {flag!r}"

        # Check flag key (the part before '=') against the allowlist.
        flag_key = flag.split("=", 1)[0]
        if flag_key not in allowed_flags:
            return [], f"Flag {flag_key!r} is not allowed for {tool}"

        resolved.append(flag)

    return resolved, None
