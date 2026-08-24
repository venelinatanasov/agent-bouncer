"""Command matching against the human-owned allowlist.

Two layers, both must pass:

1. Well-formedness: the command must be clean printable text. Anything with
   control/escape bytes is rejected outright (fail closed) rather than
   guessed at.
2. Allowlist match: the command must match one of the configured glob
   patterns (fnmatch-style). If the command contains a "guarded"
   shell metacharacter, it only passes if the *matching* pattern was
   explicitly marked `allow_metachars: true` — this stops a broad prefix
   pattern like "systemctl status *" from being used to smuggle a second
   command through via "; rm -rf /".

Guarded characters differ slightly by device mode: exec-mode targets are
real Unix shells where "|" genuinely pipes into another process, so it's
guarded. shell-line targets (network-appliance CLIs such as PAN-OS) use
"|" as a built-in output filter, not a shell pipe, so it's allowed by
default there.
"""
from __future__ import annotations

import fnmatch
import string

from .config import AllowRule

_ALLOWED_BARE_CHARS = set(string.printable) - {"\t", "\x0b", "\x0c", "\r", "\n"}

GUARDED_CHARS_EXEC = set(";&|`")
GUARDED_CHARS_SHELL_LINE = set(";&`")

GUARDED_SUBSTRINGS = ("$(", "<(", ">(")


def is_well_formed(command: str) -> bool:
    """Reject anything that isn't clean, single-line printable text."""
    if not command:
        return False
    if any(ch not in _ALLOWED_BARE_CHARS for ch in command):
        return False
    return True


def _guarded_chars_for_mode(mode: str) -> set[str]:
    return GUARDED_CHARS_EXEC if mode == "exec" else GUARDED_CHARS_SHELL_LINE


def has_guarded_metachar(command: str, mode: str) -> bool:
    guarded = _guarded_chars_for_mode(mode)
    if any(ch in guarded for ch in command):
        return True
    if any(sub in command for sub in GUARDED_SUBSTRINGS):
        return True
    return False


def check_command(command: str, rules: list[AllowRule], mode: str) -> tuple[bool, str]:
    """Return (allowed, reason)."""
    if not is_well_formed(command):
        return False, "malformed input (control/escape characters or empty)"

    guarded = has_guarded_metachar(command, mode)

    matched_rule = None
    for rule in rules:
        if fnmatch.fnmatchcase(command, rule.pattern):
            matched_rule = rule
            break

    if matched_rule is None:
        return False, "no matching allowlist entry"

    if guarded and not matched_rule.allow_metachars:
        return False, f"matched '{matched_rule.pattern}' but contains a guarded shell metacharacter"

    return True, f"matched '{matched_rule.pattern}'"
