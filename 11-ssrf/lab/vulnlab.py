"""
Shared helpers for WildWebApps labs.

Keep this file identical across labs (it's copied from _template/). It provides:
  - generate_flag():  a fresh random MD5 hex string (call once per process)
  - check_flag():     safe comparison of a submitted answer
  - plant_in_file():  write the flag to disk (path / command-injection labs)
  - lab_context():    build the dict the index template expects
"""
import hashlib
import secrets


def generate_flag() -> str:
    """Return a fresh random 32-char MD5 hex string. Rotates each process start."""
    return hashlib.md5(secrets.token_bytes(16)).hexdigest()


def check_flag(expected: str, submitted: str) -> bool:
    """Case-insensitive, whitespace-trimmed, length-safe comparison."""
    if not submitted:
        return False
    candidate = submitted.strip().lower()
    try:
        return secrets.compare_digest(candidate, expected.lower())
    except TypeError:
        # Non-ASCII input can't match an MD5 hex flag.
        return False


def plant_in_file(flag: str, path: str) -> None:
    """Write the flag to a file on disk - for path/command-injection labs."""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(flag + "\n")


DEFAULT_CONTEXT = {
    "title": "WildWebApps Lab",
    "owasp": "A00:2025 - Template",
    "summary": "",
    "instructions": [],   # list[str]
    "hints": [],          # list[str]
    "languages": {},      # { "Python": {"vuln": str, "fixed": str, "doc": str} }
    "references": [],      # list[(label, url)]
}


def lab_context(**overrides):
    """Merge overrides onto the default page context."""
    ctx = dict(DEFAULT_CONTEXT)
    ctx.update(overrides)
    return ctx
