from __future__ import annotations

import locale
import os
import re
import subprocess
from typing import Any, Mapping

_ANSI_ESCAPE_RE = re.compile(
    r"(?:\x1B[@-_][0-?]*[ -/]*[@-~]|\x9B[0-?]*[ -/]*[@-~])"
)
_OSC_RE = re.compile(r"\x1b\][^\x07]*(?:\x07|\x1b\\)")


def hidden_process_kwargs(*, new_process_group: bool = False) -> dict[str, Any]:
    """Return subprocess kwargs that prevent console-window flashes on Windows."""
    if os.name != "nt":
        return {}

    flags = int(getattr(subprocess, "CREATE_NO_WINDOW", 0))
    if new_process_group:
        flags |= int(getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0))
    return {"creationflags": flags} if flags else {}


def diagnostic_subprocess_env(env: Mapping[str, str] | None = None) -> dict[str, str]:
    """Return a deterministic, UTF-8, non-colour environment for captured diagnostics.

    Windows Python writes to pipes using the active locale unless explicitly told
    otherwise.  The launcher reads the same pipe as UTF-8, which used to turn
    characters such as an em dash into U+FFFD (the visible black-diamond `�`).
    Force Python children to UTF-8 and ask common CLI tools to disable ANSI colour.
    """
    out = dict(os.environ if env is None else env)
    out["PYTHONUTF8"] = "1"
    out["PYTHONIOENCODING"] = "utf-8:replace"
    out["NO_COLOR"] = "1"
    out["FORCE_COLOR"] = "0"
    out.setdefault("TERM", "dumb")
    return out


def clean_process_text(value: str) -> str:
    """Strip terminal control sequences and normalize captured text for evidence/logs."""
    if not value:
        return ""
    text = _OSC_RE.sub("", value)
    text = _ANSI_ESCAPE_RE.sub("", text)
    # Keep tabs/newlines; remove other C0 controls that make Tk/cmd logs unreadable.
    text = "".join(ch for ch in text if ch in "\n\r\t" or ord(ch) >= 32)
    return text.replace("\r\n", "\n").replace("\r", "\n")


def decode_process_output(value: bytes | str | None) -> str:
    """Decode captured output without silently corrupting Windows code-page text."""
    if value is None:
        return ""
    if isinstance(value, str):
        return clean_process_text(value)

    # BOM-aware UTF encodings first.
    if value.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            return clean_process_text(value.decode("utf-16"))
        except UnicodeDecodeError:
            pass
    if value.startswith(b"\xef\xbb\xbf"):
        try:
            return clean_process_text(value.decode("utf-8-sig"))
        except UnicodeDecodeError:
            pass

    encodings = ["utf-8"]
    preferred = locale.getpreferredencoding(False)
    if preferred and preferred.lower().replace("-", "") != "utf8":
        encodings.append(preferred)
    # French/Western Windows native tools commonly emit CP1252 to redirected pipes.
    encodings.extend(["cp1252", "cp850"])

    seen: set[str] = set()
    for encoding in encodings:
        key = encoding.lower()
        if key in seen:
            continue
        seen.add(key)
        try:
            return clean_process_text(value.decode(encoding, errors="strict"))
        except (LookupError, UnicodeDecodeError):
            continue

    return clean_process_text(value.decode("utf-8", errors="replace")).replace("\ufffd", "?")
