from __future__ import annotations
import os
from pathlib import Path


_SAMPLE_BYTES = 8192
_TEXT_CONTROL_BYTES = {7, 8, 9, 10, 12, 13, 27}


def iter_files(root: Path, cfg, *, max_files=None, stats=None):
    scan=cfg.get("scan",{})
    excluded=set(scan.get("exclude_dirs",[]))
    max_files=int(max_files or scan.get("max_files",20000))
    count=0
    state = stats if stats is not None else {}
    state.setdefault("files_yielded", 0)
    state.setdefault("limit_reached", False)
    for base,dirs,files in os.walk(root):
        dirs[:]=[d for d in dirs if d not in excluded]
        for name in files:
            if count >= max_files:
                state["limit_reached"] = True
                return
            p=Path(base)/name
            try: rel=p.relative_to(root).as_posix()
            except Exception: continue
            yield p,rel
            count+=1
            state["files_yielded"] = count


def _looks_binary(sample: bytes) -> bool:
    """Conservatively identify obvious binary content from a bounded sample."""
    if not sample:
        return False
    if b"\x00" in sample:
        return True

    non_text = sum(
        1 for byte in sample
        if byte < 32 and byte not in _TEXT_CONTROL_BYTES
    )
    return (non_text / len(sample)) > 0.10


def bounded_text_status(path: Path, max_bytes=1048576):
    """Return ``(text, reason)`` where reason explains skipped content.

    Obvious binary files are identified from a small sample before the size bound is
    applied. This keeps large media/JAR/archive assets from falsely turning secret-scan
    coverage into PARTIAL while still treating oversized text-like files as incomplete.
    """
    try:
        size = path.stat().st_size
        with path.open("rb") as handle:
            sample = handle.read(_SAMPLE_BYTES)

        if _looks_binary(sample):
            return None, "binary"
        if size > max_bytes:
            return None, "too_large"

        if size <= len(sample):
            raw = sample
        else:
            raw = path.read_bytes()
        return raw.decode("utf-8","replace"), None
    except Exception:
        return None, "read_error"


def bounded_text(path: Path, max_bytes=1048576):
    text, _reason = bounded_text_status(path, max_bytes)
    return text
