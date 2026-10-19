"""KonnaxionDiag Lot 1B installer. Pinned hashes, pre-install isolated tests, rollback."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from zipfile import ZipFile
from datetime import datetime, timezone
from pathlib import Path

FILES = Path(__file__).with_name("manifest.json")
REPO = Path(__file__).resolve().parents[2]
BACKUP_ROOT = REPO.parent / "Tandem_Local" / "lot1b_konnaxiondiag" / "backups"
STAGED = Path(__file__).with_name("payload.zip")
IGNORE = shutil.ignore_patterns(".git", ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache", ".mypy_cache", ".konnaxiondiag", "*.pyc")


def digest(path: Path) -> str | None:
    if not path.is_file() or path.is_symlink():
        return None
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def items() -> dict[str, dict[str, str | None]]:
    value = json.loads(FILES.read_text(encoding="utf-8"))
    assert value["schema"] == "kdiag-lot1b-hash-manifest-v1"
    files = value["files"]
    with ZipFile(STAGED) as archive:
        if sorted(archive.namelist()) != sorted(files):
            raise RuntimeError("payload contents do not match pinned manifest")
        for relative, hashes in files.items():
            path = Path(relative)
            if path.is_absolute() or ".." in path.parts or "\\" in relative:
                raise RuntimeError(f"unsafe manifest path: {relative}")
            if hashlib.sha256(archive.read(relative)).hexdigest() != hashes["after"]:
                raise RuntimeError(f"payload checksum mismatch: {relative}")
    return files


def classify(files):
    result = {}
    for relative, hashes in files.items():
        path = REPO / relative
        if path.is_symlink():
            status = "DRIFT_SYMLINK"
        elif path.exists() and not path.is_file():
            status = "DRIFT_TYPE"
        else:
            existing = digest(path)
            if existing == hashes["after"]:
                status = "ALREADY_UPDATED"
            elif existing == hashes["before"]:
                status = "READY"
            else:
                status = "DRIFT"
        result[relative] = status
    return result


def check(files, *, allow_ready: bool = True):
    states = classify(files)
    allowed = {"READY", "ALREADY_UPDATED"} if allow_ready else {"ALREADY_UPDATED"}
    for relative, state in states.items():
        print(f"[{state}] {relative}")
    if any(state not in allowed for state in states.values()):
        raise RuntimeError("unexpected repo content; refusing to overwrite local changes")
    return states


def run_tests(root):
    # Production verification must not silently skip signature tests when crypto is missing.
    try:
        import cryptography  # noqa: F401
        import pytest  # noqa: F401
    except ImportError as exc:
        raise RuntimeError(f"Required test/signing dependency unavailable: {exc.name}; no automatic install") from exc
    cmd = [sys.executable, "-m", "pytest", "-q", "tests"]
    print("[TESTS] Executing isolated full KonnaxionDiag suite (no Agent, no Neon/Orgo calls)...", flush=True)
    completed = subprocess.run(cmd, cwd=root, check=False, timeout=180)
    if completed.returncode != 0:
        raise RuntimeError(f"KonnaxionDiag test suite failed (exit={completed.returncode}); no source modified")


def install(files, states):
    todo = [relative for relative, state in states.items() if state == "READY"]
    if not todo:
        print("[OK] Idempotent: files already at the expected version; nothing to install")
        return
    # Stage a copy of the code and test all changes before touching the repo.
    with tempfile.TemporaryDirectory(prefix="kdiag-lot1b-stage-") as temp:
        stage = Path(temp) / "kdiag"
        shutil.copytree(REPO, stage, ignore=IGNORE)
        with ZipFile(STAGED) as archive:
            for relative in files:
                to = stage / relative
                to.parent.mkdir(parents=True, exist_ok=True)
                to.write_bytes(archive.read(relative))
        run_tests(stage)
    # Recheck after lengthy tests to avoid overwriting concurrent edits.
    current = check(files)
    if current != states:
        raise RuntimeError("Files changed during staging; aborting before write")
    now = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    backup = BACKUP_ROOT / now
    backup.mkdir(parents=True, exist_ok=False)
    records: dict[str, bool] = {}
    for relative in todo:
        target = REPO / relative
        existed = target.exists()
        records[relative] = existed
        if existed:
            destination = backup / "original" / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(target, destination)
    metadata = {"schema": "kdiag-lot1b-rollback-v1", "when_utc": now, "files": records, "rolled_back": False}
    (backup / "state.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    written = []
    try:
        with ZipFile(STAGED) as archive:
            for relative in todo:
                target = REPO / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                temp_target = target.with_name(target.name + ".lot1b-new")
                temp_target.write_bytes(archive.read(relative))
                os.replace(temp_target, target)
                written.append(relative)
        check(files, allow_ready=False)
    except Exception:
        for relative in reversed(written):
            target = REPO / relative
            original = backup / "original" / relative
            if records[relative]:
                shutil.copy2(original, target)
            else:
                target.unlink(missing_ok=True)
        raise
    print(f"[OK] Lot 1B updated; rollback backup: {backup}")
    print("[INFO] Capsule Agent code/runtime NOT modified; PEP integration still pending")


def rollback(files):
    if not BACKUP_ROOT.is_dir():
        raise RuntimeError("No local Lot 1B backups to restore")
    available = sorted((p for p in BACKUP_ROOT.iterdir() if (p / "state.json").is_file()), reverse=True)
    backup = next((p for p in available if not json.loads((p / "state.json").read_text(encoding="utf-8")).get("rolled_back")), None)
    if backup is None:
        raise RuntimeError("No active installation backup")
    meta = json.loads((backup / "state.json").read_text(encoding="utf-8"))
    targets = meta["files"]
    if any(digest(REPO / relative) != files[relative]["after"] for relative in targets):
        raise RuntimeError("Modified installed files detected; rollback refused to avoid data loss")
    for relative, was_file in targets.items():
        target = REPO / relative
        if was_file:
            original = backup / "original" / relative
            if digest(original) != files[relative]["before"]:
                raise RuntimeError("Backup checksum invalid; rollback refused")
            shutil.copy2(original, target)
        else:
            target.unlink(missing_ok=True)
    meta["rolled_back"] = True
    (backup / "state.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print(f"[OK] Original code restored from {backup}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("preview", "install", "verify", "rollback"))
    args = parser.parse_args()
    print(f"=== KONNAXIONDIAG 4.2.5 / LOT 1B / {args.mode.upper()} ===")
    print(f"[TARGET] {REPO}")
    files = items()
    if args.mode == "preview":
        check(files)
        print("[OK] Hash checks successful; read only")
    elif args.mode == "install":
        states = check(files)
        install(files, states)
    elif args.mode == "verify":
        check(files, allow_ready=False)
        print("[OK] All patched files match SHA-256; cryptographic tests follow")
        run_tests(REPO)
        print("[OK] Lot 1B KonnaxionDiag checks PASS")
    else:
        rollback(files)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (RuntimeError, ValueError, OSError, AssertionError) as exc:
        print(f"[BLOQUE] {type(exc).__name__}: {exc}", file=sys.stderr)
        sys.exit(2)
