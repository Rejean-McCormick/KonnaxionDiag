from __future__ import annotations

import json
from pathlib import Path

from diagcore.runner import _dependency_blockers
from diagcore.subprocesses import (
    clean_process_text,
    decode_process_output,
    diagnostic_subprocess_env,
)


def test_cp1252_em_dash_is_recovered_without_replacement_character():
    raw = "KonnaxionDiag v4.2.3 — release-all".encode("cp1252")
    text = decode_process_output(raw)
    assert "—" in text
    assert "�" not in text


def test_ansi_sequences_are_removed_from_captured_output():
    assert clean_process_text("\x1b[31mFAIL\x1b[0m") == "FAIL"


def test_diagnostic_subprocess_environment_forces_utf8_and_no_color():
    env = diagnostic_subprocess_env({"PATH": "x"})
    assert env["PATH"] == "x"
    assert env["PYTHONUTF8"] == "1"
    assert env["PYTHONIOENCODING"].startswith("utf-8")
    assert env["NO_COLOR"] == "1"
    assert env["FORCE_COLOR"] == "0"


def test_order_only_security_dependency_does_not_cascade_blocked_state():
    meta = {"id": "S13", "profile": "security", "dependency_policy": "order_only"}
    assert _dependency_blockers(meta, {"S05": "BLOCKED"}) == {}


def test_strict_dependency_still_blocks_infrastructure_failure():
    meta = {"id": "S01", "profile": "security"}
    assert _dependency_blockers(meta, {"S00": "INFRA_ERROR"}) == {"S00": "INFRA_ERROR"}


def test_remote_security_levels_are_declared_order_only():
    root = Path(__file__).resolve().parents[1]
    manifest = json.loads((root / "kdiag_manifest.json").read_text(encoding="utf-8"))
    by_id = {item["id"]: item for item in manifest["levels"]}
    for level_id in ("S06", "S07", "S08", "S09", "S10", "S11", "S13", "S14"):
        assert by_id[level_id]["dependency_policy"] == "order_only"
