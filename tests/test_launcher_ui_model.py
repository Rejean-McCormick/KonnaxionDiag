from __future__ import annotations

import json
from pathlib import Path

from diagcore.gui_model import campaign_names_for_profile, parse_level_event, split_levels


def _manifest():
    root = Path(__file__).resolve().parents[1]
    return json.loads((root / "kdiag_manifest.json").read_text(encoding="utf-8"))


def test_gui_splits_functional_and_security_series():
    functional, security = split_levels(_manifest()["levels"])
    assert functional and all(row["id"].startswith("N") for row in functional)
    assert security and all(row["id"].startswith("S") for row in security)


def test_gui_profile_campaign_lists_do_not_mix_combined_campaigns():
    campaigns = _manifest()["campaigns"]
    n_names = campaign_names_for_profile(campaigns, "levelup")
    s_names = campaign_names_for_profile(campaigns, "security")
    assert "frontend" in n_names
    assert "security-release" in s_names
    assert "release-all" not in n_names
    assert "release-all" not in s_names


def test_quick_and_playwright_operator_campaigns_exist():
    campaigns = _manifest()["campaigns"]
    assert campaigns["health-quick"]["levels"] == ["N00", "N01", "N08", "S00", "S01", "S02", "S04"]
    assert campaigns["playwright"]["levels"] == ["N05"]
    assert campaigns["release-all"]["final_release_gate"] is True


def test_live_log_parser_tracks_start_and_verdict():
    assert parse_level_event("[08:59] [03/28] N02 Backend / Django / DB - START") == ("N02", "RUNNING")
    assert parse_level_event("[09:01] [03/28] N02 - WARN (114.8s)") == ("N02", "WARN")
    assert parse_level_event("[09:02] [19/28] S05 Clean Host & OS Baseline - BLOCKED (dependency)") == ("S05", "BLOCKED")
