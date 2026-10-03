from __future__ import annotations

import re

from diagcore import utils


def test_log_timestamp_is_hours_and_minutes_only():
    stamp = utils.log_timestamp()
    assert re.fullmatch(r"\d{2}:\d{2}", stamp)


def test_log_line_prefixes_short_timestamp(monkeypatch, capsys):
    monkeypatch.setattr(utils, "log_timestamp", lambda: "08:59")
    utils.log_line("[01/03] N00 START")
    assert capsys.readouterr().out == "[08:59] [01/03] N00 START\n"


def test_log_line_supports_stderr(monkeypatch, capsys):
    import sys

    monkeypatch.setattr(utils, "log_timestamp", lambda: "08:59")
    utils.log_line("boom", file=sys.stderr)
    captured = capsys.readouterr()
    assert captured.err == "[08:59] boom\n"


def test_display_time_keeps_machine_iso_out_of_human_summary():
    rendered = utils.display_time("2026-10-03T08:59:41-04:00")
    assert re.fullmatch(r"\d{2}:\d{2}", rendered)
    assert "2026" not in rendered
    assert ":41" not in rendered
    assert "+" not in rendered and "-" not in rendered
