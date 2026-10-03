from types import SimpleNamespace

import diagcore.subprocesses as hidden


def test_hidden_process_kwargs_is_empty_off_windows(monkeypatch):
    monkeypatch.setattr(hidden, "os", SimpleNamespace(name="posix"))
    assert hidden.hidden_process_kwargs() == {}


def test_hidden_process_kwargs_uses_no_window_and_optional_process_group(monkeypatch):
    monkeypatch.setattr(hidden, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(hidden.subprocess, "CREATE_NO_WINDOW", 0x08000000, raising=False)
    monkeypatch.setattr(hidden.subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200, raising=False)

    assert hidden.hidden_process_kwargs() == {"creationflags": 0x08000000}
    assert hidden.hidden_process_kwargs(new_process_group=True) == {
        "creationflags": 0x08000200
    }
