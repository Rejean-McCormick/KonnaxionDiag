from profiles.levelup.konnaxion_diag.checks import _release_all_skip_playwright


class _Config:
    def __init__(self, enabled: bool):
        self.enabled = enabled

    def get(self, key, default=None):
        if key == "konnaxion":
            return {"release_all_skip_playwright": self.enabled}
        return default


def test_release_all_can_skip_playwright(monkeypatch):
    monkeypatch.setenv("LEVELUPDIAG_CAMPAIGN", "release-all")
    assert _release_all_skip_playwright(_Config(True)) is True


def test_other_campaigns_keep_playwright(monkeypatch):
    monkeypatch.setenv("LEVELUPDIAG_CAMPAIGN", "full-local")
    assert _release_all_skip_playwright(_Config(True)) is False


def test_release_all_skip_can_be_disabled(monkeypatch):
    monkeypatch.setenv("LEVELUPDIAG_CAMPAIGN", "release-all")
    assert _release_all_skip_playwright(_Config(False)) is False
