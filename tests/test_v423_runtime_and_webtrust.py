from __future__ import annotations

from pathlib import Path

from diagcore.runner import _dependency_blockers
from profiles.security.levels.s04_app_production import _check_web_trust_boundaries
from diagcore.report import Report


def test_n05_keeps_n00_strict_but_does_not_block_on_n03_fail():
    meta = {
        "id": "N05",
        "profile": "levelup",
        "nonblocking_depends_on": ["N03"],
    }
    assert _dependency_blockers(meta, {"N00": "PASS", "N03": "FAIL"}) == {}
    assert _dependency_blockers(meta, {"N00": "BLOCKED", "N03": "FAIL"}) == {"N00": "BLOCKED"}


def _minimal_webtrust_tree(root: Path) -> None:
    files = {
        "backend/config/settings/production.py": "ACCOUNT_ALLOW_REGISTRATION = env.bool('ACCOUNT_ALLOW_REGISTRATION', default=False)\n",
        "backend/config/settings/base.py": "DEFAULT_THROTTLE_CLASSES = []\nDEFAULT_THROTTLE_RATES = {}\n",
        "backend/konnaxion/users/adapters.py": 'ACCOUNT_ALLOW_REGISTRATION", False\n',
        "backend/konnaxion/security_controls.py": "def validate_safe_upload(): pass\n",
        "backend/konnaxion/konnected/api_views.py": "class KnowledgeResourceViewSet:\n    permission_classes = [StaffWritePublicReadPermission]\n",
        "backend/konnaxion/konnected/serializers.py": "def validate_url(self): validate_safe_external_url\ndef x(): validate_safe_upload\n",
        "backend/konnaxion/keenkonnect/api_views.py": "OwnerOrStaffWritePermission ProjectManagerWritePermission SelfOrStaffWritePermission",
        "backend/konnaxion/keenkonnect/serializers.py": "validate_safe_upload",
        "backend/konnaxion/kreative/api_views.py": "OwnerOrStaffWritePermission StaffWritePublicReadPermission",
        "backend/konnaxion/kreative/serializers.py": "validate_safe_upload",
        "backend/konnaxion/trust/serializers.py": "validate_safe_upload",
        "backend/config/websocket.py": '_websocket_origin_allowed 4403 b"origin"',
        "backend/compose/production/nginx/default.conf": "x-content-type-options nosniff content-security-policy sandbox script-src 'none' html svg xml js",
        "frontend/middleware.ts": "Content-Security-Policy strict-dynamic script-src-attr 'none' object-src 'none' frame-ancestors 'none' nonce-",
        "frontend/lib/security/navigation.ts": "openExternalUrlSafely noopener,noreferrer window.open(",
        "frontend/app/page.tsx": "export default function Page(){ return null }",
    }
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")


def test_webtrust_scan_prunes_node_modules_and_next(tmp_path: Path):
    _minimal_webtrust_tree(tmp_path)
    # These would be violations if the generated/vendor trees were traversed.
    for rel in [
        "frontend/node_modules/pkg/bad.js",
        "frontend/.next/static/bad.js",
        "frontend/artifacts/bad.js",
    ]:
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("dangerouslySetInnerHTML window.open(", encoding="utf-8")

    cfg = {
        "scan": {
            "exclude_dirs": ["node_modules", ".next", "artifacts"],
            "max_files": 25000,
        }
    }
    report = Report("test-run", "S04W", "Web Trust", "test", str(tmp_path))
    _check_web_trust_boundaries(cfg, report, tmp_path, {})
    coverage = next(f for f in report.findings if f["id"] == "app.web_trust.source_scan_coverage")
    browser = next(f for f in report.findings if f["id"] == "app.web_trust.browser_sinks")
    assert coverage["verdict"] == "PASS"
    assert browser["verdict"] == "PASS"
