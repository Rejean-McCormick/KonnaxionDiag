from __future__ import annotations

import hashlib
import json
import os
import platform
import socket
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from diagcore.commands import find_executable
from diagcore.config import AppConfig
from diagcore.models import Artifact, Finding, LevelResult
from diagcore.evidence import read_level_result
from diagcore.verdicts import CONFIG_ERROR, FAIL, INFRA_ERROR, PASS, SKIP, WARN

from .common import (
    active_session,
    command_probe,
    command_value,
    kx_config,
    make_result,
    now,
    resolve_command,
    session_metadata,
    start_session,
    target_paths,
)
from .http_probe import probe as http_probe
from .i18n_audit import audit_i18n, browser_probe_command
from .source_audit import audit as source_audit
from .worlds_audit import audit_worlds, probe_worlds_control_plane, summarize_worlds_audit


def _tool_candidates(name: str) -> list[str]:
    if os.name == "nt":
        return [f"{name}.exe", f"{name}.cmd", name]
    return [name]


def _find_tool(name: str) -> str | None:
    for candidate in _tool_candidates(name):
        path = find_executable(candidate)
        if path:
            return path
    if name == 'pnpm':
        return find_executable('corepack.cmd' if os.name == 'nt' else 'corepack') or find_executable('corepack')
    return None

def _sha256_file(path: Path) -> str:
    digest=hashlib.sha256()
    with path.open('rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def _current_campaign(config: AppConfig) -> str:
    # The worker environment is authoritative for the campaign currently being
    # executed. active-session.json is only a fallback for out-of-band helpers.
    env_campaign = os.environ.get("LEVELUPDIAG_CAMPAIGN", "").strip()
    if env_campaign:
        return env_campaign
    session = active_session(config)
    return str(session.get("campaign", "")) if session else ""


def _worlds_required(config: AppConfig) -> bool:
    return _current_campaign(config) == "world-switch"


def _worlds_focused(config: AppConfig) -> bool:
    """True for the fast, Worlds-specific qualification campaign."""
    return _current_campaign(config) == "world-switch"


def _i18n_focused(config: AppConfig) -> bool:
    """True only for the focused bilingual UI qualification campaign."""
    return _current_campaign(config) == "i18n-validation"


def _worlds_report(config: AppConfig) -> dict[str, Any]:
    paths = target_paths(config)
    frontend = paths["frontend"]
    backend_dir = paths["backend"]
    worlds_repo = paths.get("worlds_repo")
    assert frontend is not None and backend_dir is not None
    return audit_worlds(frontend, backend_dir, worlds_repo=worlds_repo)


def _worlds_enabled_for_check(config: AppConfig, report: dict[str, Any] | None = None) -> bool:
    current = report if report is not None else _worlds_report(config)
    return bool(current.get("detected")) or _worlds_required(config)


_STALE_TEST_DB_MARKERS = (
    'does not exist',
    'undefinedtable',
    'no such table',
)


def _pytest_schema_is_stale(step) -> bool:
    if step is None or step.verdict == PASS:
        return False
    text = f"{step.output_tail}\n{step.error}".lower()
    missing_relation = ('relation "' in text or "relation '" in text or 'no such table' in text)
    return missing_relation and any(marker in text for marker in _STALE_TEST_DB_MARKERS)


def _pytest_clean_db_command(command):
    """Legacy fallback: force recreation when an isolated wrapper cannot be used."""
    if not command:
        return None
    args = [str(x) for x in command]
    if not any('pytest' in part.lower() for part in args):
        return None
    args = [arg for arg in args if arg != '--reuse-db']
    if '--create-db' not in args:
        args.append('--create-db')
    return args


def _pytest_args(command) -> list[str] | None:
    """Extract pytest arguments from the supported command shapes."""
    if not command:
        return None
    args = [str(x) for x in command]
    lowered = [Path(x).name.lower() for x in args]

    for index in range(len(args) - 1):
        if lowered[index] in {'python', 'python.exe', 'python3', 'python3.exe'} and args[index + 1] == '-m':
            if index + 2 < len(args) and args[index + 2].lower() == 'pytest':
                return args[index + 3:]

    for index, value in enumerate(lowered):
        if value in {'pytest', 'pytest.exe'}:
            return args[index + 1:]
    return None


def _pytest_isolated_db_name(finding_id: str) -> str:
    """Return a deterministic-per-run/per-probe PostgreSQL-safe test DB name."""
    run_id = os.environ.get('LEVELUPDIAG_RUN_ID', '').strip() or f'pid-{os.getpid()}'
    digest = hashlib.sha256(f'{run_id}:{finding_id}'.encode('utf-8')).hexdigest()[:16]
    return f'test_kx_lud_{digest}'


def _pytest_isolated_command(config: AppConfig, command, *, finding_id: str, project_root: Path) -> tuple[list[str], str] | None:
    pytest_args = _pytest_args(command)
    if pytest_args is None:
        return None
    wrapper = config.diagnostics_root_path / 'scripts' / 'run_isolated_django_pytest.py'
    if not wrapper.is_file():
        return None

    db_name = _pytest_isolated_db_name(finding_id)
    paths = target_paths(config) if hasattr(config, 'target_root_path') else {}
    worlds_backend = paths.get('worlds_backend')
    section = kx_config(config)
    worlds_cfg = section.get('worlds', {}) if isinstance(section.get('worlds', {}), dict) else {}
    settings_module = 'config.settings.test'
    if worlds_backend is not None and project_root.resolve(strict=False) == worlds_backend.resolve(strict=False):
        settings_module = str(worlds_cfg.get('test_settings_module', 'worlds_config.settings') or 'worlds_config.settings')
    pytest_basetemp = config.control_root_path / 'current' / 'pytest-temp' / db_name
    result = [
        'python',
        str(wrapper),
        '--db-name',
        db_name,
        '--settings',
        settings_module,
        '--project-root',
        str(project_root),
        '--basetemp',
        str(pytest_basetemp),
    ]

    # KX-UNIVERSES-1 intentionally keeps ``konnaxion.worlds`` in the sibling
    # Konnaxion_Worlds repository instead of vendoring it into the host.
    # Source-level diagnostics compose both source roots even when the host
    # virtualenv has not yet received an editable install.
    if (
        worlds_backend is not None
        and worlds_backend.is_dir()
        and project_root.resolve(strict=False) != worlds_backend.resolve(strict=False)
    ):
        result.extend(['--extra-pythonpath', str(worlds_backend)])
    section = kx_config(config)
    admin_host = str(section.get('test_db_admin_host', '') or '').strip()
    if admin_host:
        result.extend(['--admin-host', admin_host])
    pytest_args = [arg for arg in pytest_args if arg not in {'--reuse-db', '--create-db'}]
    result.extend(['--', *pytest_args])
    return result, db_name


def _pytest_probe_with_clean_db_retry(
    config: AppConfig,
    *,
    finding_id: str,
    label: str,
    command,
    cwd: Path,
    timeout: int,
    optional: bool,
    recommendation: str | None = None,
):
    """Run Django pytest probes in LevelUpDiag-owned ephemeral databases.

    The function name is retained for compatibility with older LevelUpDiag
    tests/plugins. Modern behavior avoids the target project's --reuse-db
    entirely, assigns a unique DB to each campaign probe, and delegates
    pre/post cleanup to the isolated pytest wrapper.
    """
    isolated = _pytest_isolated_command(config, command, finding_id=finding_id, project_root=cwd)
    if isolated is not None:
        isolated_command, db_name = isolated
        finding, step = command_probe(
            config,
            finding_id=finding_id,
            label=label,
            command=isolated_command,
            cwd=cwd,
            timeout=timeout,
            optional=optional,
            recommendation=recommendation,
        )
        if finding.data is None:
            finding.data = {}
        finding.data.update({
            'isolated_test_database': True,
            'test_database_name': db_name,
            'target_reuse_db_disabled': True,
            'isolated_pytest_basetemp': True,
        })
        if step is not None and 'LEVELUPDIAG_DB_CLEANUP_WARN:' in (step.output_tail or ''):
            cleanup_note = (
                'The isolated pytest database cleanup was incomplete. Configure '
                'konnaxion.test_db_admin_host with a direct PostgreSQL/Neon host '
                'if the pooled endpoint retains sessions.'
            )
            finding.data['database_cleanup_warning'] = True
            if finding.recommendation:
                finding.recommendation = f"{finding.recommendation} Separately: {cleanup_note}"
            else:
                finding.recommendation = cleanup_note
        return finding, step

    # Compatibility fallback for custom pytest launchers that cannot be
    # decomposed into python -m pytest / pytest arguments.
    finding, step = command_probe(
        config,
        finding_id=finding_id,
        label=label,
        command=command,
        cwd=cwd,
        timeout=timeout,
        optional=optional,
        recommendation=recommendation,
    )
    if not _pytest_schema_is_stale(step):
        return finding, step

    retry_command = _pytest_clean_db_command(command)
    if not retry_command:
        return finding, step

    retry_finding, retry_step = command_probe(
        config,
        finding_id=finding_id,
        label=f"{label} (clean test DB retry)",
        command=retry_command,
        cwd=cwd,
        timeout=timeout,
        optional=optional,
        recommendation=recommendation,
    )
    if retry_step is not None and retry_step.verdict == PASS:
        return Finding(
            finding_id,
            PASS,
            f"{label} passed after recreating the stale pytest database.",
            "command",
            path=str(cwd),
            evidence="Initial pytest run reported a missing relation/table; automatic --create-db retry passed.",
            data={
                "recovered_from_stale_test_db": True,
                "retry_command": list(retry_step.command),
                "retry_duration_seconds": retry_step.duration_seconds,
            },
        ), retry_step

    if retry_finding.data is None:
        retry_finding.data = {}
    retry_finding.data["clean_test_db_retry"] = True
    retry_finding.recommendation = (
        recommendation
        or "The clean pytest database retry also failed. Inspect migrations and the retry output before changing application code."
    )
    return retry_finding, retry_step


def _powershell_supports_deep_only(script: Path) -> bool:
    try:
        text = script.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return "[switch]$DeepOnly" in text or "[switch] $DeepOnly" in text


def discovery(config: AppConfig, level_id: str, level_name: str) -> LevelResult:
    started = now()
    session_id = start_session(config)
    paths = target_paths(config)
    findings: list[Finding] = []
    root = paths["root"]
    if root and root.is_dir():
        findings.append(Finding("kx.discovery.target", PASS, f"Konnaxion target found: {root}", "discovery", path=str(root)))
    else:
        findings.append(Finding("kx.discovery.target", CONFIG_ERROR, "Konnaxion target repository is missing.", "discovery", path=str(root)))

    for key in ("frontend", "backend"):
        path = paths[key]
        severity = PASS if path and path.is_dir() else CONFIG_ERROR
        findings.append(Finding(f"kx.discovery.{key}", severity, f"{key} directory {'found' if severity == PASS else 'missing'}.", "discovery", path=str(path)))

    worlds_repo = paths.get("worlds_repo")
    worlds_severity = PASS if worlds_repo and worlds_repo.is_dir() else (CONFIG_ERROR if _worlds_required(config) else WARN)
    findings.append(Finding(
        "kx.discovery.worlds-repo",
        worlds_severity,
        "Sibling Konnaxion_Worlds repository found." if worlds_severity == PASS else "Sibling Konnaxion_Worlds repository is missing.",
        "worlds",
        path=str(worlds_repo) if worlds_repo else None,
        recommendation=None if worlds_severity == PASS else "Set konnaxion.worlds.repo_dir to the canonical Konnaxion_Worlds repository.",
    ))

    tools = ["git", "node", "pnpm"]
    for name in tools:
        resolved = _find_tool(name)
        findings.append(Finding(
            f"kx.tool.{name}", PASS if resolved else WARN,
            f"{name} {'available' if resolved else 'not found on PATH'}.",
            "toolchain", path=resolved,
            recommendation=None if resolved else f"Install or configure {name} before running checks that require it.",
        ))
    findings.append(Finding("kx.tool.python", PASS, f"Python available: {sys.executable}", "toolchain", path=sys.executable, evidence=platform.python_version()))

    capsule_manager = paths["capsule_manager"]
    findings.append(Finding(
        "kx.discovery.capsule-manager",
        PASS if capsule_manager and capsule_manager.is_dir() else WARN,
        "Capsule Manager repository is configured and present." if capsule_manager and capsule_manager.is_dir() else "Capsule Manager repository is not configured/present; capsule diagnostics will be limited.",
        "discovery", path=str(capsule_manager) if capsule_manager else None,
    ))
    return make_result(level_id, level_name, started, findings, metadata={"diagnostic_session_id": session_id, "cwd": str(root), "python": platform.python_version(), "platform": platform.platform()})


def repository_static(config: AppConfig, level_id: str, level_name: str) -> LevelResult:
    started = now(); paths = target_paths(config); root = paths["root"]; findings: list[Finding] = []
    expected = ["frontend/package.json", "backend/manage.py"]
    for rel in expected:
        path = root / rel
        findings.append(Finding(f"kx.repo.{rel.replace('/', '.').replace('_','-')}", PASS if path.is_file() else FAIL, f"Required repository surface {'present' if path.is_file() else 'missing'}: {rel}", "repository", path=str(path)))

    worlds = _worlds_report(config)
    if _worlds_enabled_for_check(config, worlds):
        missing = worlds.get("missing_files", [])
        forbidden = worlds.get("forbidden_present", [])
        bad = bool(missing or forbidden)
        findings.append(Finding(
            "kx.worlds.installation",
            FAIL if bad else PASS,
            "Konnaxion host + Konnaxion_Worlds split ownership is complete." if not bad else f"Universe/World installation is incomplete or overlapping: {len(missing)} missing, {len(forbidden)} forbidden surface(s).",
            "worlds",
            evidence=summarize_worlds_audit(worlds),
            recommendation="Restore the KX-UNIVERSES-1 two-repository boundary before running world-switch." if bad else None,
        ))
        for finding_id, label, cwd, script in (
            ("kx.worlds.host-ownership-guard", "Konnaxion Universe/World ownership guard", root, root / "scripts" / "check_worlds_ownership.py"),
            ("kx.worlds.engine-boundary-guard", "Konnaxion_Worlds repository boundary guard", paths.get("worlds_repo"), (paths.get("worlds_repo") / "scripts" / "check_repo_boundaries.py") if paths.get("worlds_repo") else None),
        ):
            if cwd and script and script.is_file():
                finding, step = command_probe(config, finding_id=finding_id, label=label, command=["python", str(script)], cwd=cwd, timeout=60, optional=not _worlds_required(config))
                findings.append(finding)
            else:
                findings.append(Finding(finding_id, FAIL if _worlds_required(config) else WARN, f"{label} is unavailable.", "worlds", path=str(script) if script else None))
    else:
        findings.append(Finding("kx.worlds.installation", SKIP, "Universe/World integration is not detected; focused checks skipped.", "worlds"))

    git_cmd = ["git", "status", "--short"]
    finding, step = command_probe(config, finding_id="kx.repo.git-status", label="Git status", command=git_cmd, cwd=root, timeout=60, optional=True)
    findings.append(finding)
    output = step.output_tail if step else ""
    return make_result(level_id, level_name, started, findings, output=output, metadata={**session_metadata(config), "cwd": str(root)})


def backend(config: AppConfig, level_id: str, level_name: str) -> LevelResult:
    started = now(); backend_dir = target_paths(config)["backend"]; findings: list[Finding] = []; outputs=[]
    assert backend_dir is not None
    specs = [
        ("kx.backend.django-check", "Django system check", "backend_check", ["python", "manage.py", "check"], False, 180),
        ("kx.backend.migrations", "Django migration drift check", "backend_migrations", ["python", "manage.py", "makemigrations", "--check", "--dry-run"], False, 240),
    ]
    # The focused Worlds campaign deliberately avoids the generic platform
    # smoke suite; world-switch-validation runs full-local afterwards.
    if not _worlds_focused(config):
        specs.append(("kx.backend.smoke", "Backend platform smoke tests", "backend_smoke", ["python", "-m", "pytest", "tests/test_smoke_platform.py", "-q"], False, 600))
    for fid,label,key,default,opt,timeout in specs:
        cmd = command_value(config, key) or default
        probe = _pytest_probe_with_clean_db_retry if any('pytest' in str(x).lower() for x in (cmd or [])) else command_probe
        finding, step = probe(config, finding_id=fid, label=label, command=cmd, cwd=backend_dir, timeout=timeout, optional=opt)
        findings.append(finding)
        if step: outputs.append(f"## {label}\n{step.output_tail}")

    worlds = _worlds_report(config)
    if _worlds_enabled_for_check(config, worlds):
        cmd = command_value(config, "backend_worlds_tests") or [
            "python", "-m", "pytest", "konnaxion/worlds/tests", "-q"
        ]
        finding, step = _pytest_probe_with_clean_db_retry(
            config,
            finding_id="kx.worlds.backend-tests",
            label="Konnaxion Worlds backend tests",
            command=cmd,
            cwd=target_paths(config).get("worlds_backend") or backend_dir,
            timeout=900,
            optional=not _worlds_required(config),
            recommendation="Run the canonical Konnaxion_Worlds engine test suite and resolve Universe/World/Release invariant failures.",
        )
        findings.append(finding)
        if step: outputs.append(f"## Konnaxion Worlds backend tests\n{step.output_tail}")

    return make_result(level_id, level_name, started, findings, output="\n\n".join(outputs), metadata={**session_metadata(config), "cwd": str(backend_dir), "worlds": worlds})


def _capture_eslint_report(
    config: AppConfig,
    frontend_dir: Path,
    *,
    timeout: int,
) -> dict[str, Any]:
    """Capture a complete machine-readable ESLint report for the current run."""
    report_dir = config.control_root_path / "current"
    report_dir.mkdir(parents=True, exist_ok=True)
    report_json = report_dir / "eslint-report.json"
    error_files_txt = report_dir / "eslint-error-files.txt"

    for path in (report_json, error_files_txt):
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass

    report_cmd = [
        "pnpm",
        "exec",
        "eslint",
        ".",
        "--format",
        "json",
        "--output-file",
        str(report_json),
    ]
    # ESLint exits non-zero when lint errors exist. The command's verdict is
    # intentionally not added as a second blocking finding; the primary lint
    # finding already owns that verdict.
    command_probe(
        config,
        finding_id="kx.frontend.eslint-report-capture",
        label="Frontend ESLint full report capture",
        command=report_cmd,
        cwd=frontend_dir,
        timeout=timeout,
        optional=True,
    )

    result: dict[str, Any] = {
        "report_path": str(report_json),
        "error_files_path": str(error_files_txt),
        "error_count": 0,
        "warning_count": 0,
        "error_files": [],
    }
    if not report_json.is_file():
        return result

    try:
        payload = json.loads(report_json.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return result

    if not isinstance(payload, list):
        return result

    error_files: list[str] = []
    summary_lines: list[str] = []
    total_errors = 0
    total_warnings = 0

    for entry in payload:
        if not isinstance(entry, dict):
            continue
        file_path = str(entry.get("filePath", "")).strip()
        messages = entry.get("messages", [])
        if not isinstance(messages, list):
            messages = []

        error_count = entry.get("errorCount")
        warning_count = entry.get("warningCount")
        if not isinstance(error_count, int):
            error_count = sum(
                1 for message in messages
                if isinstance(message, dict) and message.get("severity") == 2
            )
        if not isinstance(warning_count, int):
            warning_count = sum(
                1 for message in messages
                if isinstance(message, dict) and message.get("severity") == 1
            )

        total_errors += error_count
        total_warnings += warning_count
        if error_count > 0 and file_path:
            error_files.append(file_path)
            summary_lines.append(
                f"{file_path} | errors={error_count} warnings={warning_count}"
            )

    error_files = sorted(dict.fromkeys(error_files), key=str.casefold)
    result.update(
        {
            "error_count": total_errors,
            "warning_count": total_warnings,
            "error_files": error_files,
        }
    )

    try:
        error_files_txt.write_text(
            "\n".join(summary_lines) + ("\n" if summary_lines else ""),
            encoding="utf-8",
        )
    except OSError:
        pass

    return result


def frontend(config: AppConfig, level_id: str, level_name: str) -> LevelResult:
    started = now()
    frontend_dir = target_paths(config)["frontend"]
    findings: list[Finding] = []
    outputs: list[str] = []
    assert frontend_dir is not None

    i18n_report = audit_i18n(frontend_dir)
    if i18n_report.get("detected"):
        errors = i18n_report.get("catalog_errors", {})
        findings.append(Finding(
            "kx.i18n.catalog-json",
            FAIL if errors else PASS,
            "i18n catalog JSON is invalid or missing." if errors else "EN/FR i18n catalogs are valid JSON.",
            "i18n",
            evidence=str(errors) if errors else None,
            recommendation="Repair frontend/i18n/locales/en.json and fr.json before running frontend diagnostics." if errors else None,
        ))
        missing_en = i18n_report.get("missing_in_en", [])
        missing_fr = i18n_report.get("missing_in_fr", [])
        aligned = not missing_en and not missing_fr and not errors
        findings.append(Finding(
            "kx.i18n.catalog-alignment",
            PASS if aligned else FAIL,
            f"EN/FR catalogs aligned: {i18n_report.get('en_leaf_count', 0)} EN / {i18n_report.get('fr_leaf_count', 0)} FR leaves." if aligned else "EN/FR catalogs do not expose the same leaf keys.",
            "i18n",
            evidence=str({"missing_in_en": missing_en[:40], "missing_in_fr": missing_fr[:40]}) if not aligned else None,
            recommendation="Align en.json and fr.json to the exact same key tree." if not aligned else None,
        ))
        blanks = list(i18n_report.get("blank_en", [])) + list(i18n_report.get("blank_fr", []))
        findings.append(Finding(
            "kx.i18n.nonblank-values", PASS if not blanks else FAIL,
            "i18n catalog leaves are non-empty." if not blanks else f"Empty/non-string i18n leaves detected: {len(blanks)}.",
            "i18n", evidence="\n".join(blanks[:80]) if blanks else None,
            recommendation="Every catalog leaf must be a non-empty display string." if blanks else None,
        ))
        placeholders = i18n_report.get("placeholder_mismatches", [])
        findings.append(Finding(
            "kx.i18n.placeholders", PASS if not placeholders else FAIL,
            "EN/FR interpolation placeholders match." if not placeholders else f"Interpolation placeholder mismatches detected: {len(placeholders)}.",
            "i18n", evidence=json.dumps(placeholders[:40], ensure_ascii=False) if placeholders else None,
            recommendation="Keep the same {placeholder} names in both language values." if placeholders else None,
        ))
        css_values = i18n_report.get("css_like_catalog_values", [])
        style_calls = i18n_report.get("style_translation_calls", [])
        style_bad = bool(css_values or style_calls)
        findings.append(Finding(
            "kx.i18n.style-safety", PASS if not style_bad else FAIL,
            "No CSS/styled-jsx content is routed through translations." if not style_bad else "CSS or styled-jsx content was captured by i18n.",
            "i18n",
            evidence=json.dumps({"catalog_keys": css_values[:40], "source_calls": style_calls[:40]}, ensure_ascii=False) if style_bad else None,
            recommendation="Keep CSS static. Never replace <style jsx> content with t()/i18nT()." if style_bad else None,
        ))
        value_calls = i18n_report.get("translated_value_calls", [])
        findings.append(Finding(
            "kx.i18n.stable-values", PASS if not value_calls else FAIL,
            "No translated strings are used as technical option/input values." if not value_calls else f"Translated technical values detected: {len(value_calls)}.",
            "i18n", evidence=json.dumps(value_calls[:60], ensure_ascii=False) if value_calls else None,
            recommendation="Translate only labels. Keep option/filter/form values stable language-independent identifiers." if value_calls else None,
        ))

    if _worlds_focused(config):
        # Keep only compilation/build gates here. The dedicated Worlds Jest suite
        # is added below; generic lint/Jest belong to the subsequent full-local.
        specs = []
        if i18n_report.get("detected"):
            specs.append(("kx.frontend.i18n-check", "Frontend i18n catalog check", "frontend_i18n_check", ["pnpm", "run", "i18n:check"], False, 300))
        specs.extend([
            ("kx.frontend.typecheck", "TypeScript typecheck", "frontend_typecheck", ["pnpm", "exec", "tsc", "-p", "tsconfig.json", "--noEmit", "--pretty", "false"], False, 600),
            ("kx.frontend.build", "Next production build", "frontend_build", ["pnpm", "exec", "next", "build"], False, 1200),
        ])
    else:
        specs = []
        if i18n_report.get("detected"):
            specs.append(("kx.frontend.i18n-check", "Frontend i18n catalog check", "frontend_i18n_check", ["pnpm", "run", "i18n:check"], False, 300))
        specs.extend([
            ("kx.frontend.typecheck", "TypeScript typecheck", "frontend_typecheck", ["pnpm", "exec", "tsc", "-p", "tsconfig.json", "--noEmit", "--pretty", "false"], False, 600),
            ("kx.frontend.eslint", "Frontend ESLint", "frontend_lint", ["pnpm", "exec", "eslint", "."], False, 600),
            ("kx.frontend.jest", "Frontend Jest", "frontend_jest", ["pnpm", "exec", "jest", "--passWithNoTests", "--runInBand"], False, 900),
            ("kx.frontend.build", "Next production build", "frontend_build", ["pnpm", "exec", "next", "build"], False, 1200),
        ])

    eslint_report: dict[str, Any] = {}
    for fid, label, key, default, opt, timeout in specs:
        cmd = command_value(config, key) or default
        finding, step = command_probe(
            config,
            finding_id=fid,
            label=label,
            command=cmd,
            cwd=frontend_dir,
            timeout=timeout,
            optional=opt,
        )
        findings.append(finding)
        if step:
            outputs.append(f"## {label}\n{step.output_tail}")

        if fid == "kx.frontend.eslint" and finding.severity == FAIL:
            eslint_report = _capture_eslint_report(
                config,
                frontend_dir,
                timeout=timeout,
            )
            error_files = eslint_report.get("error_files", [])
            if error_files:
                findings.append(
                    Finding(
                        "kx.frontend.eslint-error-files",
                        WARN,
                        f"ESLint errors are present in {len(error_files)} file(s).",
                        "command",
                        path=str(eslint_report.get("error_files_path", "")),
                        evidence="\n".join(error_files[:40]),
                        recommendation=(
                            "Fix the files listed in .konnaxiondiag/current/"
                            "eslint-error-files.txt, then rerun N03."
                        ),
                    )
                )
                outputs.append(
                    "## ESLint files containing errors\n"
                    + "\n".join(error_files)
                )

    worlds = _worlds_report(config)
    if _worlds_enabled_for_check(config, worlds):
        cmd = command_value(config, "frontend_worlds_tests") or [
            "pnpm", "exec", "jest",
            "lib/__tests__/worlds.test.ts",
            "routes/suites.test.ts",
            "--runInBand",
        ]
        finding, step = command_probe(
            config,
            finding_id="kx.worlds.frontend-tests",
            label="Konnaxion Worlds frontend routing tests",
            command=cmd,
            cwd=frontend_dir,
            timeout=600,
            optional=not _worlds_required(config),
            recommendation="Keep World URL helpers and suite/sidebar ownership tests green before validating the switcher.",
        )
        findings.append(finding)
        if step:
            outputs.append(f"## Konnaxion Worlds frontend routing tests\n{step.output_tail}")

    metadata: dict[str, Any] = {
        **session_metadata(config),
        "cwd": str(frontend_dir),
        "worlds": worlds,
        "i18n": i18n_report,
    }
    if eslint_report:
        metadata["eslint"] = eslint_report

    return make_result(
        level_id,
        level_name,
        started,
        findings,
        output="\n\n".join(outputs),
        metadata=metadata,
    )


def contracts(config: AppConfig, level_id: str, level_name: str) -> LevelResult:
    started = now(); paths = target_paths(config); findings=[]; outputs=[]
    specs = [
        ("kx.contract.backend-api-scan", "Django API scanner", "backend_api_scan", ["python", "django_api_scanner.py"], paths["backend"], True, 300),
        ("kx.contract.frontend-endpoints", "Frontend endpoint scan", "frontend_endpoint_scan", ["node", "scripts/scan-endpoints.mjs"], paths["frontend"], True, 300),
        ("kx.contract.openapi-tests", "OpenAPI contract tests", "backend_openapi", ["python", "-m", "pytest", "konnaxion/users/tests/api/test_openapi.py", "-q"], paths["backend"], False, 600),
    ]
    for fid,label,key,default,cwd,opt,timeout in specs:
        assert cwd is not None
        cmd = command_value(config,key) or default
        probe = _pytest_probe_with_clean_db_retry if any('pytest' in str(x).lower() for x in (cmd or [])) else command_probe
        finding, step = probe(config, finding_id=fid, label=label, command=cmd, cwd=cwd, timeout=timeout, optional=opt)
        findings.append(finding)
        if step: outputs.append(f"## {label}\n{step.output_tail}")
    audit = source_audit(paths["frontend"], paths["backend"])
    findings.append(Finding("kx.contract.double-api", FAIL if audit["double_api"] else PASS, f"Double /api prefix: {len(audit['double_api'])}", "contract", evidence=str(audit["double_api"][:20])))
    findings.append(Finding("kx.contract.forbidden-namespaces", FAIL if audit["forbidden"] else PASS, f"Forbidden legacy API calls: {len(audit['forbidden'])}", "contract", evidence=str(audit["forbidden"][:30])))
    findings.append(Finding("kx.contract.csrf-risk", WARN if audit["csrf_risk_files"] else PASS, f"Mutation files requiring CSRF review: {len(audit['csrf_risk_files'])}", "auth", evidence=str(audit["csrf_risk_files"][:30]), recommendation="Review raw mutation fetches. Calls through apiFetch/apiPost/apiPut/apiPatch/apiDelete or services/_request are treated as CSRF-aware." if audit["csrf_risk_files"] else None))
    findings.append(Finding("kx.contract.unmapped", WARN if audit["unmapped"] else PASS, f"Frontend endpoints not mapped to discovered backend prefixes: {len(audit['unmapped'])}", "contract", evidence=str(audit["unmapped"][:40])))

    worlds = _worlds_report(config)
    if _worlds_enabled_for_check(config, worlds):
        protected = bool(worlds.get("frontend", {}).get("next_api_safety_net"))
        legacy_literals = audit.get("world_owned_unscoped", [])
        findings.append(Finding(
            "kx.contract.world-owned-unscoped-literals",
            PASS if protected else (FAIL if legacy_literals else PASS),
            f"World-owned API literals protected by the canonical client/Next safety net: {len(legacy_literals)}" if protected else f"World-owned API literals without a verified scoping safety net: {len(legacy_literals)}",
            "worlds",
            evidence=str(legacy_literals[:40]),
            recommendation="Normalize legacy call-sites onto the canonical World-aware API client over time; the verified same-origin middleware currently protects them." if protected and legacy_literals else ("Restore the World API scoping safety net before accepting legacy unscoped calls." if legacy_literals else None),
        ))
        for group in ("frontend", "host", "engine", "ownership", "jobs"):
            values = worlds.get(group, {})
            failed = [name for name, ok in values.items() if not ok]
            findings.append(Finding(
                f"kx.worlds.contract.{group}",
                FAIL if failed else PASS,
                f"Worlds {group} contract {'failed' if failed else 'is coherent'}.",
                "worlds",
                evidence=str(failed) if failed else str(sorted(values)),
                recommendation="Repair the listed Worlds invariant(s) before accepting the overlay." if failed else None,
            ))

    auth = audit["auth_contract"]
    findings.append(Finding(
        "kx.auth.oidc-contract",
        PASS if auth["allauth_oidc_provider"] and auth["oidc_uid_sub"] and auth["oidc_optional"] else FAIL,
        "Common OIDC contract is present and optional." if auth["allauth_oidc_provider"] and auth["oidc_uid_sub"] and auth["oidc_optional"] else "Common OIDC contract is incomplete.",
        "auth",
        evidence=str({k: auth[k] for k in ("allauth_oidc_provider", "oidc_uid_sub", "oidc_optional")}),
    ))
    findings.append(Finding(
        "kx.auth.identity-link-policy",
        PASS if auth["email_auto_connect_disabled"] else FAIL,
        "Email auto-linking is disabled; external identity is not merged by email." if auth["email_auto_connect_disabled"] else "Email-based social-account auto-linking is not clearly disabled.",
        "auth",
    ))
    findings.append(Finding(
        "kx.auth.local-login",
        PASS if auth["accounts_route"] else FAIL,
        "Local django-allauth account routes remain available." if auth["accounts_route"] else "Local django-allauth account route is missing.",
        "auth",
    ))
    findings.append(Finding(
        "kx.auth.interactive-policy",
        PASS if auth["interactive_policy"] else FAIL,
        "Interactive-login policy for human/service/klone accounts is present." if auth["interactive_policy"] else "Interactive-login policy is missing or not enforced by the account adapter.",
        "auth",
    ))
    findings.append(Finding(
        "kx.auth.legacy-token-endpoint",
        FAIL if auth["legacy_token_endpoint"] else PASS,
        "Legacy DRF username/password auth-token endpoint is still exposed." if auth["legacy_token_endpoint"] else "Legacy DRF username/password auth-token endpoint is absent.",
        "auth",
    ))
    findings.append(Finding(
        "kx.auth.auth0-residue",
        WARN if auth["auth0_residue"] else PASS,
        "Legacy Auth0 frontend residue remains." if auth["auth0_residue"] else "Legacy Auth0 frontend scaffolding is absent.",
        "auth",
        evidence=str(auth["auth0_residue"]) if auth["auth0_residue"] else None,
    ))
    findings.append(Finding(
        "kx.auth.browser-session-contract",
        PASS if auth["csrf_browser_contract"] and auth["admin_allauth"] and auth["same_origin_api"] else FAIL,
        "Production browser auth contract is coherent: secure session/CSRF path, allauth admin, same-origin API." if auth["csrf_browser_contract"] and auth["admin_allauth"] and auth["same_origin_api"] else "Production browser auth contract is incomplete.",
        "auth",
        evidence=str({k: auth[k] for k in ("csrf_browser_contract", "admin_allauth", "same_origin_api")}),
    ))
    findings.append(Finding(
        "kx.auth.oidc-dependencies",
        PASS if auth["requirements_oidc"] else FAIL,
        "Backend requirements include django-allauth socialaccount/OIDC dependencies." if auth["requirements_oidc"] else "Backend requirements do not clearly include the django-allauth socialaccount extra.",
        "auth",
    ))
    return make_result(level_id, level_name, started, findings, output="\n\n".join(outputs), metadata={**session_metadata(config), "cwd": str(paths["root"]), "source_audit": audit, "worlds": worlds})



def _start_runtime_process(command: list[str] | None, cwd: Path, env: dict[str, str]) -> subprocess.Popen[str] | None:
    if not command or not cwd.is_dir():
        return None
    args = resolve_command(command, cwd=cwd)
    kwargs: dict[str, Any] = {
        "cwd": str(cwd),
        "env": env,
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.STDOUT,
        "text": True,
        "shell": False,
    }
    if os.name == "nt":
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    else:
        kwargs["start_new_session"] = True
    return subprocess.Popen(args, **kwargs)


def _stop_runtime_process(proc: subprocess.Popen[str] | None) -> None:
    if proc is None or proc.poll() is not None:
        return
    try:
        if os.name == "nt":
            subprocess.run(
                ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=15,
                shell=False,
                check=False,
            )
        else:
            import signal
            os.killpg(proc.pid, signal.SIGTERM)
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
    except (OSError, subprocess.SubprocessError):
        try:
            proc.kill()
        except OSError:
            pass


def _wait_for_urls(urls: list[str], timeout_seconds: int) -> dict[str, tuple[bool, str]]:
    deadline = time.monotonic() + max(1, timeout_seconds)
    pending = set(urls)
    results: dict[str, tuple[bool, str]] = {}
    last_errors: dict[str, str] = {}
    while pending and time.monotonic() < deadline:
        for url in list(pending):
            result = http_probe(url, timeout=2.0)
            if result.ok:
                results[url] = (True, f"HTTP {result.status} in {result.elapsed_ms}ms")
                pending.remove(url)
            else:
                last_errors[url] = result.error
        if pending:
            time.sleep(1.0)
    for url in pending:
        results[url] = (False, last_errors.get(url) or "startup timeout")
    return results

def runtime_smoke(config: AppConfig, level_id: str, level_name: str) -> LevelResult:
    started = now()
    paths = target_paths(config)
    section = kx_config(config)
    frontend_dir = paths["frontend"] or config.target_root_path
    backend_dir = paths["backend"] or config.target_root_path
    urls = section.get("local_urls", ["http://127.0.0.1:3000", "http://127.0.0.1:8000/api/"])
    if _i18n_focused(config):
        # The bilingual probe only needs the frontend shell. Do not make an
        # unrelated backend outage contaminate the focused i18n verdict.
        frontend_urls = [str(url) for url in urls if ":3000" in str(url)]
        urls = frontend_urls or ["http://127.0.0.1:3000"]
    findings: list[Finding] = []
    started_processes: list[subprocess.Popen[str] | None] = []
    worlds: dict[str, Any] = {}
    probe_report: dict[str, Any] = {}

    initial = {str(url): http_probe(str(url), timeout=3.0) for url in urls}
    needs_runtime = any(not result.ok for result in initial.values())
    autostart = bool(section.get("runtime_autostart", True))

    try:
        if needs_runtime and autostart:
            backend_cmd = command_value(config, "backend_runtime_start")
            frontend_cmd = command_value(config, "frontend_runtime_start")
            backend_needed = any(
                not result.ok and (":8000" in url or "/api" in url)
                for url, result in initial.items()
            )
            frontend_needed = any(
                not result.ok and ":3000" in url
                for url, result in initial.items()
            )
            backend_proc = _start_runtime_process(backend_cmd, backend_dir, config.env()) if backend_needed else None
            frontend_proc = _start_runtime_process(frontend_cmd, frontend_dir, config.env()) if frontend_needed else None
            started_processes.extend([backend_proc, frontend_proc])

            if backend_proc is not None:
                findings.append(Finding("kx.runtime.backend-start", PASS, "Backend runtime started by LevelUpDiag.", "runtime", path=str(backend_dir)))
            if frontend_proc is not None:
                findings.append(Finding("kx.runtime.frontend-start", PASS, "Frontend runtime started by LevelUpDiag.", "runtime", path=str(frontend_dir)))

            startup_timeout = int(section.get("runtime_startup_timeout_seconds", 120))
            readiness = _wait_for_urls([str(url) for url in urls], startup_timeout)
            for url in urls:
                ok, evidence = readiness[str(url)]
                findings.append(Finding(
                    "kx.runtime.local-http-ready",
                    PASS if ok else WARN,
                    f"Local runtime {'ready' if ok else 'not ready'}: {url}",
                    "runtime",
                    evidence=evidence,
                ))
        else:
            for url, result in initial.items():
                findings.append(Finding(
                    "kx.runtime.local-http",
                    PASS if result.ok else WARN,
                    f"Local probe {url}: {'OK' if result.ok else 'REFUSED/ERROR'}",
                    "runtime",
                    evidence=result.error or f"HTTP {result.status} {result.elapsed_ms}ms",
                ))

        worlds = _worlds_report(config)
        if _worlds_enabled_for_check(config, worlds) and not _i18n_focused(config):
            probe_report = probe_worlds_control_plane(config, paths)
            for item in probe_report.get("findings", []):
                findings.append(Finding(
                    item["id"],
                    item["severity"],
                    item["message"],
                    "worlds",
                    path=item.get("path"),
                    evidence=item.get("evidence"),
                    recommendation=item.get("recommendation"),
                ))

        playwright_timeout = int(section.get("playwright_smoke_timeout_seconds", 2400))
        step = None
        if _worlds_focused(config):
            findings.append(Finding(
                "kx.runtime.playwright-smoke",
                SKIP,
                "Full Playwright smoke is deferred to full-local after the focused Worlds qualification.",
                "runtime",
                recommendation="Run world-switch-validation to execute full-local after Worlds gates pass.",
            ))
        elif _i18n_focused(config):
            findings.append(Finding(
                "kx.runtime.playwright-smoke",
                SKIP,
                "Generic Playwright smoke is excluded from the focused i18n-validation campaign.",
                "runtime",
                recommendation="Run frontend or full-local separately for the broader Playwright suite.",
            ))
        else:
            seed_cmd = command_value(config, "ethikos_seed_workflow") or [
                "python",
                "manage.py",
                "seed_ethikos_workflow",
            ]
            seed_finding, _seed_step = command_probe(
                config,
                finding_id="kx.runtime.ethikos-seed",
                label="Ethikos workflow seed",
                command=seed_cmd,
                cwd=backend_dir,
                timeout=300,
                optional=True,
                recommendation=(
                    "The authenticated Playwright workflow needs the canonical local "
                    "Ethikos seed data."
                ),
            )
            findings.append(seed_finding)

            cmd = command_value(config, "playwright_smoke") or ["pnpm", "run", "smoke:gate"]
            finding, step = command_probe(
                config,
                finding_id="kx.runtime.playwright-smoke",
                label="Playwright smoke gate",
                command=cmd,
                cwd=frontend_dir,
                timeout=playwright_timeout,
                optional=True,
                recommendation=(
                    "Inspect Playwright failures and retained current-run artifacts. "
                    "The smoke gate runs with SMOKE_GATE=1. "
                    "If the full route campaign legitimately needs more time, set "
                    "konnaxion.playwright_smoke_timeout_seconds."
                ),
            )
            findings.append(finding)

        i18n_report = audit_i18n(frontend_dir)
        if i18n_report.get("detected") and not _worlds_focused(config):
            frontend_url = next((str(url) for url in urls if ":3000" in str(url)), str(urls[0]) if urls else "http://127.0.0.1:3000")
            probe_path = str(section.get("i18n_browser_probe_path", "/ekoh/dashboard?sidebar=ekoh"))
            i18n_timeout = int(section.get("i18n_browser_probe_timeout_seconds", 180))
            custom_i18n_cmd = command_value(config, "i18n_browser_probe")
            i18n_cmd = custom_i18n_cmd or browser_probe_command(frontend_url, probe_path)
            i18n_finding, i18n_step = command_probe(
                config,
                finding_id="kx.runtime.i18n-browser-switch",
                label="FR/EN browser language switch",
                command=i18n_cmd,
                cwd=frontend_dir,
                timeout=i18n_timeout,
                optional=not bool(section.get("i18n_browser_probe_required", True)),
                recommendation=(
                    "Verify the LanguageToggle is rendered in the application shell, html[lang] switches between fr-CA/en-CA, "
                    "and konnaxion.language persists in localStorage + cookie. Ensure Playwright Chromium is installed."
                ),
            )
            findings.append(i18n_finding)
            if i18n_step:
                outputs_i18n = i18n_step.output_tail
            else:
                outputs_i18n = ""
        else:
            outputs_i18n = ""
        return make_result(
            level_id,
            level_name,
            started,
            findings,
            output="\n\n".join(x for x in [step.output_tail if step else "", outputs_i18n] if x),
            metadata={
                **session_metadata(config),
                "autostarted_runtime": needs_runtime and autostart,
                "playwright_smoke_timeout_seconds": playwright_timeout,
                "worlds": worlds,
                "worlds_runtime_probe": probe_report,
                "focused_worlds_campaign": _worlds_focused(config),
                "focused_i18n_campaign": _i18n_focused(config),
                "i18n": audit_i18n(frontend_dir),
            },
        )
    finally:
        for proc in reversed(started_processes):
            _stop_runtime_process(proc)

def jobs(config: AppConfig, level_id: str, level_name: str) -> LevelResult:
    started=now(); backend_dir=target_paths(config)["backend"]; findings=[]; outputs=[]; assert backend_dir is not None
    specs=[
        ("kx.jobs.celery-tests","Celery task tests","backend_task_tests",["python","-m","pytest","konnaxion/users/tests/test_tasks.py","-q"],True,600),
        ("kx.jobs.custom-probe","Configured Redis/Celery runtime probe","jobs_probe",None,True,300),
    ]
    for fid,label,key,default,opt,timeout in specs:
        cmd=command_value(config,key) or default
        probe = _pytest_probe_with_clean_db_retry if any('pytest' in str(x).lower() for x in (cmd or [])) else command_probe
        finding,step=probe(config,finding_id=fid,label=label,command=cmd,cwd=backend_dir,timeout=timeout,optional=opt,recommendation="Configure konnaxion.commands.jobs_probe for live Redis/Celery verification." if key=="jobs_probe" else None)
        findings.append(finding)
        if step: outputs.append(step.output_tail)
    worlds = _worlds_report(config)
    if _worlds_enabled_for_check(config, worlds):
        pinned = bool(worlds.get("jobs", {}).get("release_pinned_task_scope"))
        findings.append(Finding(
            "kx.worlds.jobs.release-pinned",
            PASS if pinned else FAIL,
            "World task scope pins world_id + release_id and rejects stale releases." if pinned else "World task scope is not clearly release-pinned/fail-closed.",
            "worlds",
            recommendation="Use world_task_scope(world_id, release_id) for World-owned mutation tasks." if not pinned else None,
        ))
    return make_result(level_id,level_name,started,findings,output="\n".join(outputs),metadata={**session_metadata(config),"cwd":str(backend_dir),"worlds":worlds})



def _unified_web_trust_gate(config: AppConfig, paths: dict[str, Path | None]):
    """v4 compatibility finding: security release qualification lives in S04/S04W/S14."""
    return Finding(
        "kx.security.unified-web-trust",
        SKIP,
        "Nested security-profile execution is disabled in N07; S04/S04W are qualified independently by the unified security profile.",
        "security",
        recommendation="Run `kdiag run release-all` for the authoritative cross-domain release gate.",
    ), None

def security(config: AppConfig, level_id: str, level_name: str) -> LevelResult:
    started=now(); paths=target_paths(config); findings=[]; outputs=[]; backend_dir=paths["backend"]; assert backend_dir is not None
    cmd=command_value(config,"django_deploy_check") or ["python","manage.py","check","--deploy"]
    finding,step=command_probe(config,finding_id="kx.security.django-deploy-check",label="Django deploy security check",command=cmd,cwd=backend_dir,timeout=300,optional=True)
    findings.append(finding)
    if step: outputs.append(step.output_tail)

    cmd=command_value(config,"backend_auth_policy") or ["python","-m","pytest","konnaxion/users/tests/test_auth_policy.py","-q"]
    finding,step=_pytest_probe_with_clean_db_retry(
        config,
        finding_id="kx.security.auth-policy-tests",
        label="Konnaxion common-auth policy tests",
        command=cmd,
        cwd=backend_dir,
        timeout=300,
        optional=False,
        recommendation="Restore/run konnaxion/users/tests/test_auth_policy.py and align the local allauth/OIDC policy.",
    )
    findings.append(finding)
    if step: outputs.append(step.output_tail)

    finding, step = _unified_web_trust_gate(config, paths)
    findings.append(finding)
    if step: outputs.append(step.output_tail)

    worlds = _worlds_report(config)
    if _worlds_enabled_for_check(config, worlds):
        host_contract = worlds.get("host", {})
        engine_contract = worlds.get("engine", {})
        security_checks = {
            "host.middleware_after_auth": host_contract.get("middleware_after_auth"),
            "host.data_plane_default_off": host_contract.get("data_plane_default_off"),
            "host.scoped_api_default_on": host_contract.get("scoped_api_default_on"),
            "host.data_plane_fail_closed_503": host_contract.get("data_plane_fail_closed_503"),
            "engine.transaction_local_search_path": engine_contract.get("transaction_local_search_path"),
            "engine.response_context_headers": engine_contract.get("response_context_headers"),
            "engine.canonical_and_legacy_runtime_routing": engine_contract.get("canonical_and_legacy_runtime_routing"),
        }
        failed = [key for key, ok in security_checks.items() if not ok]
        security_keys = tuple(security_checks)
        findings.append(Finding(
            "kx.worlds.security.fail-closed",
            FAIL if failed else PASS,
            "World isolation/security invariants are fail-closed." if not failed else "World fail-closed security invariants are incomplete.",
            "worlds",
            evidence=str(failed) if failed else ", ".join(security_keys),
            recommendation="Do not enable the World data plane until all fail-closed invariants pass." if failed else None,
        ))

    cm=paths["capsule_manager"]
    if cm and cm.is_dir():
        cmd=command_value(config,"capsule_security_tests") or ["python","-m","pytest","tests/test_security_gate.py","-q"]
        finding,step=command_probe(config,finding_id="kx.security.capsule-gate",label="Capsule Manager security gate tests",command=cmd,cwd=cm,timeout=600,optional=True)
        findings.append(finding)
        if step: outputs.append(step.output_tail)
    else:
        findings.append(Finding("kx.security.capsule-gate",WARN,"Capsule Manager security checks unavailable because its repository is not configured.","security"))
    return make_result(level_id,level_name,started,findings,output="\n".join(outputs),metadata={**session_metadata(config),"cwd":str(paths["root"]),"worlds":worlds})


def capsule_local(config: AppConfig, level_id: str, level_name: str) -> LevelResult:
    started=now(); paths=target_paths(config); findings=[]; outputs=[]
    cm=paths["capsule_manager"]; capsule=paths["capsule_file"]
    if cm and cm.is_dir():
        findings.append(Finding("kx.capsule.manager-repo",PASS,"Capsule Manager repository available.","capsule",path=str(cm)))
        health=cm/"kx_agent"/"runtime"/"healthchecks.py"
        findings.append(Finding("kx.capsule.healthchecks-source",PASS if health.is_file() else WARN,"Capsule runtime healthcheck engine found." if health.is_file() else "Capsule runtime healthcheck engine not found at expected path.","capsule",path=str(health)))
        cmd=command_value(config,"capsule_manager_tests") or ["python","-m","pytest","tests/test_instance_states.py","-q"]
        finding,step=command_probe(config,finding_id="kx.capsule.manager-tests",label="Capsule Manager instance-state tests",command=cmd,cwd=cm,timeout=600,optional=True)
        findings.append(finding)
        if step: outputs.append(step.output_tail)
    else:
        findings.append(Finding("kx.capsule.manager-repo",WARN,"Capsule Manager repository not configured; local capsule diagnostics are limited.","capsule"))
    if capsule:
        if capsule.is_file():
            digest=_sha256_file(capsule)
            findings.append(Finding("kx.capsule.file",PASS,"Configured capsule file exists and was hashed.","capsule",path=str(capsule),evidence=f"sha256={digest} size={capsule.stat().st_size}"))
        else:
            findings.append(Finding("kx.capsule.file",WARN,"Configured capsule file does not exist.","capsule",path=str(capsule)))
    else:
        findings.append(Finding("kx.capsule.file",SKIP,"No capsule file configured; file integrity probe skipped.","capsule"))
    return make_result(level_id,level_name,started,findings,output="\n".join(outputs),metadata={**session_metadata(config),"cwd":str(cm or paths["root"])})


def deployed(config: AppConfig, level_id: str, level_name: str) -> LevelResult:
    started=now(); section=kx_config(config); findings=[]; outputs=[]
    remote=section.get("remote", {}); remote=dict(remote) if isinstance(remote,dict) else {}
    enabled=bool(remote.get("enabled",False))
    if not enabled:
        findings.append(Finding("kx.remote.enabled",WARN,"Remote diagnostics are disabled. Local diagnostics remain active.","remote",recommendation="Set konnaxion.remote.enabled=true only when deployed-runtime diagnostics are desired."))
        return make_result(level_id,level_name,started,findings,metadata={**session_metadata(config),"remote_enabled":False})
    domain=str(remote.get("domain","")).strip()
    urls=remote.get("urls")
    if not isinstance(urls,list) or not urls:
        urls=[f"https://{domain}/",f"https://{domain}/api/",f"https://{domain}/admin/"] if domain else []
    for index,url in enumerate(urls):
        if not isinstance(url,str) or not url.strip(): continue
        result=http_probe(url,timeout=float(remote.get("http_timeout_seconds",10)),allow_insecure_tls=bool(remote.get("allow_insecure_tls",False)))
        findings.append(Finding(f"kx.remote.http.{index:02d}",PASS if result.ok else FAIL,f"Remote HTTP probe {'succeeded' if result.ok else 'failed'}: {url}","remote",path=url,evidence=f"status={result.status} elapsed_ms={result.elapsed_ms} error={result.error}"))
    if domain:
        try:
            addresses=sorted({item[4][0] for item in socket.getaddrinfo(domain,None)})
            findings.append(Finding("kx.remote.dns",PASS,f"DNS resolved for {domain}.","remote",path=domain,evidence=", ".join(addresses)))
        except OSError as exc:
            findings.append(Finding("kx.remote.dns",FAIL,f"DNS resolution failed for {domain}.","remote",path=domain,evidence=str(exc)))
    deep=command_value(config,"remote_deep_diagnostic")
    if deep:
        cwd=target_paths(config)["capsule_manager"] or config.target_root_path
        finding,step=command_probe(config,finding_id="kx.remote.deep-diagnostic",label="Configured deep deployed-runtime diagnostic",command=deep,cwd=cwd,timeout=int(remote.get("deep_timeout_seconds",1800)),optional=True)
        findings.append(finding)
        if step: outputs.append(step.output_tail)
    else:
        findings.append(Finding("kx.remote.deep-diagnostic",SKIP,"No deep remote diagnostic command configured; read-only HTTP/DNS probes only.","remote"))
    return make_result(level_id,level_name,started,findings,output="\n".join(outputs),metadata={**session_metadata(config),"remote_enabled":True,"domain":domain})


def _latest_result(config: AppConfig, level: str):
    # KonnaxionDiag v4 has one canonical evidence tree. N11 reads the active
    # campaign directly instead of a duplicated LevelUpDiag latest mirror.
    path=config.control_root_path/"current"/"levels"/str(level).upper()/"result.json"
    if not path.is_file(): return None
    try: return read_level_result(path)
    except Exception: return None


def correlation(config: AppConfig, level_id: str, level_name: str) -> LevelResult:
    started=now(); findings=[]; session=active_session(config); session_id=str(session.get("session_id")) if session else ""
    observed=[]
    if not session_id:
        findings.append(Finding("kx.correlation.session",WARN,"No active diagnostic session found; correlation is limited.","correlation"))
    else:
        findings.append(Finding("kx.correlation.session",PASS,f"Correlating current diagnostic session {session_id}.","correlation"))
    failures=[]; warnings=[]; missing=[]
    expected = session.get("expected_levels", []) if session else []
    if not isinstance(expected, list) or not expected:
        expected = [f"N{number:02d}" for number in range(1, 11)]
    expected = [str(lid) for lid in expected if str(lid) not in {"N00", "N11"}]
    for lid in expected:
        result=_latest_result(config,lid)
        if result is None:
            missing.append(lid); continue
        if session_id and str(result.metadata.get("diagnostic_session_id","")) != session_id:
            missing.append(lid); continue
        observed.append((lid,result))
        if result.verdict in {FAIL,INFRA_ERROR,CONFIG_ERROR,"ERROR","BLOCKED"}: failures.append((lid,result))
        elif result.verdict == WARN: warnings.append((lid,result))
    if missing:
        findings.append(Finding("kx.correlation.coverage",WARN,"Some diagnostic domains were not executed in the current session.","correlation",evidence=", ".join(missing),recommendation="Run the full-local or connection-debug campaign for broader evidence."))
    else:
        findings.append(Finding("kx.correlation.coverage",PASS,"All diagnostic domains expected by this campaign have current-session evidence.","correlation",evidence=", ".join(expected)))

    ids={f.id for _,r in observed for f in r.findings if f.severity in {FAIL,INFRA_ERROR,CONFIG_ERROR,"ERROR"}}
    hypotheses=[]
    if any(x.startswith("kx.frontend.") for x in ids): hypotheses.append("frontend build/type/test failure")
    if any(x.startswith("kx.backend.") for x in ids): hypotheses.append("backend/Django/database failure")
    if any(x.startswith("kx.contract.") for x in ids): hypotheses.append("frontend↔backend API contract mismatch")
    if any(x.startswith("kx.runtime.") for x in ids): hypotheses.append("local runtime/browser smoke failure")
    if any(x.startswith("kx.jobs.") for x in ids): hypotheses.append("Celery/Redis/background-job failure")
    if any(x.startswith("kx.worlds.") for x in ids): hypotheses.append("Konnaxion Universe/World routing, ownership, isolation or release failure")
    if any(x.startswith("kx.capsule.") for x in ids): hypotheses.append("capsule packaging/runtime-manager failure")
    if any(x.startswith("kx.remote.") for x in ids): hypotheses.append("deployed DNS/HTTP/Agent/runtime failure")
    if failures:
        evidence="; ".join(f"{lid}={r.verdict}" for lid,r in failures)
        findings.append(Finding("kx.correlation.failures",FAIL,"Blocking failures were detected in the current diagnostic session.","correlation",evidence=evidence,recommendation="Fix the earliest failing domain, then rerun the focused campaign."))
    elif warnings:
        findings.append(Finding("kx.correlation.failures",WARN,"No blocking failure was found, but warnings remain.","correlation",evidence="; ".join(f"{lid}={r.verdict}" for lid,r in warnings)))
    else:
        findings.append(Finding("kx.correlation.failures",PASS,"No blocking failure or warning was found in correlated current-session results.","correlation"))
    if hypotheses:
        findings.append(Finding("kx.correlation.hypotheses",WARN,"Likely failure domain(s): " + ", ".join(hypotheses),"correlation",evidence=" | ".join(hypotheses)))
    elif failures:
        findings.append(Finding("kx.correlation.hypotheses",WARN,"Failures exist but do not match a specialized correlation rule yet.","correlation"))
    else:
        findings.append(Finding("kx.correlation.hypotheses",PASS,"No failure-domain hypothesis required.","correlation"))
    return make_result(level_id,level_name,started,findings,metadata={"diagnostic_session_id":session_id,"campaign":session.get("campaign", "") if session else "","expected_levels":expected,"observed_levels":[lid for lid,_ in observed],"hypotheses":hypotheses})


CHECKS = {
    "N00": discovery,
    "N01": repository_static,
    "N02": backend,
    "N03": frontend,
    "N04": contracts,
    "N05": runtime_smoke,
    "N06": jobs,
    "N07": security,
    "N08": capsule_local,
    "N09": deployed,
    # N10 intentionally performs a broad deep/full-scan command when configured.
}


def deep_scan(config: AppConfig, level_id: str, level_name: str) -> LevelResult:
    started=now(); paths=target_paths(config); findings=[]; outputs=[]; frontend=paths["frontend"]; assert frontend is not None
    backend_dir=paths["backend"]; assert backend_dir is not None

    # world-switch is a focused qualification. The expensive generic deep scan
    # belongs to full-local, which world-switch-validation runs only after this
    # campaign succeeds.
    if not _worlds_focused(config):
        cmd=command_value(config,"frontend_full_scan")
        if cmd is None:
            script=frontend/"tools"/"full-scan.ps1"
            if script.is_file():
                shell="pwsh" if _find_tool("pwsh") else "powershell"
                cmd=[shell,"-NoProfile","-ExecutionPolicy","Bypass","-File",str(script)]
                if _powershell_supports_deep_only(script):
                    cmd.append("-DeepOnly")
        finding,step=command_probe(config,finding_id="kx.deep.frontend-full-scan",label="Konnaxion full frontend diagnostic scan",command=cmd,cwd=frontend,timeout=2400,optional=True,recommendation="Keep frontend/tools/full-scan.ps1 or configure konnaxion.commands.frontend_full_scan.")
        findings.append(finding)
        if step: outputs.append(step.output_tail)
        cmd=command_value(config,"backend_full_tests") or ["python","-m","pytest","-q"]
        finding,step=_pytest_probe_with_clean_db_retry(config,finding_id="kx.deep.backend-tests",label="Full backend pytest suite",command=cmd,cwd=backend_dir,timeout=2400,optional=True)
        findings.append(finding)
        if step: outputs.append(step.output_tail)
    else:
        findings.append(Finding(
            "kx.deep.generic-deferred",
            SKIP,
            "Generic frontend/full-backend deep scans are deferred to full-local.",
            "worlds",
        ))

    worlds = _worlds_report(config)
    if _worlds_enabled_for_check(config, worlds):
        cmd = command_value(config, "backend_worlds_isolation_tests") or [
            "python", "-m", "pytest",
            "konnaxion/worlds/tests/test_multiworld_isolation.py",
            "konnaxion/worlds/tests/test_universes.py",
            "konnaxion/worlds/tests/test_strict_routing.py",
            "-q",
        ]
        finding, step = _pytest_probe_with_clean_db_retry(
            config,
            finding_id="kx.worlds.deep-isolation",
            label="Universe/World isolation + invariant tests",
            command=cmd,
            cwd=paths.get("worlds_backend") or backend_dir,
            timeout=900,
            optional=not _worlds_required(config),
            recommendation="Validate Alpha/Beta schema and release isolation on PostgreSQL before enabling the data plane.",
        )
        findings.append(finding)
        if step: outputs.append(step.output_tail)

    return make_result(level_id,level_name,started,findings,output="\n\n".join(outputs),metadata={**session_metadata(config),"cwd":str(paths["root"]),"worlds":worlds})

CHECKS["N10"] = deep_scan
CHECKS["N11"] = correlation


def run_domain(config: AppConfig, level_id: str, level_name: str) -> LevelResult:
    fn=CHECKS[level_id]
    return fn(config,level_id,level_name)
