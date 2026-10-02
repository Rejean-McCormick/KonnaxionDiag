from __future__ import annotations

import json
import os
import re
import shlex
import sys
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Iterable, Sequence

from diagcore.commands import find_executable, run_cmd
from diagcore.config import AppConfig
from diagcore.models import Artifact, Finding, LevelResult, StepResult
from diagcore.verdicts import (
    CONFIG_ERROR,
    ERROR,
    FAIL,
    INFRA_ERROR,
    PARTIAL,
    PASS,
    SKIP,
    WARN,
    aggregate_verdicts,
)

_SECRET_RE = re.compile(
    r"(?i)(password|secret|token|private[_-]?key|api[_-]?key|authorization|cookie)"
    r"(\s*[:=]\s*)([^\s\"';]+)"
)
_URL_SECRET_RE = re.compile(r"(?i)((?:postgres|postgresql|redis)://[^:/\s]+:)[^@\s]+@")


def now() -> datetime:
    return datetime.now().astimezone()


def redact(text: str | None) -> str:
    value = "" if text is None else str(text)
    value = _SECRET_RE.sub(r"\1\2[REDACTED]", value)
    value = _URL_SECRET_RE.sub(r"\1[REDACTED]@", value)
    return value


def kx_config(config: AppConfig) -> dict[str, Any]:
    raw = config.get("konnaxion", {})
    return dict(raw) if isinstance(raw, dict) else {}


def _path_from(config: AppConfig, value: str | None, *, base: Path | None = None) -> Path | None:
    if not isinstance(value, str) or not value.strip():
        return None
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = (base or config.target_root_path) / path
    return path.resolve()


def target_paths(config: AppConfig) -> dict[str, Path | None]:
    section = kx_config(config)
    target = config.target_root_path
    worlds = section.get("worlds", {}) if isinstance(section.get("worlds", {}), dict) else {}
    worlds_repo = _path_from(config, worlds.get("repo_dir", "../Konnaxion_Worlds"), base=target)

    securitydiag = None  # external SecurityDiag coupling removed in KonnaxionDiag v4

    return {
        "root": target,
        "frontend": _path_from(config, section.get("frontend_dir", "frontend"), base=target),
        "backend": _path_from(config, section.get("backend_dir", "backend"), base=target),
        "worlds_repo": worlds_repo,
        "worlds_backend": (worlds_repo / "backend").resolve(strict=False) if worlds_repo else None,
        "capsule_manager": _path_from(config, section.get("capsule_manager_repo"), base=config.diagnostics_root_path),
        "capsule_file": _path_from(config, section.get("capsule_file"), base=config.diagnostics_root_path),
        "securitydiag": securitydiag,
    }


def command_value(config: AppConfig, name: str) -> list[str] | None:
    section = kx_config(config)
    commands = section.get("commands", {})
    if not isinstance(commands, dict):
        return None
    raw = commands.get(name)
    if raw is None or raw == "":
        return None
    if isinstance(raw, list) and all(isinstance(x, str) for x in raw) and raw:
        return list(raw)
    if isinstance(raw, str) and raw.strip():
        return shlex.split(raw, posix=not sys.platform.startswith("win"))
    return None


def resolve_command(command: Sequence[str], *, cwd: Path | None = None) -> list[str]:
    args = list(command)
    if not args:
        raise ValueError("empty command")
    aliases = {
        "python": [sys.executable],
        "python3": [sys.executable],
        "pnpm": ["pnpm.cmd", "pnpm"] if os.name == "nt" else ["pnpm"],
        "node": ["node.exe", "node"] if os.name == "nt" else ["node"],
        "git": ["git.exe", "git"] if os.name == "nt" else ["git"],
        "pwsh": ["pwsh.exe", "pwsh"] if os.name == "nt" else ["pwsh"],
        "powershell": ["powershell.exe", "powershell"] if os.name == "nt" else ["powershell"],
        "kx": ["kx.exe", "kx"] if os.name == "nt" else ["kx"],
    }
    first = args[0].casefold()
    if first in {"python", "python3"} and cwd is not None:
        candidates = [cwd/".venv"/("Scripts/python.exe" if os.name=="nt" else "bin/python"), cwd/"venv"/("Scripts/python.exe" if os.name=="nt" else "bin/python")]
        for candidate in candidates:
            if candidate.is_file():
                args[0] = str(candidate)
                return args
    if first == "pnpm":
        direct = find_executable("pnpm.cmd" if os.name == "nt" else "pnpm") or find_executable("pnpm")
        if direct:
            args[0] = direct
            return args
        corepack = find_executable("corepack.cmd" if os.name == "nt" else "corepack") or find_executable("corepack")
        if corepack:
            return [corepack, "pnpm", *args[1:]]
    if first in aliases:
        for candidate in aliases[first]:
            found = find_executable(candidate)
            if found:
                args[0] = found
                return args
        if first in {"python", "python3"}:
            args[0] = sys.executable
            return args
    return args


def _command_env(config: AppConfig, cwd: Path) -> dict[str, str]:
    """Return the command environment with KX-UNIVERSES-1 source composition.

    The host Konnaxion repo deliberately does not vendor ``konnaxion.worlds``.
    When a diagnostic command executes from the host backend, expose the
    sibling Konnaxion_Worlds/backend source root through PYTHONPATH.  Commands
    executed inside the engine repo itself are left unchanged.
    """
    env = config.env()
    paths = target_paths(config)
    host_backend = paths.get("backend")
    worlds_backend = paths.get("worlds_backend")
    if not host_backend or not worlds_backend or not worlds_backend.is_dir():
        return env
    try:
        is_host_backend = cwd.resolve(strict=False) == host_backend.resolve(strict=False)
    except OSError:
        is_host_backend = False
    if not is_host_backend:
        return env

    extra = str(worlds_backend.resolve(strict=False))
    current = str(env.get("PYTHONPATH", "") or "")
    parts = [part for part in current.split(os.pathsep) if part]
    normalized = {os.path.normcase(os.path.normpath(part)) for part in parts}
    if os.path.normcase(os.path.normpath(extra)) not in normalized:
        parts.insert(0, extra)
    env["PYTHONPATH"] = os.pathsep.join(parts)
    return env


def command_probe(
    config: AppConfig,
    *,
    finding_id: str,
    label: str,
    command: Sequence[str] | None,
    cwd: Path,
    timeout: int,
    optional: bool = False,
    recommendation: str | None = None,
) -> tuple[Finding, StepResult | None]:
    if not command:
        severity = SKIP if optional else CONFIG_ERROR
        return (
            Finding(
                id=finding_id,
                severity=severity,
                category="configuration",
                message=f"{label}: command is not configured.",
                path=str(cwd),
                recommendation=recommendation or "Configure the command in levelupdiag.config.local.json.",
            ),
            None,
        )
    if not cwd.is_dir():
        severity = SKIP if optional else CONFIG_ERROR
        return (
            Finding(
                id=finding_id,
                severity=severity,
                category="configuration",
                message=f"{label}: working directory does not exist.",
                path=str(cwd),
            ),
            None,
        )
    args = resolve_command(command, cwd=cwd)
    step = run_cmd(args, cwd=cwd, timeout=timeout, name=label, env=_command_env(config, cwd), tail_chars=12000)
    evidence = redact(step.output_tail)
    if step.verdict == PASS:
        severity = PASS
        message = f"{label} passed."
    elif step.verdict == INFRA_ERROR:
        severity = INFRA_ERROR if not optional else WARN
        message = f"{label} could not be executed."
    else:
        severity = FAIL if not optional else WARN
        message = f"{label} failed."
    finding = Finding(
        id=finding_id,
        severity=severity,
        category="command",
        message=message,
        path=str(cwd),
        evidence=(evidence[-6000:] if evidence else step.error),
        recommendation=recommendation,
        data={
            "command": list(step.command),
            "exit_code": step.exit_code,
            "duration_seconds": step.duration_seconds,
        },
    )
    return finding, step


def verdict_from(findings: Iterable[Finding], *, default: str = PASS) -> str:
    values = [f.severity for f in findings]
    if not values:
        return default
    # SKIP is useful at finding granularity, but a level with only optional skips
    # should remain usable in a campaign.
    mapped = [PASS if value == SKIP else value for value in values]
    return aggregate_verdicts(mapped)


def make_result(
    level_id: str,
    level_name: str,
    started: datetime,
    findings: list[Finding],
    *,
    output: str = "",
    metadata: dict[str, Any] | None = None,
    artifacts: list[Artifact] | None = None,
) -> LevelResult:
    ended = now()
    session_id = current_session_id_from_metadata(metadata)
    out_meta = dict(metadata or {})
    if session_id:
        out_meta["diagnostic_session_id"] = session_id
    return LevelResult(
        level=level_id,
        name=level_name,
        verdict=verdict_from(findings),
        findings=findings,
        artifacts=list(artifacts or []),
        started_at=started.isoformat(timespec="seconds"),
        ended_at=ended.isoformat(timespec="seconds"),
        duration_seconds=round((ended - started).total_seconds(), 6),
        cwd=str(out_meta.get("cwd", "")),
        output_tail=redact(output)[-12000:],
        metadata=out_meta,
    )


def active_session_path(config: AppConfig) -> Path:
    return config.control_root_path / "konnaxion" / "active-session.json"


def start_session(config: AppConfig) -> str:
    session_id = f"kxdiag-{now().strftime('%Y%m%d_%H%M%S')}-{uuid.uuid4().hex[:8]}"
    path = active_session_path(config)
    path.parent.mkdir(parents=True, exist_ok=True)
    expected = [x for x in os.environ.get("LEVELUPDIAG_EXPECTED_LEVELS", "").split(",") if x]
    payload = {
        "session_id": session_id,
        "started_at": now().isoformat(timespec="seconds"),
        "target": str(config.target_root_path),
        "campaign": os.environ.get("LEVELUPDIAG_CAMPAIGN", ""),
        "expected_levels": expected,
        "run_id": os.environ.get("LEVELUPDIAG_RUN_ID", ""),
    }
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    tmp.replace(path)
    return session_id


def active_session(config: AppConfig, *, max_age_minutes: int = 180) -> dict[str, Any] | None:
    path = active_session_path(config)
    if not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        started = datetime.fromisoformat(str(payload["started_at"]))
        if now() - started > timedelta(minutes=max_age_minutes):
            return None
        if str(payload.get("target", "")) != str(config.target_root_path):
            return None
        return payload
    except (OSError, ValueError, KeyError, json.JSONDecodeError):
        return None


def session_metadata(config: AppConfig) -> dict[str, Any]:
    session = active_session(config)
    return {"diagnostic_session_id": session.get("session_id")} if session else {}


def current_session_id_from_metadata(metadata: dict[str, Any] | None) -> str | None:
    if not metadata:
        return None
    value = metadata.get("diagnostic_session_id")
    return str(value) if value else None
