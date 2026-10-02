from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import Any
from . import REPORT_SCHEMA

@dataclass(slots=True)
class Finding:
    id: str
    severity: str
    message: str
    category: str
    path: str | None = None
    evidence: Any = None
    recommendation: str | None = None
    data: dict[str, Any] | None = None
    release_blocker: bool | None = None

    @property
    def verdict(self) -> str:
        return self.severity

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["verdict"] = d.pop("severity")
        return {k: v for k, v in d.items() if v is not None}

@dataclass(slots=True)
class Artifact:
    kind: str
    path: str
    description: str | None = None
    data: dict[str, Any] | None = None
    def to_dict(self):
        return {k:v for k,v in asdict(self).items() if v is not None}

@dataclass(slots=True)
class StepResult:
    name: str
    command: tuple[str, ...]
    cwd: str
    verdict: str
    exit_code: int | None
    duration_seconds: float
    output_tail: str = ""
    error: str = ""
    timed_out: bool = False
    def to_dict(self): return asdict(self)

@dataclass(slots=True)
class LevelResult:
    level: str
    name: str
    verdict: str
    findings: list[Finding] = field(default_factory=list)
    artifacts: list[Artifact] = field(default_factory=list)
    started_at: str = ""
    ended_at: str = ""
    duration_seconds: float = 0.0
    cwd: str = ""
    output_tail: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def level_id(self): return self.level
    @property
    def level_name(self): return self.name

    def to_dict(self, *, profile: str | None = None, run_id: str | None = None, target_root: str | None = None) -> dict[str, Any]:
        data = {
            "schema": REPORT_SCHEMA,
            "standard": "KonnaxionDiag",
            "standard_version": "4.2.0",
            "profile": profile,
            "run_id": run_id,
            "level_id": self.level,
            "level": self.level,
            "level_name": self.name,
            "name": self.name,
            "verdict": self.verdict,
            "findings": [f.to_dict() for f in self.findings],
            "artifacts": [a.to_dict() for a in self.artifacts],
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "duration_seconds": self.duration_seconds,
            "cwd": self.cwd,
            "output_tail": self.output_tail,
            "metadata": self.metadata,
            "target_repo_root": target_root,
        }
        return {k:v for k,v in data.items() if v not in (None, "") or k in {"cwd","output_tail"}}
