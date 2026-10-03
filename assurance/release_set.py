from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any, Iterable

from diagcore import VERSION
from diagcore.utils import read_json, redact_data
from diagcore.subprocesses import hidden_process_kwargs

RELEASE_SET_SCHEMA = "konnaxiondiag.release-set.v1"
SHA256_PREFIX = "sha256:"


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sha256_json(value: Any) -> str:
    return SHA256_PREFIX + hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return SHA256_PREFIX + h.hexdigest()


def _run_git(target: Path, *args: str) -> str | None:
    if shutil.which("git") is None:
        return None
    try:
        cp = subprocess.run(
            ["git", *args], cwd=str(target), stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, encoding="utf-8", errors="replace", timeout=20,
            shell=False, check=False, **hidden_process_kwargs(),
        )
        return cp.stdout.strip() if cp.returncode == 0 else None
    except Exception:
        return None


def git_identity(target: Path) -> dict[str, Any]:
    status = _run_git(target, "status", "--porcelain=v1", "--untracked-files=all")
    commit = _run_git(target, "rev-parse", "HEAD")
    tree = _run_git(target, "rev-parse", "HEAD^{tree}")
    branch = _run_git(target, "rev-parse", "--abbrev-ref", "HEAD")
    return {
        "source_commit_sha": commit,
        "source_tree_digest": f"git-sha1:{tree}" if tree else None,
        "source_branch": branch,
        "worktree_clean": status == "" if status is not None else None,
        "worktree_status_sha256": SHA256_PREFIX + hashlib.sha256((status or "").encode("utf-8")).hexdigest()
        if status is not None else None,
    }


def _capsule_subjects(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    subjects: list[dict[str, Any]] = []
    for result in results:
        if result.get("level_id") != "S09":
            continue
        for finding in result.get("findings", []):
            if finding.get("id") != "capsule.security_gate.evidence":
                continue
            evidence = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
            subject = evidence.get("subject")
            if isinstance(subject, dict):
                subjects.append(subject)
    return subjects


def _normalize_digest(value: Any) -> str | None:
    text = str(value or "").strip().lower()
    if not text:
        return None
    if text.startswith("sha256:") and len(text) == 71:
        try:
            int(text[7:], 16)
            return text
        except ValueError:
            return None
    if len(text) == 64:
        try:
            int(text, 16)
            return "sha256:" + text
        except ValueError:
            return None
    return None


def _digest_component_files(target_root: Path, raw: Any) -> tuple[str | None, list[dict[str, str]], list[str]]:
    """Digest one logical ReleaseSet component from one or more files.

    The component digest is a canonical hash of relative-path + file-digest entries,
    so changing either bytes or the selected file set changes the ReleaseSet identity.
    """
    if raw in (None, "", [], {}):
        return None, [], []
    values = raw if isinstance(raw, list) else [raw]
    entries: list[dict[str, str]] = []
    issues: list[str] = []
    for item in values:
        if isinstance(item, dict):
            rel = str(item.get("path", "")).strip()
        else:
            rel = str(item).strip()
        if not rel:
            issues.append("component contains an empty path")
            continue
        p = Path(rel).expanduser()
        p = p if p.is_absolute() else (target_root / p).resolve(strict=False)
        if not p.is_relative_to(target_root):
            issues.append(f"component path escapes target repository: {rel}")
            continue
        if not p.is_file():
            issues.append(f"component file is missing: {rel}")
            continue
        entries.append({
            "path": p.relative_to(target_root).as_posix(),
            "digest": _sha256_file(p),
        })
    entries.sort(key=lambda x: x["path"])
    return (_sha256_json(entries) if entries and not issues else None), entries, issues


def _effective_policy_digest(cfg: dict[str, Any]) -> str:
    policy = {k: v for k, v in redact_data(cfg).items() if not str(k).startswith("_")}
    # Keys and risk acceptances authorize a decision; they are not release bytes.
    gate = policy.get("release_gate")
    if isinstance(gate, dict):
        gate.pop("security_warn_dispositions", None)
        signing = gate.get("signing")
        if isinstance(signing, dict):
            signing.pop("private_key_file", None)
    release = policy.get("release")
    if isinstance(release, dict):
        release.pop("warn_dispositions", None)
    return _sha256_json(policy)


def _registry_digest(cfg: dict[str, Any]) -> str | None:
    tool_root = Path(str(cfg.get("_tool_root", "") or Path(__file__).resolve().parents[1])).resolve(strict=False)
    path = tool_root / "security_contracts.json"
    if not path.is_file():
        path = tool_root / "assurance" / "security_contracts.json"
    try:
        return _sha256_json(read_json(path)) if path.is_file() else None
    except Exception:
        return None


def build_release_set(*, target_root: Path, results: list[dict[str, Any]], cfg: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """Build the exact release object that a signed authorization applies to.

    Important: `release_set_digest` intentionally excludes `security_evidence_set_digest`.
    External attestations can therefore bind to the immutable release object without a
    cryptographic cycle. The final signed authorization covers both digests.
    """
    rs_cfg = cfg.get("release_set", {}) if isinstance(cfg.get("release_set", {}), dict) else {}
    subject_cfg = cfg.get("release_gate", {}).get("subject_binding", {}) if isinstance(cfg.get("release_gate", {}), dict) else {}
    require_git = bool(rs_cfg.get("require_git_identity", subject_cfg.get("require_git_identity", True)))
    require_clean = bool(rs_cfg.get("require_clean_worktree", subject_cfg.get("require_clean_worktree", True)))
    required_components = rs_cfg.get("required_components", ["source"])
    if not isinstance(required_components, list):
        raise ValueError("release_set.required_components must be a list")
    required_components = [str(x).strip() for x in required_components if str(x).strip()]

    issues: list[str] = []
    git = git_identity(target_root)
    if require_git and (not git.get("source_commit_sha") or not git.get("source_tree_digest")):
        issues.append("source identity could not be resolved from Git")
    if require_clean and git.get("worktree_clean") is not True:
        issues.append("ReleaseSet requires a clean Git worktree")

    subjects = _capsule_subjects([r for r in results if r.get("level_id") != "S14"])
    manifest_digests: list[str] = []
    image_digests: list[str] = []
    for subject in subjects:
        for key in ("manifest_digest", "capsule_digest"):
            digest = _normalize_digest(subject.get(key))
            if digest and digest not in manifest_digests:
                manifest_digests.append(digest)
        raw_images = subject.get("image_digests")
        if isinstance(raw_images, dict):
            raw_images = list(raw_images.values())
        if isinstance(raw_images, list):
            for raw in raw_images:
                digest = _normalize_digest(raw)
                if digest and digest not in image_digests:
                    image_digests.append(digest)
    manifest_digests.sort(); image_digests.sort()

    components_cfg = rs_cfg.get("components", {}) if isinstance(rs_cfg.get("components", {}), dict) else {}
    component_names = ("runtime_pack", "policy_bundle", "infra_manifest", "sbom", "provenance")
    component_digests: dict[str, str | None] = {}
    component_files: dict[str, list[dict[str, str]]] = {}
    for name in component_names:
        digest, entries, component_issues = _digest_component_files(target_root, components_cfg.get(name))
        component_digests[name] = digest
        component_files[name] = entries
        issues.extend(f"{name}: {problem}" for problem in component_issues)

    identity = {
        "schema": "konnaxiondiag.release-set.identity.v1",
        "source_commit_sha": git.get("source_commit_sha"),
        "source_tree_digest": git.get("source_tree_digest"),
        "capsule_digest": manifest_digests[0] if len(manifest_digests) == 1 else None,
        "capsule_digests": manifest_digests,
        "image_digests": image_digests,
        "runtime_pack_digest": component_digests["runtime_pack"],
        "policy_bundle_digest": component_digests["policy_bundle"],
        "infra_manifest_digest": component_digests["infra_manifest"],
        "sbom_digest": component_digests["sbom"],
        "provenance_digest": component_digests["provenance"],
    }

    present = {
        "source": bool(identity["source_commit_sha"] and identity["source_tree_digest"]),
        "capsule": bool(identity["capsule_digest"] or identity["capsule_digests"]),
        "images": bool(identity["image_digests"]),
        "runtime_pack": bool(identity["runtime_pack_digest"]),
        "policy_bundle": bool(identity["policy_bundle_digest"]),
        "infra_manifest": bool(identity["infra_manifest_digest"]),
        "sbom": bool(identity["sbom_digest"]),
        "provenance": bool(identity["provenance_digest"]),
    }
    for component in required_components:
        if component not in present:
            issues.append(f"unknown required ReleaseSet component: {component}")
        elif not present[component]:
            issues.append(f"required ReleaseSet component is missing: {component}")

    evidence_results = [r for r in results if r.get("level_id") != "S14"]
    release_set = {
        "schema": RELEASE_SET_SCHEMA,
        "assurance_engine_version": VERSION,
        "identity": identity,
        "release_set_digest": _sha256_json(identity),
        "qualification_policy_digest": _effective_policy_digest(cfg),
        "security_contract_registry_digest": _registry_digest(cfg),
        "security_evidence_set_digest": _sha256_json(evidence_results),
        "component_files": component_files,
        "capsule_subjects": subjects,
        "source": git,
        "required_components": required_components,
        "complete": not issues,
        "problems": list(issues),
    }
    return release_set, issues


def validate_release_set(value: dict[str, Any], *, require_complete: bool = True) -> tuple[bool, dict[str, Any]]:
    problems: list[str] = []
    if not isinstance(value, dict) or value.get("schema") != RELEASE_SET_SCHEMA:
        return False, {"problems": ["invalid ReleaseSet schema"]}
    identity = value.get("identity") if isinstance(value.get("identity"), dict) else None
    if identity is None:
        return False, {"problems": ["ReleaseSet identity missing"]}
    expected = _sha256_json(identity)
    if value.get("release_set_digest") != expected:
        problems.append("release_set_digest does not match canonical identity")
    if require_complete and value.get("complete") is not True:
        problems.append("ReleaseSet is incomplete")
    return not problems, {"problems": problems, "computed_release_set_digest": expected}
