from __future__ import annotations
import re
from pathlib import Path
from profiles.security.support.scanner import iter_files, bounded_text_status
from diagcore.commands import run_command

PATTERNS=[
 ("private-key",re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
 ("github-token",re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b")),
 ("github-fine-token",re.compile(r"\bgithub_pat_[A-Za-z0-9_]{30,}\b")),
 ("aws-access-key",re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
 ("secret-assignment",re.compile(r"(?i)\b(?:DJANGO_SECRET_KEY|POSTGRES_PASSWORD|DATABASE_URL|api[_-]?key|access[_-]?token)\s*[:=]\s*['\"]?[A-Za-z0-9_./+=:@%-]{16,}")),
]


def run(cfg,report):
    root=Path(cfg["_target_root"]); sec=cfg.get("repo_security",{}); scan=cfg.get("scan",{})
    sensitive=set(sec.get("sensitive_names",[])); max_bytes=int(scan.get("max_file_bytes",1048576))
    scan_untracked=bool(sec.get("scan_untracked",True))

    tracked=set()
    gr=run_command(["git","ls-files","-z"],cwd=root,timeout_seconds=20,capture_limit_kb=4096)
    git_inventory_ok=gr["exit_code"]==0 and not gr.get("timed_out",False)
    if git_inventory_ok:
        tracked=set(x for x in gr["stdout_tail"].split("\x00") if x)

    hits=[]; sensitive_paths=[]; archives=[]; scanned=0; content_scanned=0
    scan_stats={}
    skipped={"too_large":[],"binary":[],"read_error":[]}
    for p,rel in iter_files(root,cfg,stats=scan_stats):
        scanned+=1
        is_tracked=rel in tracked
        name=p.name
        if name in sensitive or name.endswith(".pem") or name.endswith(".key"):
            sensitive_paths.append({"path":rel,"tracked":is_tracked})
        lower=rel.lower()
        if any(lower.endswith(ext.lower()) for ext in sec.get("archive_extensions",[])):
            archives.append({"path":rel,"tracked":is_tracked})

        if git_inventory_ok and not is_tracked and not scan_untracked:
            continue

        text,reason=bounded_text_status(p,max_bytes)
        if text is None:
            if reason in skipped:
                skipped[reason].append({"path":rel,"tracked":is_tracked})
            continue
        content_scanned+=1
        for pid,rx in PATTERNS:
            m=rx.search(text)
            if m:
                line_no=text.count("\n",0,m.start())+1
                if pid=="secret-assignment":
                    lines=text.splitlines()
                    line_text=lines[line_no-1].lower() if 0 < line_no <= len(lines) else ""
                    placeholders=[str(x).lower() for x in sec.get("placeholder_tokens",[])]
                    if any(token in line_text for token in placeholders):
                        continue
                hits.append({"pattern":pid,"path":rel,"line":line_no,"tracked":is_tracked})
                break

    tracked_sensitive=[x for x in sensitive_paths if x["tracked"]]
    tracked_hits=[x for x in hits if x["tracked"]]
    report.add("repo.secrets.tracked_patterns","FAIL" if tracked_hits else "PASS","secrets",
               "Tracked files contain potential secret material." if tracked_hits else "No conservative secret pattern matched in tracked files.",
               evidence=tracked_hits[:100] if tracked_hits else None,
               recommendation="Rotate genuine credentials immediately and remove them from Git history." if tracked_hits else None,
               release_blocker=bool(tracked_hits))
    report.add("repo.secrets.sensitive_files","FAIL" if tracked_sensitive else ("WARN" if sensitive_paths else "PASS"),"secrets",
               "Sensitive filename review completed.",evidence=sensitive_paths[:100] if sensitive_paths else None,
               recommendation="Production env/private-key files must not be tracked; keep machine-local secrets outside releases." if sensitive_paths else None)
    tracked_archives=[x for x in archives if x["tracked"]]
    report.add("repo.deploy_archives.tracked","WARN" if tracked_archives else "PASS","artifact_hygiene",
               "Tracked deployment/archive files were found." if tracked_archives else "No tracked deployment archives were found.",
               evidence=tracked_archives[:100] if tracked_archives else None,
               recommendation="Prefer versioned Git source/archive creation outside the repository." if tracked_archives else None)
    untracked_hits=[x for x in hits if not x["tracked"]]
    report.add("repo.secrets.untracked_patterns","WARN" if untracked_hits else "PASS","secrets",
               "Potential secret material exists in untracked/local files." if untracked_hits else "No potential secret pattern found in scanned untracked/local files.",
               evidence=untracked_hits[:100] if untracked_hits else None,
               recommendation="Ensure untracked secrets are excluded from deployment archives and logs." if untracked_hits else None)

    tracked_oversized=[x for x in skipped["too_large"] if x["tracked"]]
    untracked_oversized=[x for x in skipped["too_large"] if not x["tracked"]]
    read_errors=skipped["read_error"]
    hard_incomplete=(
        not git_inventory_ok
        or bool(scan_stats.get("limit_reached"))
        or bool(tracked_oversized)
        or bool(read_errors)
    )
    soft_incomplete=bool(untracked_oversized) and scan_untracked
    coverage_verdict="PARTIAL" if hard_incomplete else ("WARN" if soft_incomplete else "PASS")
    coverage_evidence={
        "git_inventory_ok":git_inventory_ok,
        "git_error":None if git_inventory_ok else {"exit_code":gr.get("exit_code"),"timed_out":gr.get("timed_out")},
        "max_files_reached":bool(scan_stats.get("limit_reached")),
        "oversized_tracked":tracked_oversized[:100],
        "oversized_untracked":untracked_oversized[:100],
        "binary_skipped_count":len(skipped["binary"]),
        "read_errors":read_errors[:100],
    }
    report.add(
        "repo.scan.coverage",
        coverage_verdict,
        "secrets",
        "Repository secret-scan coverage is incomplete."
        if hard_incomplete
        else ("Some untracked oversized files were not content-scanned." if soft_incomplete else "Repository secret-scan coverage completed within configured bounds."),
        evidence=coverage_evidence,
        recommendation=(
            "Restore Git metadata/read access or raise reviewed scan bounds before relying on this result."
            if coverage_verdict!="PASS" else None
        ),
        release_blocker=coverage_verdict=="PARTIAL",
    )
    report.metrics.update({
        "files_seen":scanned,
        "files_content_scanned":content_scanned,
        "tracked_files":len(tracked),
        "potential_hits":len(hits),
        "sensitive_paths":len(sensitive_paths),
        "oversized_files":len(skipped["too_large"]),
        "binary_files_skipped":len(skipped["binary"]),
        "read_errors":len(read_errors),
        "scan_limit_reached":bool(scan_stats.get("limit_reached")),
    })
