from __future__ import annotations
import json, re, time
from pathlib import Path
from profiles.security.support.remote import run_script, RemoteBlocked
from diagcore.utils import read_json
from diagcore.assurance import RESTORE_DRILL_PURPOSE, resolve_trusted_public_keys, temporal_attestation_check, verify_signed_attestation, parse_time
from assurance.attestation import ATTESTATION_SCHEMA, validate_universal_attestation
from assurance.release_set import build_release_set

def safe_path(p):
    return bool(re.fullmatch(r'/[A-Za-z0-9._/@%+=:,~\-]+(?:/[A-Za-z0-9._ @%+=:,~\-]+)*',p))

def shq(p):
    return "'" + p.replace("'","'\"'\"'") + "'"

def run(cfg,report):
    paths=[str(x) for x in cfg.get("remote",{}).get("backup_paths",[])]
    invalid=[p for p in paths if not safe_path(p)]
    if invalid:
        report.add("recovery.backup_paths.valid","CONFIG_ERROR","recovery","Configured backup paths contain unsafe characters.",evidence=invalid)
        return
    if not paths:
        report.add("recovery.backups.configured","BLOCKED","recovery","No remote backup_paths are configured.",
                   recommendation="Configure at least one off-release backup directory before release.")
    else:
        blocks=[]
        for p in paths:
            blocks.append(f'''
p={shq(p)}
if [ -e "$p" ]; then
  latest=$(find "$p" -type f -printf '%T@|%s|%p\\n' 2>/dev/null | sort -nr | head -1)
  if [ -n "$latest" ]; then echo "FOUND|$p|$latest"; else echo "EMPTY|$p"; fi
else
  echo "MISSING|$p"
fi
''')
        script="set +e\n"+"\n".join(blocks)
        try:
            r=run_script(cfg,script,timeout_seconds=90)
        except RemoteBlocked as e:
            report.add("recovery.backups.remote","BLOCKED","recovery",str(e))
            r=None
        if r is not None:
            if r["exit_code"]!=0:
                report.add("recovery.backups.remote","INFRA_ERROR","recovery","Backup metadata collection failed.",evidence=r)
            else:
                now=time.time(); max_age=float(cfg.get("remote",{}).get("backup_max_age_hours",30))*3600
                rows=[]; stale=[]; bad=[]
                for line in r["stdout_tail"].splitlines():
                    if line.startswith(("MISSING|","EMPTY|")):
                        bad.append(line); continue
                    if line.startswith("FOUND|"):
                        parts=line.split("|",4)
                        if len(parts)>=5:
                            try:
                                ts=float(parts[2]); age=round((now-ts)/3600,2)
                            except Exception:
                                age=None
                            row={"base":parts[1],"mtime_epoch":parts[2],"size":parts[3],"path":parts[4],"age_hours":age}
                            rows.append(row)
                            if age is None or age>max_age/3600:
                                stale.append(row)
                verdict="FAIL" if bad or stale else "PASS"
                report.add("recovery.backups.recent",verdict,"recovery",
                           "Backup path is missing/empty or latest backup is stale." if verdict=="FAIL" else "Recent backup evidence exists.",
                           evidence={"latest":rows,"problems":bad,"stale":stale},
                           recommendation="Create a fresh backup and copy it off-server before release." if verdict=="FAIL" else None)
    rel=cfg.get("recovery",{}).get("restore_attestation_file","securitydiag/attestations/restore-drill.local.json")
    att_path=(Path(cfg["_target_root"])/rel).resolve(strict=False)
    target=Path(cfg["_target_root"]).resolve(strict=False)
    if not att_path.is_relative_to(target):
        report.add("recovery.restore_attestation","CONFIG_ERROR","recovery","Restore attestation path escapes repository.")
        return
    if not att_path.exists():
        verdict="BLOCKED" if cfg.get("recovery",{}).get("require_restore_drill_for_release",True) else "WARN"
        report.add("recovery.restore_attestation",verdict,"recovery","Isolated restore-drill attestation is missing.",path=att_path,
                   recommendation="Perform a real isolated restore and emit a signed universal recovery attestation bound to the current ReleaseSet.")
        return
    try:
        a=read_json(att_path)
    except Exception as e:
        report.add("recovery.restore_attestation","CONFIG_ERROR","recovery","Restore attestation is invalid JSON.",evidence={"error":str(e)})
        return

    recovery_cfg=cfg.get("recovery",{}) if isinstance(cfg.get("recovery",{}),dict) else {}
    run_root=Path(cfg.get("_run_root",""))
    prior=[]
    level_root=run_root/"levels"
    if level_root.is_dir():
        for rp in sorted(level_root.glob("*/result.json")):
            try:
                item=read_json(rp)
                if item.get("level_id")!="S13":prior.append(item)
            except Exception:
                pass
    release_set,release_set_issues=build_release_set(target_root=target,results=prior,cfg=cfg)
    expected_release_set_digest=str(release_set.get("release_set_digest","")).strip()

    sig_rel=str(recovery_cfg.get("restore_attestation_signature_file","") or "").strip()
    sig_path=(target/sig_rel).resolve(strict=False) if sig_rel else att_path.with_suffix(att_path.suffix+".sig")
    if not sig_path.is_relative_to(target):
        report.add("recovery.restore_attestation.signature","CONFIG_ERROR","recovery","Restore attestation signature path escapes repository.")
        return
    try:envelope=read_json(sig_path) if sig_path.is_file() else None
    except Exception:envelope=None
    signature_required=bool(recovery_cfg.get("restore_attestation_signature_required",True))
    keys=resolve_trusted_public_keys(recovery_cfg.get("restore_attestation_trusted_public_keys"),base=target)
    max_age_hours=float(recovery_cfg.get("restore_attestation_max_age_hours",720) or 720)
    max_age_seconds=int(max_age_hours*3600)
    metadata_problems=[]

    if a.get("schema")==ATTESTATION_SCHEMA:
        expected_issuers=recovery_cfg.get("restore_attestation_trusted_issuers",[])
        if isinstance(expected_issuers,str):expected_issuers=[expected_issuers]
        universal_ok,universal_detail=validate_universal_attestation(
            a,envelope,public_keys=keys,expected_release_set_digest=expected_release_set_digest,
            expected_evidence_type="recovery.restore-drill",expected_issuers=expected_issuers,
            expected_policy_digest=str(recovery_cfg.get("restore_attestation_expected_policy_digest","") or "").strip() or None,
            max_age_seconds=max_age_seconds,signature_required=signature_required,
        )
        if not universal_ok:metadata_problems.extend(universal_detail.get("problems",[]))
        statement=a.get("statement") if isinstance(a.get("statement"),dict) else {}
        subject=a.get("subject") if isinstance(a.get("subject"),dict) else {}
        required=["isolated_target","database_restored","application_booted","critical_data_verified","offsite_copy_verified"]
        missing=[k for k in required if statement.get(k) is not True]
        operator=str(statement.get("operator","")).strip()
        if not operator:metadata_problems.append("statement.operator missing")
        started=parse_time(statement.get("started_at"));completed=parse_time(statement.get("completed_at"))
        if started is None:metadata_problems.append("statement.started_at missing or invalid")
        if completed is None:metadata_problems.append("statement.completed_at missing or invalid")
        if started and completed and completed<=started:metadata_problems.append("restore drill completed_at must be after started_at")
        required_subject_fields=recovery_cfg.get("required_subject_fields",[
            "release_set_digest","backup_digest","restore_target_identity","environment_id",
            "trust_epoch_before","trust_epoch_after","revocation_epoch","audit_anchor"
        ])
        if not isinstance(required_subject_fields,list):required_subject_fields=[]
        missing_subject=[str(k) for k in required_subject_fields if subject.get(str(k)) in (None,"",[],{})]
        if missing_subject:metadata_problems.append("missing subject fields: "+", ".join(missing_subject))
        ok=not missing and not metadata_problems
        report.add("recovery.restore_attestation","FAIL" if not ok else "PASS","recovery",
                   "Restore-drill attestation is incomplete, stale, release-unbound, or untrusted." if not ok else "Restore drill is signed, fresh, exact-ReleaseSet-bound, and records recovery/trust epochs.",
                   evidence={"issuer":a.get("issuer"),"operator":operator,"subject":subject,"missing_true_fields":missing,"metadata_problems":metadata_problems,"release_set_digest":expected_release_set_digest,"release_set_problems":release_set_issues,"attestation_verification":universal_detail},
                   recommendation="Produce a fresh konnaxiondiag.attestation.v1 recovery.restore-drill attestation for this exact ReleaseSet and trusted recovery operator." if not ok else None,
                   release_blocker=not ok)
        return

    if not bool(recovery_cfg.get("allow_legacy_restore_attestation",False)):
        report.add("recovery.restore_attestation","FAIL","recovery","Legacy restore attestation rejected; universal konnaxiondiag.attestation.v1 is required.",
                   recommendation="Migrate the restore drill to the universal recovery.restore-drill attestation envelope.",release_blocker=True)
        return

    # Migration-only compatibility path for v4.1 evidence.
    required=["isolated_target","database_restored","application_booted","critical_data_verified","offsite_copy_verified"]
    missing=[k for k in required if a.get(k) is not True]
    if not str(a.get("operator","")).strip():metadata_problems.append("operator missing")
    subject=a.get("subject") if isinstance(a.get("subject"),dict) else {}
    time_ok,time_detail=temporal_attestation_check(a,issued_field="performed_at",expires_field="expires_at",max_age_seconds=max_age_seconds)
    if not time_ok:metadata_problems.extend(time_detail.get("problems",[]))
    sig_ok,sig_detail=verify_signed_attestation(a,envelope,purpose=RESTORE_DRILL_PURPOSE,public_keys=keys,signature_required=signature_required)
    if not sig_ok:metadata_problems.append("restore attestation signature is not trusted/valid")
    ok=not missing and not metadata_problems
    report.add("recovery.restore_attestation","FAIL" if not ok else "PASS","recovery",
               "Legacy restore-drill attestation is incomplete, stale, or untrusted." if not ok else "Legacy restore-drill attestation accepted by migration policy.",
               evidence={"subject":subject,"missing_true_fields":missing,"metadata_problems":metadata_problems,"freshness":time_detail,"signature_verification":sig_detail},release_blocker=not ok)

