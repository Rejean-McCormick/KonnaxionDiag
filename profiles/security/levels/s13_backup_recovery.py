from __future__ import annotations
import json, re, time
from pathlib import Path
from profiles.security.support.remote import run_script, RemoteBlocked
from diagcore.utils import read_json

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
                   recommendation="Copy the example attestation, perform a real isolated restore, then record only the non-secret result.")
        return
    try:
        a=read_json(att_path)
    except Exception as e:
        report.add("recovery.restore_attestation","CONFIG_ERROR","recovery","Restore attestation is invalid JSON.",evidence={"error":str(e)})
        return
    required=["isolated_target","database_restored","application_booted","critical_data_verified","offsite_copy_verified"]
    missing=[k for k in required if a.get(k) is not True]
    report.add("recovery.restore_attestation","FAIL" if missing else "PASS","recovery",
               "Restore-drill attestation is incomplete." if missing else "Restore-drill attestation records an isolated successful recovery exercise.",
               evidence={"performed_at":a.get("performed_at"),"operator":a.get("operator"),"missing_true_fields":missing},
               recommendation="Complete the isolated restore drill before release." if missing else None)
