from __future__ import annotations
import re
from profiles.security.support.remote import run_script, RemoteBlocked

def safe_path(p):
    return bool(re.fullmatch(r'/[A-Za-z0-9._/@%+=:,~\-]+(?:/[A-Za-z0-9._ @%+=:,~\-]+)*',p))

def shq(p):
    return "'" + p.replace("'","'\"'\"'") + "'"

def run(cfg,report):
    paths=[str(x) for x in cfg.get("remote",{}).get("secret_paths",[])]
    invalid=[p for p in paths if not safe_path(p)]
    if invalid:
        report.add("secrets.paths.valid","CONFIG_ERROR","secrets","Configured secret paths contain unsafe characters.",evidence=invalid)
        return

    # SSH material belongs to the configured remote user and must be inspected
    # without sudo so $HOME resolves to that user's home (for example kx-admin).
    ssh_script=r'''
set +e
echo "__SSH_DIR__"
stat -Lc '%a|%U|%G|%n' "$HOME/.ssh" "$HOME/.ssh/authorized_keys" 2>/dev/null || true
echo "__AUTHORIZED_KEY_FINGERPRINTS__"
if command -v ssh-keygen >/dev/null 2>&1 && [ -r "$HOME/.ssh/authorized_keys" ]; then
  ssh-keygen -lf "$HOME/.ssh/authorized_keys" -E sha256 2>/dev/null | awk '{print $2}'
fi
'''
    try:
        ssh_result=run_script(cfg,ssh_script,timeout_seconds=60)
    except RemoteBlocked as e:
        report.add("secrets.remote.permissions","BLOCKED","secrets",str(e))
        return
    if ssh_result["exit_code"]!=0:
        report.add("secrets.remote.permissions","INFRA_ERROR","secrets","Could not collect remote SSH permission metadata.",evidence=ssh_result)
        return

    out=ssh_result["stdout_tail"]
    sshsec=out.split("__SSH_DIR__",1)[-1].split("__AUTHORIZED_KEY_FINGERPRINTS__",1)[0].strip().splitlines()
    badssh=[]
    for line in sshsec:
        p=line.split("|")
        if len(p)>=4:
            mode=p[0]
            if p[3].endswith("/.ssh") and mode not in {"700"}:
                badssh.append(line)
            if p[3].endswith("authorized_keys") and mode not in {"600","640"}:
                badssh.append(line)
    report.add("secrets.ssh_permissions","FAIL" if badssh else "PASS","ssh",
               "SSH directory/key-list permissions are too broad." if badssh else "SSH directory/key-list permissions are appropriately restrictive.",
               evidence=badssh or sshsec)

    fps=out.split("__AUTHORIZED_KEY_FINGERPRINTS__",1)[-1].strip().splitlines()
    fps=[x.strip() for x in fps if x.strip().startswith("SHA256:")]
    allowed=set(str(x) for x in cfg.get("remote",{}).get("allowed_ssh_key_fingerprints",[]) if "REPLACE_" not in str(x))
    unexpected=[x for x in fps if allowed and x not in allowed]
    missing_allowed=[x for x in allowed if x not in fps]
    if allowed:
        report.add("secrets.authorized_keys.allowlist","FAIL" if unexpected or missing_allowed else "PASS","ssh",
                   "Authorized SSH key fingerprints differ from the configured allowlist." if unexpected or missing_allowed else "Authorized SSH key fingerprints match the configured allowlist.",
                   evidence={"observed":fps,"unexpected":unexpected,"missing_allowed":missing_allowed})
    else:
        report.add("secrets.authorized_keys.allowlist","WARN" if fps else "FAIL","ssh",
                   "Authorized SSH keys exist but no fingerprint allowlist is configured." if fps else "No authorized SSH key fingerprint was collected.",
                   evidence={"observed":fps},
                   recommendation="Record the expected SHA256 public-key fingerprint(s) in remote.allowed_ssh_key_fingerprints.")

    if not paths:
        report.add("secrets.production_paths","BLOCKED" if cfg.get("phase")=="production" else "SKIP","secrets",
                   "No production secret_paths are configured.",
                   recommendation="Configure remote.secret_paths before the production release campaign.")
        return

    # Production secret paths are intentionally outside the deployment user's
    # readable tree. Inspect only metadata through the configured noninteractive
    # privileged audit path; do not read secret contents.
    quoted=" ".join(shq(p) for p in paths)
    secret_script=f'''
set +e
echo "__SECRETS__"
for p in {quoted}; do
  if [ -e "$p" ]; then
    stat -Lc '%a|%U|%G|%n' "$p" 2>/dev/null || echo "STAT_ERROR|$p"
  else
    echo "MISSING|$p"
  fi
done
'''
    try:
        secret_result=run_script(cfg,secret_script,privileged=True,timeout_seconds=60)
    except RemoteBlocked as e:
        report.add("secrets.production_paths","BLOCKED","secrets",str(e),
                   recommendation="Configure remote.sudo_mode=noninteractive for privileged metadata-only secret-path checks.")
        return
    if secret_result["exit_code"]!=0:
        report.add("secrets.production_paths","INFRA_ERROR","secrets","Could not collect privileged production secret permission metadata.",evidence=secret_result)
        return

    sec=secret_result["stdout_tail"].split("__SECRETS__",1)[-1].strip().splitlines()
    missing=[x for x in sec if x.startswith("MISSING|")]
    stat_errors=[x for x in sec if x.startswith("STAT_ERROR|")]
    broad=[]
    for line in sec:
        if line.startswith(("MISSING|","STAT_ERROR|")):
            continue
        p=line.split("|")
        if len(p)>=4 and p[0].isdigit():
            mode=p[0]
            if len(mode)>=3 and (int(mode[-2])>0 or int(mode[-1])>0):
                broad.append(line)

    if stat_errors:
        report.add("secrets.production_paths","INFRA_ERROR","secrets","Some configured secret files exist but their permission metadata could not be collected.",
                   evidence={"stat_errors":stat_errors,"missing":missing,"checked":len(paths)})
    else:
        report.add("secrets.production_paths","FAIL" if broad else ("BLOCKED" if missing else "PASS"),"secrets",
                   "Secret file permissions are too broad." if broad else ("Configured secret files are missing." if missing else "Configured secret files are owner-only."),
                   evidence={"broad":broad,"missing":missing,"checked":len(paths)},
                   recommendation="Use owner-only permissions such as 600 for production secret files." if broad else None)
