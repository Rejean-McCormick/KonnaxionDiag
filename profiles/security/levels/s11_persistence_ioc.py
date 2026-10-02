from __future__ import annotations
import re
from profiles.security.support.remote import run_script, RemoteBlocked

BASE = r'''
set +e
echo "__USERS__"
cut -d: -f1,3,7 /etc/passwd 2>/dev/null
echo "__TMP_EXEC__"
find /tmp /dev/shm -xdev -maxdepth 3 -type f -perm /111 -printf '%p\n' 2>/dev/null | head -200
echo "__CRON_FILES__"
find /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly /var/spool/cron -maxdepth 3 -type f -printf '%p\n' 2>/dev/null | head -300
echo "__SYSTEMD_CUSTOM__"
find /etc/systemd/system -maxdepth 3 -type f -printf '%p\n' 2>/dev/null | head -300
echo "__SUDO_GROUP__"
getent group sudo 2>/dev/null || getent group wheel 2>/dev/null || true
echo "__SUDOERS_FILES__"
find /etc/sudoers.d -maxdepth 1 -type f -printf '%f\n' 2>/dev/null | sort | head -100
'''

PRIV = r'''
set +e
PATTERN=__PATTERN__
echo "__IOC_FILES__"
grep -RIlE "$PATTERN" /etc/cron.d /etc/cron.daily /etc/cron.hourly /var/spool/cron /etc/systemd/system /etc/sudoers /etc/sudoers.d /tmp /dev/shm 2>/dev/null | head -200
echo "__ROOT_CRON_COUNT__"
crontab -l -u root 2>/dev/null | grep -Ev '^[[:space:]]*(#|$)' | wc -l
'''

def run(cfg,report):
    try:
        r=run_script(cfg,BASE,timeout_seconds=90)
    except RemoteBlocked as e:
        report.add("incident.persistence.baseline","BLOCKED","incident_recovery",str(e))
        return
    if r["exit_code"]!=0:
        report.add("incident.persistence.baseline","INFRA_ERROR","incident_recovery","Persistence baseline collection failed.",evidence=r)
        return
    out=r["stdout_tail"]
    usernames=set(cfg.get("remote",{}).get("iocs",{}).get("usernames",[]))
    found_users=[]
    users=out.split("__USERS__",1)[-1].split("__TMP_EXEC__",1)[0]
    for line in users.splitlines():
        name=line.split(":",1)[0]
        if name in usernames:
            found_users.append(line)
    report.add("incident.ioc.users","FAIL" if found_users else "PASS","incident_recovery",
               "Known compromise username exists." if found_users else "No configured compromise username found.",
               evidence=found_users or None)
    tmp=out.split("__TMP_EXEC__",1)[-1].split("__CRON_FILES__",1)[0].strip().splitlines()
    exact=set(cfg.get("remote",{}).get("iocs",{}).get("exact_paths",[]))
    exact_hits=[x for x in tmp if x in exact]
    report.add("incident.ioc.exact_paths","FAIL" if exact_hits else "PASS","incident_recovery",
               "Known compromise path exists." if exact_hits else "No configured exact compromise path found.",
               evidence=exact_hits or None)
    report.add("incident.tmp.executables","WARN" if tmp else "PASS","incident_recovery",
               "Executable files exist under /tmp or /dev/shm and require review." if tmp else "No executable file was found under /tmp or /dev/shm in bounded scan.",
               evidence=tmp[:200] if tmp else None)
    tokens=[str(x) for x in cfg.get("remote",{}).get("iocs",{}).get("tokens",[])]
    pattern="|".join(re.escape(x) for x in tokens) if tokens else "a^"
    shell_pattern="'" + pattern.replace("'","'\\\"'\\\"'") + "'"
    priv_script=PRIV.replace("__PATTERN__",shell_pattern)
    sudo_group=out.split("__SUDO_GROUP__",1)[-1].split("__SUDOERS_FILES__",1)[0].strip().splitlines()
    members=[]
    if sudo_group:
        parts=sudo_group[0].split(":")
        if len(parts)>=4 and parts[3].strip():
            members=[x.strip() for x in parts[3].split(",") if x.strip()]
    allowed_sudo=set(str(x) for x in cfg.get("remote",{}).get("allowed_sudo_users",[]))
    unexpected_sudo=[x for x in members if allowed_sudo and x not in allowed_sudo]
    if allowed_sudo:
        report.add("incident.sudo_group.allowlist","FAIL" if unexpected_sudo else "PASS","incident_recovery",
                   "Unexpected sudo-group members detected." if unexpected_sudo else "Sudo-group membership matches the configured allowlist.",
                   evidence={"members":members,"allowed":sorted(allowed_sudo),"unexpected":unexpected_sudo})
    else:
        report.add("incident.sudo_group.allowlist","WARN" if members else "PASS","incident_recovery",
                   "Sudo-group members exist but no allowlist is configured." if members else "No sudo-group members were reported.",
                   evidence={"members":members},
                   recommendation="Configure remote.allowed_sudo_users after establishing the fresh VPS admin model." if members else None)
    sudoers_files=out.split("__SUDOERS_FILES__",1)[-1].strip().splitlines()
    report.add("incident.sudoers.inventory","PASS","incident_recovery","sudoers.d inventory collected without reading secret material.",
               evidence={"files":sudoers_files[:100]})
    try:
        pr=run_script(cfg,priv_script,privileged=True,timeout_seconds=90)
    except RemoteBlocked as e:
        report.add("incident.privileged.persistence_scan","BLOCKED","incident_recovery",str(e))
        return
    if pr["exit_code"]!=0:
        report.add("incident.privileged.persistence_scan","INFRA_ERROR","incident_recovery","Privileged persistence scan failed.",evidence=pr)
        return
    ioc=pr["stdout_tail"].split("__IOC_FILES__",1)[-1].split("__ROOT_CRON_COUNT__",1)[0].strip().splitlines()
    report.add("incident.ioc.persistence_files","FAIL" if ioc else "PASS","incident_recovery",
               "Known incident IOC matched persistence or temporary files." if ioc else "No known incident IOC matched privileged persistence paths.",
               evidence=ioc[:200] if ioc else None)
    rootcron=pr["stdout_tail"].split("__ROOT_CRON_COUNT__",1)[-1].strip().splitlines()
    try:
        root_count=int(rootcron[0].strip()) if rootcron else 0
    except ValueError:
        root_count=0
    report.add("incident.root_cron.review","WARN" if root_count else "PASS","incident_recovery",
               "Root crontab contains entries and requires explicit review." if root_count else "Root crontab is empty or absent.",
               evidence={"entry_count":root_count})
