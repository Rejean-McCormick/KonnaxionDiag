from __future__ import annotations
from profiles.security.support.remote import run_script, RemoteBlocked

SCRIPT = r'''
set +e
echo "HOSTNAME=$(hostname -f 2>/dev/null || hostname)"
echo "KERNEL=$(uname -srmo 2>/dev/null)"
if [ -r /etc/os-release ]; then
  . /etc/os-release
  echo "OS_ID=${ID:-unknown}"
  echo "OS_VERSION=${VERSION_ID:-unknown}"
fi
echo "UPTIME_SECONDS=$(cut -d. -f1 /proc/uptime 2>/dev/null)"
if command -v timedatectl >/dev/null 2>&1; then
  echo "NTP_SYNC=$(timedatectl show -p NTPSynchronized --value 2>/dev/null)"
fi
if command -v apt-get >/dev/null 2>&1; then
  echo "APT_UPDATES=$(apt-get -s upgrade 2>/dev/null | grep -c '^Inst ')"
fi
echo "CURRENT_USER=$(id -un 2>/dev/null)"
echo "UID=$(id -u 2>/dev/null)"
if command -v systemctl >/dev/null 2>&1; then
  echo "FAIL2BAN_ACTIVE=$(systemctl is-active fail2ban 2>/dev/null)"
  echo "APT_DAILY_UPGRADE_ENABLED=$(systemctl is-enabled apt-daily-upgrade.timer 2>/dev/null)"
fi
if command -v dpkg-query >/dev/null 2>&1; then
  echo "UNATTENDED_INSTALLED=$(dpkg-query -W -f='${Status}' unattended-upgrades 2>/dev/null)"
fi
'''

def kv(text):
    out={}
    for line in text.splitlines():
        if "=" in line:
            k,v=line.split("=",1); out[k.strip()]=v.strip()
    return out

def run(cfg,report):
    try:
        r=run_script(cfg,SCRIPT,timeout_seconds=90)
    except RemoteBlocked as e:
        report.add("host.remote.available","BLOCKED","host",str(e))
        return
    if r["timed_out"] or r["exit_code"]!=0:
        report.add("host.remote.available","INFRA_ERROR","host","Remote host baseline command failed.",evidence=r)
        return
    d=kv(r["stdout_tail"])
    report.add("host.remote.available","PASS","host","Remote host is reachable through configured SSH.",
               evidence={"hostname":d.get("HOSTNAME"),"user":d.get("CURRENT_USER")})
    report.add("host.os.linux","PASS" if d.get("OS_ID") else "WARN","host",
               "Linux OS identity collected." if d.get("OS_ID") else "Could not read /etc/os-release.",
               evidence={"id":d.get("OS_ID"),"version":d.get("OS_VERSION"),"kernel":d.get("KERNEL")})
    ntp=d.get("NTP_SYNC","").lower()
    report.add("host.time.synchronized","PASS" if ntp=="yes" else "WARN","host",
               "System clock reports NTP synchronization." if ntp=="yes" else "NTP synchronization was not confirmed.",
               evidence={"NTPSynchronized":d.get("NTP_SYNC")})
    try:
        updates=int(d.get("APT_UPDATES","0") or 0)
    except ValueError:
        updates=0
    report.add("host.os.pending_updates","PASS" if updates==0 else "WARN","patching",
               "No pending APT upgrades were reported." if updates==0 else f"{updates} pending APT upgrade(s) were reported.",
               evidence={"pending_updates":updates},
               recommendation=None if updates==0 else "Apply and reboot for security updates as appropriate before public release.")
    fail2ban=d.get("FAIL2BAN_ACTIVE","")
    req_f2b=cfg.get("remote",{}).get("require_fail2ban",True)
    report.add("host.fail2ban.active","PASS" if fail2ban=="active" else ("FAIL" if req_f2b else "WARN"),"host_security",
               "Fail2Ban is active." if fail2ban=="active" else f"Fail2Ban active state is {fail2ban or 'unknown'}.",
               recommendation=None if fail2ban=="active" else "Enable Fail2Ban before public exposure.")
    unattended="install ok installed" in d.get("UNATTENDED_INSTALLED","").lower()
    timer=d.get("APT_DAILY_UPGRADE_ENABLED","")=="enabled"
    req_ua=cfg.get("remote",{}).get("require_unattended_upgrades",True)
    ua_ok=unattended and timer
    report.add("host.security_updates.automatic","PASS" if ua_ok else ("FAIL" if req_ua else "WARN"),"patching",
               "unattended-upgrades is installed and apt-daily-upgrade.timer is enabled." if ua_ok else "Automatic security-update evidence is incomplete.",
               evidence={"package_installed":unattended,"apt_daily_upgrade_timer":d.get("APT_DAILY_UPGRADE_ENABLED")},
               recommendation=None if ua_ok else "Install unattended-upgrades and enable the APT daily upgrade timer.")
    report.metrics.update(d)
