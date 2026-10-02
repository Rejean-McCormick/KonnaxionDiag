from __future__ import annotations
import re
from profiles.security.support.remote import run_script, RemoteBlocked

BASE = r'''
set +e
echo "__GROUPS__"
id
echo "__DOCKER_SOCKET__"
stat -Lc '%a|%U|%G|%n' /var/run/docker.sock 2>/dev/null || true
echo "__DOCKER_PRESENT__"
command -v docker 2>/dev/null || true
'''

PRIV = r'''
set +e
echo "__INFO__"
docker info --format 'security={{json .SecurityOptions}}' 2>/dev/null || true
echo "__PS__"
docker ps --format '{{.ID}}|{{.Names}}|{{.Image}}|{{.Ports}}' 2>/dev/null || true
echo "__IMAGES__"
docker images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null || true
echo "__INSPECT__"
for id in $(docker ps -q 2>/dev/null); do
  docker inspect --format '{{.Id}}|{{.Name}}|privileged={{.HostConfig.Privileged}}|network={{.HostConfig.NetworkMode}}|pid={{.HostConfig.PidMode}}|ipc={{.HostConfig.IpcMode}}|project={{index .Config.Labels "com.docker.compose.project"}}|mounts={{json .Mounts}}' "$id" 2>/dev/null
done
'''

def section(text,name,next_name=None):
    token=f"__{name}__"
    if token not in text:
        return ""
    s=text.split(token,1)[1]
    if next_name and f"__{next_name}__" in s:
        s=s.split(f"__{next_name}__",1)[0]
    return s.strip()

def run(cfg,report):
    try:
        r=run_script(cfg,BASE,timeout_seconds=60)
    except RemoteBlocked as e:
        report.add("docker.host.available","BLOCKED","docker",str(e))
        return
    if r["exit_code"]!=0:
        report.add("docker.host.available","INFRA_ERROR","docker","Could not collect Docker host baseline.",evidence=r)
        return
    txt=r["stdout_tail"]
    present=bool(section(txt,"DOCKER_PRESENT"))
    required=cfg.get("remote",{}).get("docker",{}).get("required",True)
    if not present:
        report.add("docker.installed","FAIL" if required else "SKIP","docker","Docker executable is not present on remote host.")
        return
    report.add("docker.installed","PASS","docker","Docker executable is present.")
    groups=section(txt,"GROUPS","DOCKER_SOCKET")
    user=cfg.get("remote",{}).get("user","deploy")
    in_group=bool(re.search(r'\bdocker\b',groups))
    forbid=cfg.get("remote",{}).get("forbid_remote_user_docker_group",True)
    report.add("docker.remote_user.group","FAIL" if (forbid and in_group) else "PASS","docker",
               f"{user} is {'in' if in_group else 'not in'} the docker group.",
               recommendation="Remove routine deploy users from the docker group; Docker documents it as root-equivalent." if forbid and in_group else None)
    sock=section(txt,"DOCKER_SOCKET","DOCKER_PRESENT")
    report.add("docker.socket.present","PASS" if sock else "WARN","docker",
               "Docker socket metadata collected." if sock else "Docker socket metadata was not available.",evidence=sock or None)
    try:
        pr=run_script(cfg,PRIV,privileged=True,timeout_seconds=120)
    except RemoteBlocked as e:
        report.add("docker.privileged.audit","BLOCKED","docker",str(e),
                   recommendation="Use an audit-capable ops account and remote.sudo_mode=noninteractive only after reviewing the privilege boundary.")
        return
    if pr["exit_code"]!=0:
        report.add("docker.privileged.audit","INFRA_ERROR","docker","Privileged Docker audit failed.",evidence=pr)
        return
    out=pr["stdout_tail"]
    ps=[x for x in section(out,"PS","IMAGES").splitlines() if x.strip()]
    imgs=[x for x in section(out,"IMAGES","INSPECT").splitlines() if x.strip()]
    inspect=[x for x in section(out,"INSPECT").splitlines() if x.strip()]
    forbidden=set(int(x) for x in cfg.get("remote",{}).get("forbidden_public_ports",[]))
    bad_ports=[]
    for line in ps:
        for m in re.finditer(r'(?:0\.0\.0\.0|\[::\]|:::|\*):(\d+)->',line):
            if int(m.group(1)) in forbidden:
                bad_ports.append(line[:300])
    report.add("docker.forbidden_published_ports","FAIL" if bad_ports else "PASS","docker",
               "Docker publishes forbidden internal ports." if bad_ports else "No configured forbidden Docker host port was detected.",
               evidence=bad_ports or None)
    privileged=[x for x in inspect if "privileged=true" in x.lower()]
    hosts=[x for x in inspect if "network=host" in x.lower()]
    host_pid=[x for x in inspect if "|pid=host|" in x.lower()]
    host_ipc=[x for x in inspect if "|ipc=host|" in x.lower()]
    sockmount=[x for x in inspect if "docker.sock" in x]

    forbidden_mount_roots = (
        '"/etc"', '"/root"', '"/home"', '"/var/lib/docker"', '"/tmp"',
        '"/dev"', '"/proc"', '"/sys"', '"/boot"',
        '"/usr/bin/docker"', '"/usr/local/bin/docker"',
    )
    dangerous_mounts=[
        x for x in inspect
        if any(token in x.lower() for token in forbidden_mount_roots)
    ]
    report.add("docker.containers.privileged","FAIL" if privileged else "PASS","docker",
               "Privileged containers detected." if privileged else "No privileged running container detected.",evidence=privileged or None)
    report.add("docker.containers.host_network","FAIL" if hosts else "PASS","docker",
               "Host-network containers detected." if hosts else "No host-network container detected.",evidence=hosts or None)
    report.add("docker.containers.host_pid","FAIL" if host_pid else "PASS","docker",
               "Host PID namespace containers detected." if host_pid else "No host PID namespace container detected.",evidence=host_pid or None)
    report.add("docker.containers.host_ipc","FAIL" if host_ipc else "PASS","docker",
               "Host IPC namespace containers detected." if host_ipc else "No host IPC namespace container detected.",evidence=host_ipc or None)
    report.add("docker.containers.dangerous_mounts","FAIL" if dangerous_mounts else "PASS","docker",
               "Containers mount forbidden host paths." if dangerous_mounts else "No forbidden host-path mount detected.",evidence=dangerous_mounts or None)
    report.add("docker.containers.socket_mount","FAIL" if sockmount else "PASS","docker",
               "A running container mounts the Docker socket." if sockmount else "No running container Docker-socket mount detected.",
               evidence=sockmount or None)
    tokens=[str(x).lower() for x in cfg.get("remote",{}).get("iocs",{}).get("tokens",[])]
    ioc=[x for x in (ps+imgs+inspect) if any(t in x.lower() for t in tokens)]
    report.add("docker.incident_ioc","FAIL" if ioc else "PASS","incident_recovery",
               "Known incident IOC matched Docker state." if ioc else "No configured incident IOC matched Docker state.",
               evidence=ioc[:100] if ioc else None)
    docker_cfg=cfg.get("remote",{}).get("docker",{})
    strict=bool(docker_cfg.get("strict_container_allowlist",False))

    allowed_prefixes=tuple(str(x).strip() for x in docker_cfg.get("allowed_image_prefixes",[]) if str(x).strip())
    if strict and not allowed_prefixes:
        report.add(
            "docker.images.allowlist",
            "CONFIG_ERROR",
            "docker",
            "Strict Docker image allowlist is enabled but allowed_image_prefixes is empty.",
            recommendation="Configure a reviewed runtime image allowlist before release.",
            release_blocker=True,
        )
    else:
        unknown_images=[
            image for image in imgs
            if strict and not any(image.startswith(prefix) for prefix in allowed_prefixes)
        ]
        report.add(
            "docker.images.allowlist",
            "FAIL" if unknown_images else ("PASS" if strict else "SKIP"),
            "docker",
            "Unexpected Docker images are present on the host."
            if unknown_images
            else ("Docker image inventory matches configured prefixes." if strict else "Strict image allowlist is disabled."),
            evidence=unknown_images[:100] if unknown_images else None,
            release_blocker=bool(unknown_images),
        )

    allowed_projects={str(x).strip() for x in docker_cfg.get("allowed_compose_projects",[]) if str(x).strip()}
    if strict and not allowed_projects:
        report.add(
            "docker.container_allowlist",
            "CONFIG_ERROR",
            "docker",
            "Strict Docker container allowlist is enabled but allowed_compose_projects is empty.",
            recommendation="Configure reviewed Compose project names before release.",
            release_blocker=True,
        )
    else:
        unknown=[]
        if strict:
            for x in inspect:
                m=re.search(r'\|project=([^|]*)\|',x)
                project=(m.group(1).strip() if m else "")
                if project not in allowed_projects:
                    unknown.append(x[:300])
        report.add(
            "docker.container_allowlist",
            "FAIL" if unknown else ("PASS" if strict else "SKIP"),
            "docker",
            "Unexpected running container projects detected."
            if unknown
            else ("Running container projects match configured allowlist." if strict else "Strict container allowlist is disabled."),
            evidence=unknown[:100] if unknown else None,
            release_blocker=bool(unknown),
        )
    report.metrics.update({"running_containers":len(ps),"images":len(imgs),"inspect_rows":len(inspect)})
