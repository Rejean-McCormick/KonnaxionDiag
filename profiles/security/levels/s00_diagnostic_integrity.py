from __future__ import annotations
import importlib.util, sys
from pathlib import Path
from diagcore.manifest import load_manifest
from diagcore.contracts import load_contract_registry

def run(cfg, report):
    tool=Path(cfg["_tool_root"])
    report.add("kdiag.python.version","PASS" if sys.version_info>=(3,10) else "CONFIG_ERROR",
               "diagnostics",f"Python {sys.version.split()[0]} {'is supported' if sys.version_info>=(3,10) else 'is unsupported'}.",
               recommendation=None if sys.version_info>=(3,10) else "Use Python 3.10+.")
    m=load_manifest(tool)
    missing=[x["module"] for x in m["levels"] if importlib.util.find_spec(x["module"]) is None]
    report.add("kdiag.level_modules.available","PASS" if not missing else "CONFIG_ERROR","diagnostics",
               "All declared level modules are importable." if not missing else "Declared level modules are missing.",
               evidence={"count":len(m["levels"])} if not missing else missing)
    req=[tool/"schemas"/"report.schema.json",tool/"schemas"/"campaign-summary.schema.json",tool/"schemas"/"release-verdict.schema.json",tool/"schemas"/"security-contract-attestation.schema.json",tool/"schemas"/"detached-signature.schema.json"]
    absent=[p.name for p in req if not p.exists()]
    report.add("kdiag.schemas.present","PASS" if not absent else "CONFIG_ERROR","diagnostics",
               "Required schemas are present." if not absent else "Required schemas are missing.",evidence=absent or {"count":len(req)})
    try:
        registry=load_contract_registry(tool)
        ids=[str(x.get("id")) for x in registry.get("contracts",[])]
        registry_ok=len(ids)==53 and ids==[f"SEC-{i:02d}" for i in range(1,54)]
        registry_evidence={"count":len(ids),"first":ids[0] if ids else None,"last":ids[-1] if ids else None}
    except Exception as exc:
        registry_ok=False;registry_evidence={"error":f"{type(exc).__name__}: {exc}"}
    report.add("kdiag.security_contract_registry","PASS" if registry_ok else "CONFIG_ERROR","diagnostics",
               "Senior Security Codex SEC-01..SEC-53 registry is complete." if registry_ok else "Security contract registry is missing, malformed, or incomplete.",
               evidence=registry_evidence)
    cfg_file=tool/"kdiag.config.json"
    report.add("kdiag.config.present","PASS" if cfg_file.exists() else "CONFIG_ERROR","diagnostics",
               "Base configuration is present." if cfg_file.exists() else "Base configuration is missing.")
    report.add("kdiag.safety.read_only","PASS","safety",
               "SecurityDiag levels are designed for read-only evidence collection; remediation is not automatically applied.")
