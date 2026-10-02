from __future__ import annotations
import importlib.util, sys
from pathlib import Path
from diagcore.manifest import load_manifest

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
    req=[tool/"schemas"/"report.schema.json",tool/"schemas"/"campaign-summary.schema.json"]
    absent=[p.name for p in req if not p.exists()]
    report.add("kdiag.schemas.present","PASS" if not absent else "CONFIG_ERROR","diagnostics",
               "Required schemas are present." if not absent else "Required schemas are missing.",evidence=absent or {"count":len(req)})
    cfg_file=tool/"kdiag.config.json"
    report.add("kdiag.config.present","PASS" if cfg_file.exists() else "CONFIG_ERROR","diagnostics",
               "Base configuration is present." if cfg_file.exists() else "Base configuration is missing.")
    report.add("kdiag.safety.read_only","PASS","safety",
               "SecurityDiag levels are designed for read-only evidence collection; remediation is not automatically applied.")
