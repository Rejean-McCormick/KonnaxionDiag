from __future__ import annotations
from pathlib import Path
from .s04_app_production import _check_web_trust_boundaries

def run(cfg, report):
    """S04W — focused web trust and authorization release qualification."""
    root=Path(cfg['_target_root'])
    app=cfg.get('application',{})
    _check_web_trust_boundaries(cfg,report,root,app)
