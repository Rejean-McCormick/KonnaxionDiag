from __future__ import annotations
import importlib,traceback
from pathlib import Path
from .config import load_config
from .manifest import get_level
from .models import Finding,LevelResult
from .evidence import write_level_result
from .report import Report
from .utils import local_now
from .verdicts import ERROR

def run_worker(root:Path,level_id:str,run_id:str,output:Path,target_override=None):
    spec=get_level(level_id,root);cfg=load_config(root,target_override)
    try:
        mod=importlib.import_module(spec.module)
        if spec.runner=='levelup':
            result=mod.run(cfg)
            if not isinstance(result,LevelResult):raise TypeError(f'{spec.id} run() did not return LevelResult')
            write_level_result(output,result,profile=spec.profile,run_id=run_id,target_root=str(cfg.target_root_path));return 0
        report=Report(run_id,spec.id,spec.name,spec.purpose,cfg.target_root_path,profile=spec.profile)
        sec_cfg=cfg.security_dict(output.parent.parent.parent)
        mod.run(sec_cfg,report);report.write(output);return 0
    except Exception as exc:
        if spec.runner=='security':
            report=locals().get('report') or Report(run_id,spec.id,spec.name,spec.purpose,cfg.target_root_path,profile=spec.profile)
            report.add('kdiag.level.exception','ERROR','diagnostics',f'Level raised {type(exc).__name__}.',evidence={'error':str(exc)[:1000],'traceback':traceback.format_exc()[-12000:]})
            report.write(output,override_verdict='ERROR');return 30
        now=local_now();result=LevelResult(spec.id,spec.name,ERROR,[Finding('kdiag.level.exception',ERROR,'Unhandled diagnostic level exception.','diagnostics',evidence=f'{type(exc).__name__}: {exc}',recommendation='Inspect traceback evidence and fix the diagnostic code.')],started_at=now,ended_at=now,metadata={'traceback':traceback.format_exc()[-12000:]})
        write_level_result(output,result,profile=spec.profile,run_id=run_id,target_root=str(cfg.target_root_path));return 30
