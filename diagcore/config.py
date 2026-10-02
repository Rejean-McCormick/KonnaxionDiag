from __future__ import annotations
import copy,json,os
from pathlib import Path
from typing import Any,Iterator

class ConfigError(RuntimeError): pass

def _merge(base,overlay):
    out=copy.deepcopy(base)
    for k,v in overlay.items():
        out[k]=_merge(out[k],v) if isinstance(v,dict) and isinstance(out.get(k),dict) else copy.deepcopy(v)
    return out

def _load(path):
    with path.open('r',encoding='utf-8-sig') as f:return json.load(f)

def _konnaxion_markers(path:Path,data:dict[str,Any])->int:
    section=data.get('konnaxion',{}) if isinstance(data.get('konnaxion',{}),dict) else {}
    frontend=str(section.get('frontend_dir','frontend')); backend=str(section.get('backend_dir','backend')); score=0
    if (path/frontend).is_dir():score+=2
    if (path/backend).is_dir():score+=2
    if (path/frontend/'package.json').is_file():score+=2
    if (path/backend/'manage.py').is_file():score+=2
    if (path/'.git').exists():score+=1
    return score

def _auto_target(root:Path,data:dict[str,Any])->Path:
    parent=root.parent
    candidates=[parent,parent/'Konnaxion',root]
    scored=[(_konnaxion_markers(c,data),i,c) for i,c in enumerate(candidates) if c.is_dir()]
    if scored:
        score,_,candidate=max(scored,key=lambda item:(item[0],-item[1]))
        if score>=4:return candidate
    return parent

class AppConfig:
    def __init__(self,data:dict[str,Any],root:Path):
        self.data=data; self.diagnostics_root_path=root.resolve()
        raw=data.get('target_repo_root','auto')
        if str(raw).lower()=='auto':target=_auto_target(self.diagnostics_root_path,data)
        else:
            p=Path(str(raw)).expanduser(); target=p if p.is_absolute() else self.diagnostics_root_path/p
        self.target_root_path=target.resolve(strict=False)
        control=Path(str(data.get('control_dir','.konnaxiondiag')))
        if control.is_absolute():raise ConfigError('control_dir must be relative to target_repo_root')
        self.control_root_path=(self.target_root_path/control).resolve(strict=False)
        if not self.control_root_path.is_relative_to(self.target_root_path):raise ConfigError('control_dir escapes target_repo_root')
        if not self.target_root_path.is_dir():raise ConfigError(f'target repository not found: {self.target_root_path}')
    def get(self,key,default=None):return self.data.get(key,default)
    def __getitem__(self,key):return self.data[key]
    def env(self):
        env=dict(os.environ); extra=self.data.get('env',{})
        if isinstance(extra,dict):env.update({str(k):str(v) for k,v in extra.items()})
        return env
    def security_dict(self,run_root:Path|None=None)->dict[str,Any]:
        out=copy.deepcopy(self.data)
        out['_tool_root']=str(self.diagnostics_root_path)
        out['_target_root']=str(self.target_root_path)
        out['_control_root']=str(self.control_root_path)
        if run_root is not None:out['_run_root']=str(run_root)
        return out

def load_config(root:Path|None=None,target_override:str|None=None)->AppConfig:
    root=(root or Path(__file__).resolve().parents[1]).resolve()
    base=root/'kdiag.config.json'
    if not base.is_file():raise ConfigError(f'configuration missing: {base}')
    data=_load(base); local=root/'kdiag.config.local.json'
    if local.is_file():data=_merge(data,_load(local))
    if data.get('schema')!='konnaxiondiag.config.v4':raise ConfigError(f"unsupported config schema: {data.get('schema')}")
    if target_override:data['target_repo_root']=target_override
    return AppConfig(data,root)
