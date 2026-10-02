from __future__ import annotations
import json,re
from dataclasses import dataclass
from pathlib import Path

class ManifestError(RuntimeError):pass

@dataclass(frozen=True,slots=True)
class LevelSpec:
    id:str; name:str; module:str; profile:str; runner:str; required:bool; depends_on:tuple[str,...]; timeout_seconds:int; order:int; purpose:str=''

def load_manifest(root:Path|None=None):
    root=(root or Path(__file__).resolve().parents[1]).resolve(); p=root/'kdiag_manifest.json'
    if not p.is_file():raise ManifestError(f'Missing manifest: {p}')
    data=json.loads(p.read_text(encoding='utf-8-sig')); errors=validate_manifest(data)
    if errors:raise ManifestError('; '.join(errors))
    return data

def validate_manifest(data):
    errors=[]
    if data.get('schema')!='konnaxiondiag.manifest.v4':errors.append('unsupported manifest schema')
    levels=data.get('levels',[])
    if not isinstance(levels,list) or not levels:errors.append('manifest must declare levels');return errors
    ids=[x.get('id') for x in levels]; known=set(ids)
    if any(not x for x in ids) or len(ids)!=len(known):errors.append('level IDs must be non-empty and unique')
    for x in levels:
        if x.get('profile') not in {'levelup','security'}:errors.append(f"{x.get('id')} has invalid profile")
        if x.get('runner') not in {'levelup','security'}:errors.append(f"{x.get('id')} has invalid runner")
        if not x.get('module'):errors.append(f"{x.get('id')} missing module")
        for dep in x.get('depends_on',[]):
            if dep not in known:errors.append(f"{x.get('id')} depends on unknown {dep}")
    for name,c in data.get('campaigns',{}).items():
        for lid in c.get('levels',[]):
            if lid not in known:errors.append(f'campaign {name} contains unknown level {lid}')
    return errors

def list_levels(root:Path|None=None):
    return [LevelSpec(x['id'],x['name'],x['module'],x['profile'],x['runner'],bool(x.get('required',False)),tuple(x.get('depends_on',[])),int(x.get('timeout_seconds',120)),int(x.get('order',0)),x.get('purpose','')) for x in load_manifest(root)['levels']]

def normalize_level_id(value):
    s=str(value).strip().upper().replace('_','')
    if re.fullmatch(r'N\d{1,2}',s):return f'N{int(s[1:]):02d}'
    if s=='S04W':return s
    if re.fullmatch(r'S\d{1,2}',s):return f'S{int(s[1:]):02d}'
    raise ValueError(f'invalid level id: {value}')

def get_level(level_id,root:Path|None=None):
    lid=normalize_level_id(level_id)
    for x in list_levels(root):
        if x.id==lid:return x
    raise ManifestError(f'unknown level: {lid}')

def get_campaign(name,root:Path|None=None):
    c=load_manifest(root).get('campaigns',{}).get(name)
    if c is None:raise ManifestError(f'unknown campaign: {name}')
    return dict(c)

def resolve_selection(m,name):
    lm={x['id']:x for x in m['levels']}
    if name in lm:selected={name}
    elif name in m.get('campaigns',{}):selected=set(m['campaigns'][name].get('levels',[]))
    else:raise ManifestError(f'unknown level or campaign: {name}')
    changed=True
    while changed:
        changed=False
        for lid in list(selected):
            for dep in lm[lid].get('depends_on',[]):
                if dep not in selected:selected.add(dep);changed=True
    return sorted((lm[x] for x in selected),key=lambda x:(x.get('order',0),x['id']))
