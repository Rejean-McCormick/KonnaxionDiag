from __future__ import annotations
import os
from pathlib import Path
from typing import Any
from .utils import read_json,write_json,utc_now
from .signing import resolve_private_key,sign_payload

HARD={'FAIL','BLOCKED','ERROR','INFRA_ERROR','CONFIG_ERROR','PARTIAL'}

def _dispositions(cfg:dict[str,Any])->dict[str,Any]:
    release=cfg.get('release',{}) if isinstance(cfg.get('release',{}),dict) else {}
    gate=cfg.get('release_gate',{}) if isinstance(cfg.get('release_gate',{}),dict) else {}
    value=gate.get('security_warn_dispositions',release.get('warn_dispositions',{}))
    return value if isinstance(value,dict) else {}

def disposition_valid(value:Any)->bool:
    if isinstance(value,str):return bool(value.strip())
    if not isinstance(value,dict):return False
    status=str(value.get('status','accepted')).strip().lower()
    rationale=str(value.get('rationale','')).strip()
    return status in {'accepted','approved','risk-accepted'} and bool(rationale)

def unresolved_security_warnings(results:list[dict],cfg:dict[str,Any])->list[dict]:
    dispositions=_dispositions(cfg); unresolved=[]
    for result in results:
        if str(result.get('level_id','')).startswith('S'):
            for f in result.get('findings',[]):
                if f.get('verdict')=='WARN':
                    fid=str(f.get('id',''))
                    if not disposition_valid(dispositions.get(fid)):
                        unresolved.append({'level_id':result.get('level_id'),'finding_id':fid,'message':f.get('message','')})
    return unresolved

def build_final_release_verdict(*,campaign:str,run_id:str,target_root:Path,results:list[dict],cfg:dict[str,Any],correlation:dict[str,Any],out_dir:Path)->dict[str,Any]:
    n=[r for r in results if str(r.get('level_id','')).startswith('N')]
    s=[r for r in results if str(r.get('level_id','')).startswith('S')]
    n_hard=[r for r in n if r.get('verdict') in HARD]
    n_warn=[r for r in n if r.get('verdict')=='WARN']
    s_hard=[r for r in s if r.get('verdict') in HARD]
    unresolved=unresolved_security_warnings(s,cfg)
    s14=next((r for r in s if r.get('level_id')=='S14'),None)
    security_clean=bool(s14 and s14.get('verdict')=='PASS' and not s_hard and not unresolved)
    functional_clean=not n_hard
    if not security_clean or not functional_clean:verdict='BLOCKED'
    elif n_warn:verdict='WARN'
    else:verdict='PASS'
    signing_cfg=cfg.get('release_gate',{}).get('signing',{}) if isinstance(cfg.get('release_gate',{}),dict) else {}
    signing_required=bool(signing_cfg.get('required',True))
    key_path=resolve_private_key(cfg,target_root)
    payload={
      'schema':'konnaxiondiag.release-verdict.v4','standard':'KonnaxionDiag','standard_version':'4.0.0',
      'campaign':campaign,'run_id':run_id,'target_repo_root':str(target_root),'created_at':utc_now(),
      'verdict':verdict,'functional':{'clean':functional_clean,'blocking_levels':[r.get('level_id') for r in n_hard],'warning_levels':[r.get('level_id') for r in n_warn]},
      'security':{'clean':security_clean,'s14_verdict':s14.get('verdict') if s14 else 'MISSING','blocking_levels':[r.get('level_id') for r in s_hard],
                  'unresolved_warnings':unresolved},
      'cross_domain_correlation':{'verdict':correlation.get('verdict'),'chains':correlation.get('chains',[])},
      'signature':{},
      'consumer_contract':{'capsule_manager':'consume this verdict plus the detached Ed25519 signature; never infer PASS from missing evidence'},
    }
    if key_path is None:
        payload['signature']={'required':signing_required,'status':'MISSING' if signing_required else 'UNSIGNED'}
        if signing_required:
            payload['verdict']='BLOCKED';payload['signature']['reason']='release signing is required but no KDIAG_RELEASE_SIGNING_KEY/private_key_file is configured'
        write_json(out_dir/'release-verdict.json',payload);return payload
    if not key_path.is_file():
        payload['signature']={'required':signing_required,'status':'ERROR','reason':f'signing key not found: {key_path}'}
        if signing_required:payload['verdict']='BLOCKED'
        write_json(out_dir/'release-verdict.json',payload);return payload
    # The detached signature covers the exact final release-verdict.json content.
    payload['signature']={'required':signing_required,'status':'SIGNED','algorithm':'ed25519','envelope':'release-verdict.sig'}
    try:
        password=os.environ.get('KDIAG_RELEASE_SIGNING_KEY_PASSWORD')
        envelope=sign_payload(payload,key_path,password.encode('utf-8') if password else None)
        write_json(out_dir/'release-verdict.json',payload)
        write_json(out_dir/'release-verdict.sig',envelope)
    except Exception as exc:
        payload['signature']={'required':signing_required,'status':'ERROR','reason':f'{type(exc).__name__}: {exc}'}
        if signing_required:payload['verdict']='BLOCKED'
        write_json(out_dir/'release-verdict.json',payload)
    return payload
