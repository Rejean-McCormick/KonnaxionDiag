from __future__ import annotations

import os
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from assurance.release_set import build_release_set
from . import VERSION
from .assurance import finding_fingerprint, validate_warning_disposition
from .signing import resolve_private_key, sign_payload
from .utils import utc_now, write_json

HARD={'FAIL','BLOCKED','ERROR','INFRA_ERROR','CONFIG_ERROR','PARTIAL'}


def _dispositions(cfg:dict[str,Any])->dict[str,Any]:
    release=cfg.get('release',{}) if isinstance(cfg.get('release',{}),dict) else {}
    gate=cfg.get('release_gate',{}) if isinstance(cfg.get('release_gate',{}),dict) else {}
    value=gate.get('security_warn_dispositions',release.get('warn_dispositions',{}))
    return value if isinstance(value,dict) else {}


def _disposition_policy(cfg:dict[str,Any])->dict[str,Any]:
    gate=cfg.get('release_gate',{}) if isinstance(cfg.get('release_gate',{}),dict) else {}
    value=gate.get('disposition_policy',{})
    return value if isinstance(value,dict) else {}


def _policy_version(cfg:dict[str,Any])->str:
    gate=cfg.get('release_gate',{}) if isinstance(cfg.get('release_gate',{}),dict) else {}
    auth=gate.get('authorization',{}) if isinstance(gate.get('authorization',{}),dict) else {}
    return str(auth.get('policy_version','konnaxiondiag-security-policy-v1')).strip() or 'konnaxiondiag-security-policy-v1'


def disposition_valid(
    value:Any,*,cfg:dict[str,Any]|None=None,subject_sha256:str|None=None,
    release_set_digest:str|None=None,target_root:Path|None=None,
    level_id:str|None=None,finding:dict[str,Any]|None=None
)->bool:
    effective_cfg=cfg or {}
    fp=finding_fingerprint(level_id or '',finding or {}) if finding else None
    ok,_=validate_warning_disposition(
        value,policy=_disposition_policy(effective_cfg),subject_sha256=subject_sha256,
        release_set_digest=release_set_digest,finding_fingerprint_value=fp,
        policy_version=_policy_version(effective_cfg),target_root=target_root,
    )
    return ok


def unresolved_security_warnings(
    results:list[dict],cfg:dict[str,Any],*,subject_sha256:str|None=None,
    release_set_digest:str|None=None,target_root:Path|None=None
)->list[dict]:
    dispositions=_dispositions(cfg); unresolved=[];policy=_disposition_policy(cfg)
    digest=release_set_digest or subject_sha256
    for result in results:
        level_id=str(result.get('level_id',''))
        if level_id.startswith('S'):
            for f in result.get('findings',[]):
                if f.get('verdict')=='WARN':
                    fid=str(f.get('id',''));fp=finding_fingerprint(level_id,f)
                    ok,detail=validate_warning_disposition(
                        dispositions.get(fid),policy=policy,release_set_digest=digest,
                        finding_fingerprint_value=fp,policy_version=_policy_version(cfg),target_root=target_root
                    )
                    if not ok:
                        unresolved.append({'level_id':level_id,'finding_id':fid,'finding_fingerprint':fp,'message':f.get('message',''),'disposition_validation':detail})
    return unresolved


def _authorization(*,verdict:str,release_set_digest:str|None,run_id:str,cfg:dict[str,Any],issued:datetime)->dict[str,Any]:
    gate=cfg.get('release_gate',{}) if isinstance(cfg.get('release_gate',{}),dict) else {}
    auth=gate.get('authorization',{}) if isinstance(gate.get('authorization',{}),dict) else {}
    ttl=int(auth.get('ttl_seconds',3600) or 3600)
    if ttl<=0:raise ValueError('release_gate.authorization.ttl_seconds must be > 0')
    return {
        'schema':'konnaxiondiag.release-authorization.v1',
        'subject':release_set_digest,
        'verdict':verdict,
        'policy_version':_policy_version(cfg),
        'issued_at':issued.isoformat(),
        'expires_at':(issued+timedelta(seconds=ttl)).isoformat(),
        'run_id':run_id,
        'nonce':secrets.token_urlsafe(24),
    }


def build_final_release_verdict(*,campaign:str,run_id:str,target_root:Path,results:list[dict],cfg:dict[str,Any],correlation:dict[str,Any],out_dir:Path,target_protection:dict[str,Any]|None=None)->dict[str,Any]:
    n=[r for r in results if str(r.get('level_id','')).startswith('N')]
    s=[r for r in results if str(r.get('level_id','')).startswith('S')]
    n_hard=[r for r in n if r.get('verdict') in HARD]
    n_warn=[r for r in n if r.get('verdict')=='WARN']
    s_hard=[r for r in s if r.get('verdict') in HARD]

    release_set,release_set_issues=build_release_set(target_root=target_root,results=results,cfg=cfg)
    release_set_digest=release_set.get('release_set_digest')
    gate_cfg=cfg.get('release_gate',{}) if isinstance(cfg.get('release_gate',{}),dict) else {}
    rs_cfg=cfg.get('release_set',{}) if isinstance(cfg.get('release_set',{}),dict) else {}
    subject_required=bool(rs_cfg.get('required',gate_cfg.get('subject_binding',{}).get('required',False)))
    unresolved=unresolved_security_warnings(
        s,cfg,release_set_digest=release_set_digest,target_root=target_root
    )
    s14=next((r for r in s if r.get('level_id')=='S14'),None)
    subject_clean=not release_set_issues or not subject_required
    protection_clean=not target_protection
    security_clean=bool(s14 and s14.get('verdict')=='PASS' and not s_hard and not unresolved and subject_clean and protection_clean)
    functional_clean=not n_hard
    if not security_clean or not functional_clean:verdict='BLOCKED'
    elif n_warn:verdict='WARN'
    else:verdict='PASS'

    signing_cfg=gate_cfg.get('signing',{}) if isinstance(gate_cfg.get('signing',{}),dict) else {}
    signing_required=bool(signing_cfg.get('required',True))
    key_path=resolve_private_key(cfg,target_root)
    signature_meta:dict[str,Any]
    if key_path is None:
        signature_meta={'required':signing_required,'status':'MISSING' if signing_required else 'UNSIGNED'}
        if signing_required:
            verdict='BLOCKED';signature_meta['reason']='release signing is required but no KDIAG_RELEASE_SIGNING_KEY/private_key_file is configured'
    elif not key_path.is_file():
        signature_meta={'required':signing_required,'status':'ERROR','reason':f'signing key not found: {key_path}'}
        if signing_required:verdict='BLOCKED'
    else:
        signature_meta={'required':signing_required,'status':'SIGNED','algorithm':'ed25519','envelope':'release-verdict.sig'}

    issued=datetime.now(timezone.utc)
    authorization=_authorization(verdict=verdict,release_set_digest=release_set_digest,run_id=run_id,cfg=cfg,issued=issued)
    payload={
      'schema':'konnaxiondiag.release-verdict.v5','standard':'KonnaxionDiag','standard_version':VERSION,
      'campaign':campaign,'run_id':run_id,'target_repo_root':str(target_root),'created_at':issued.isoformat(),
      'verdict':verdict,'authorization':authorization,'release_set':release_set,
      'subject_binding':{'required':subject_required,'valid':subject_clean,'problems':release_set_issues,'release_set_digest':release_set_digest},
      'target_protection':target_protection or {'verdict':'PASS'},
      'functional':{'clean':functional_clean,'blocking_levels':[r.get('level_id') for r in n_hard],'warning_levels':[r.get('level_id') for r in n_warn]},
      'security':{'clean':security_clean,'s14_verdict':s14.get('verdict') if s14 else 'MISSING','blocking_levels':[r.get('level_id') for r in s_hard],
                  'unresolved_warnings':unresolved,'security_evidence_set_digest':release_set.get('security_evidence_set_digest')},
      'cross_domain_correlation':{'verdict':correlation.get('verdict'),'chains':correlation.get('chains',[])},
      'signature':signature_meta,
      'consumer_contract':{
          'pep':'verify detached Ed25519 signature; require an activation-acceptable verdict; recompute the active ReleaseSet; require active release_set_digest == authorization.subject; verify authorization freshness/policy; fail closed on missing/unknown evidence',
          'release_set_digest':release_set_digest,
          'authorization_schema':'konnaxiondiag.release-authorization.v1',
          'caller_may_disable_gate':False,
      },
    }
    write_json(out_dir/'release-set.json',release_set)

    if signature_meta.get('status')!='SIGNED':
        write_json(out_dir/'release-verdict.json',payload);return payload
    try:
        password=os.environ.get('KDIAG_RELEASE_SIGNING_KEY_PASSWORD')
        envelope=sign_payload(payload,key_path,password.encode('utf-8') if password else None)
        write_json(out_dir/'release-verdict.json',payload);write_json(out_dir/'release-verdict.sig',envelope)
    except Exception as exc:
        payload['signature']={'required':signing_required,'status':'ERROR','reason':f'{type(exc).__name__}: {exc}'}
        if signing_required:
            payload['verdict']='BLOCKED';payload['authorization']['verdict']='BLOCKED'
        write_json(out_dir/'release-verdict.json',payload)
    return payload
