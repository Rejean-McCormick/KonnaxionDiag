from __future__ import annotations

from pathlib import Path
from typing import Any

from assurance.attestation import ATTESTATION_SCHEMA, attestation_purpose, validate_universal_attestation
from assurance.release_set import validate_release_set
from .assurance import resolve_trusted_public_keys, temporal_attestation_check, verify_signed_attestation
from .utils import read_json

# Deprecated compatibility constant. v4.2 uses the universal attestation purpose.
CONTRACT_ATTESTATION_PURPOSE_PREFIX='konnaxiondiag-security-contract-attestation:'


def load_contract_registry(tool_root:Path)->dict[str,Any]:
    path=tool_root/'security_contracts.json'
    if not path.is_file():
        path=tool_root/'assurance'/'security_contracts.json'
    data=read_json(path)
    if data.get('schema')!='konnaxiondiag.security-contract-registry.v1':
        raise ValueError('unsupported security contract registry schema')
    contracts=data.get('contracts')
    if not isinstance(contracts,list) or not contracts:raise ValueError('security contract registry is empty')
    ids=[str(x.get('id','')) for x in contracts if isinstance(x,dict)]
    if len(ids)!=len(set(ids)):raise ValueError('security contract registry contains duplicate ids')
    return data


def _finding_map(results:list[dict])->dict[str,dict]:
    out={}
    for result in results:
        for f in result.get('findings',[]):
            fid=str(f.get('id','')).strip()
            if fid:out[fid]=f
    return out


def _native_contract(contract_id:str,*,results:list[dict],release_set:dict[str,Any],subject_ok:bool)->tuple[bool,dict[str,Any]]:
    findings=_finding_map(results)
    if contract_id=='SEC-29':
        required=['supply_chain.container_images.immutable','capsule.security_gate.evidence']
        states={fid:(findings.get(fid) or {}).get('verdict','MISSING') for fid in required}
        ok=all(v=='PASS' for v in states.values()) and bool(release_set.get('identity',{}).get('image_digests'))
        return ok,{'validator':'release_admission_by_digest_and_attestation','required_findings':states,'release_set_digest':release_set.get('release_set_digest')}
    if contract_id=='SEC-33':
        rs_ok,detail=validate_release_set(release_set,require_complete=True)
        ok=bool(subject_ok and rs_ok and release_set.get('release_set_digest'))
        return ok,{'validator':'release_set_security_object','release_set_digest':release_set.get('release_set_digest'),'subject_ok':subject_ok,'release_set_validation':detail}
    if contract_id=='SEC-43':
        state=(findings.get('recovery.restore_attestation') or {}).get('verdict','MISSING')
        return state=='PASS',{'validator':'compromise_ready_restore','restore_attestation_verdict':state}
    return False,{'validator':'unknown','reason':'no native validator registered'}


def _required_ids(cfg:dict[str,Any],registry:dict[str,Any])->list[str]:
    assurance=cfg.get('security_assurance',{}) if isinstance(cfg.get('security_assurance',{}),dict) else {}
    raw=assurance.get('required_contracts','all')
    known=[str(c.get('id')) for c in registry.get('contracts',[]) if isinstance(c,dict) and c.get('id')]
    if raw=='all':return known
    if not isinstance(raw,list):raise ValueError('security_assurance.required_contracts must be "all" or a list')
    requested=[]
    for x in raw:
        cid=str(x).strip()
        if cid and cid not in requested:requested.append(cid)
    unknown=[cid for cid in requested if cid not in known]
    if unknown:raise ValueError('unknown security assurance contract ids: '+', '.join(unknown))
    return requested

def _legacy_contract_attestation(
    payload:dict[str,Any],envelope:dict[str,Any]|None,*,cid:str,expected_subject:str,
    public_keys:list[Path],max_age:int,signature_required:bool
)->tuple[bool,dict[str,Any]]:
    """Migration-only verifier for v4.1 contract attestations."""
    problems=[]
    if payload.get('schema')!='konnaxiondiag.security-contract-attestation.v1':problems.append('invalid legacy attestation schema')
    if str(payload.get('contract_id',''))!=cid:problems.append('contract_id mismatch')
    if str(payload.get('status','')).upper()!='PASS':problems.append('attestation status is not PASS')
    subject=payload.get('subject') if isinstance(payload.get('subject'),dict) else {}
    legacy_expected=expected_subject.removeprefix('sha256:')
    if str(subject.get('release_subject_sha256','')).strip()!=legacy_expected:problems.append('legacy attestation is not bound to this ReleaseSet')
    time_ok,time_detail=temporal_attestation_check(payload,max_age_seconds=max_age)
    if not time_ok:problems.extend(time_detail.get('problems',[]))
    sig_ok,sig_detail=verify_signed_attestation(payload,envelope,purpose=CONTRACT_ATTESTATION_PURPOSE_PREFIX+cid,public_keys=public_keys,signature_required=signature_required)
    if not sig_ok:problems.append('signature is not trusted/valid')
    return not problems,{'problems':problems,'legacy':True,'freshness':time_detail,'signature_verification':sig_detail}


def evaluate_security_contracts(*,cfg:dict[str,Any],results:list[dict],release_set:dict[str,Any]|None=None,release_subject:dict[str,Any]|None=None,subject_ok:bool)->tuple[bool,dict[str,Any]]:
    legacy_call=release_set is None and release_subject is not None
    if release_set is None:
        old=release_subject or {}
        digest=str(old.get('release_set_digest') or old.get('subject_sha256') or '').strip()
        if digest and not digest.startswith('sha256:') and len(digest)==64:
            digest='sha256:'+digest
        release_set={
            'schema':'konnaxiondiag.release-set.v1',
            'identity':{'schema':'konnaxiondiag.release-set.identity.v1','image_digests':[x for subj in old.get('capsule_subjects',[]) if isinstance(subj,dict) for x in (subj.get('image_digests') or [])]},
            'release_set_digest':digest,
            'complete':True,
            'capsule_subjects':old.get('capsule_subjects',[]),
        }
    assurance=cfg.get('security_assurance',{}) if isinstance(cfg.get('security_assurance',{}),dict) else {}
    enabled=bool(assurance.get('enabled',True))
    if not enabled:
        return False,{'enabled':False,'reason':'security assurance contracts are disabled; release cannot claim codex coverage'}
    tool_root=Path(cfg.get('_tool_root','')).resolve(strict=False)
    target_root=Path(cfg.get('_target_root','')).resolve(strict=False)
    registry=load_contract_registry(tool_root)
    required=_required_ids(cfg,registry)
    by_id={str(c.get('id')):c for c in registry.get('contracts',[]) if isinstance(c,dict)}
    evidence_rel=str(assurance.get('evidence_dir','attestations/security-contracts')).strip()
    evidence_dir=(target_root/evidence_rel).resolve(strict=False)
    if not evidence_dir.is_relative_to(target_root):raise ValueError('security_assurance.evidence_dir escapes target repository')
    max_age=int(assurance.get('max_age_seconds',86400) or 86400)
    signature_required=bool(assurance.get('signature_required',True))
    accept_legacy=bool(assurance.get('accept_legacy_attestations',legacy_call))
    global_keys=resolve_trusted_public_keys(assurance.get('trusted_public_keys'),base=target_root)
    keys_by_contract=assurance.get('trusted_public_keys_by_contract',{}) if isinstance(assurance.get('trusted_public_keys_by_contract',{}),dict) else {}
    keys_by_group=assurance.get('trusted_public_keys_by_authority_group',{}) if isinstance(assurance.get('trusted_public_keys_by_authority_group',{}),dict) else {}
    issuers_by_contract=assurance.get('trusted_issuers_by_contract',{}) if isinstance(assurance.get('trusted_issuers_by_contract',{}),dict) else {}
    issuers_by_group=assurance.get('trusted_issuers_by_authority_group',{}) if isinstance(assurance.get('trusted_issuers_by_authority_group',{}),dict) else {}
    allow_global_fallback=bool(assurance.get('allow_global_trust_fallback',legacy_call))
    expected_subject=str(release_set.get('release_set_digest','')).strip()
    expected_policy_digest=str(assurance.get('expected_policy_digest','') or '').strip() or None
    evaluated=[]
    for cid in required:
        c=by_id[cid];mode=str(c.get('verification','external_attestation'))
        if mode=='native':
            ok,detail=_native_contract(cid,results=results,release_set=release_set,subject_ok=subject_ok)
            evaluated.append({'id':cid,'name':c.get('name'),'mode':'native','valid':ok,'detail':detail})
            continue
        payload_path=evidence_dir/f'{cid}.json';sig_path=evidence_dir/f'{cid}.json.sig'
        if not payload_path.is_file():
            evaluated.append({'id':cid,'name':c.get('name'),'mode':'external_attestation','valid':False,'detail':{'reason':'attestation missing','path':str(payload_path)}});continue
        try:payload=read_json(payload_path)
        except Exception as exc:
            evaluated.append({'id':cid,'name':c.get('name'),'mode':'external_attestation','valid':False,'detail':{'reason':f'invalid attestation JSON: {exc}'}});continue
        try:envelope=read_json(sig_path) if sig_path.is_file() else None
        except Exception:envelope=None
        authority_group=str(c.get('authority_group','')).strip()
        contract_keys=resolve_trusted_public_keys(keys_by_contract.get(cid),base=target_root)
        group_keys=resolve_trusted_public_keys(keys_by_group.get(authority_group),base=target_root)
        registry_keys=resolve_trusted_public_keys(c.get('trusted_public_keys'),base=target_root)
        keys=contract_keys or group_keys or registry_keys or (global_keys if allow_global_fallback else [])
        expected_issuers=issuers_by_contract.get(cid,issuers_by_group.get(authority_group,[]))
        if isinstance(expected_issuers,str):expected_issuers=[expected_issuers]

        if payload.get('schema')==ATTESTATION_SCHEMA:
            ok,detail=validate_universal_attestation(
                payload,envelope,public_keys=keys,expected_release_set_digest=expected_subject,
                expected_evidence_type=f'security.contract.{cid}',expected_issuers=expected_issuers,
                expected_policy_digest=expected_policy_digest,max_age_seconds=max_age,
                signature_required=signature_required,
            )
            statement=payload.get('statement') if isinstance(payload.get('statement'),dict) else {}
            if str(statement.get('contract_id',''))!=cid:
                detail.setdefault('problems',[]).append('statement.contract_id mismatch')
                ok=False
        elif accept_legacy:
            ok,detail=_legacy_contract_attestation(payload,envelope,cid=cid,expected_subject=expected_subject,public_keys=keys,max_age=max_age,signature_required=signature_required)
        else:
            ok=False;detail={'problems':['legacy/specialized attestation rejected; universal konnaxiondiag.attestation.v1 required']}
        evaluated.append({'id':cid,'name':c.get('name'),'mode':'external_attestation','valid':ok,'detail':detail})
    failed=[x for x in evaluated if not x.get('valid')]
    return not failed,{
        'enabled':True,'registry_schema':registry.get('schema'),'required_count':len(required),'valid_count':len(evaluated)-len(failed),
        'failed_count':len(failed),'release_set_digest':expected_subject,'evaluated':evaluated,
    }
