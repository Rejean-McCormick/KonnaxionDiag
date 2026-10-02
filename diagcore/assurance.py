from __future__ import annotations
import hashlib,json,shutil,subprocess
from datetime import datetime,timezone
from pathlib import Path
from typing import Any,Iterable
from .signing import canonical_bytes,verify_evidence
from .utils import redact_data,read_json
from . import VERSION

CAPSULE_GATE_PURPOSE='konnaxiondiag-capsule-security-gate'
RESTORE_DRILL_PURPOSE='konnaxiondiag-restore-drill'
WARN_DISPOSITION_PURPOSE='konnaxiondiag-security-warning-disposition'


def sha256_json(value:Any)->str:
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode('utf-8')).hexdigest()


def _run_git(target:Path,*args:str)->str|None:
    if shutil.which('git') is None:return None
    try:
        cp=subprocess.run(['git',*args],cwd=str(target),stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
                          text=True,encoding='utf-8',errors='replace',timeout=20,shell=False,check=False)
        return cp.stdout.strip() if cp.returncode==0 else None
    except Exception:return None


def git_release_identity(target:Path)->dict[str,Any]:
    commit=_run_git(target,'rev-parse','HEAD')
    tree=_run_git(target,'rev-parse','HEAD^{tree}')
    branch=_run_git(target,'rev-parse','--abbrev-ref','HEAD')
    status=_run_git(target,'status','--porcelain=v1','--untracked-files=all')
    return {
        'commit_sha':commit,
        'tree_sha':tree,
        'branch':branch,
        'worktree_clean': status == '' if status is not None else None,
        'status_sha256': hashlib.sha256((status or '').encode('utf-8')).hexdigest() if status is not None else None,
    }


def _capsule_subjects(results:list[dict])->list[dict[str,Any]]:
    subjects=[]
    for result in results:
        if result.get('level_id')!='S09':continue
        for finding in result.get('findings',[]):
            if finding.get('id')!='capsule.security_gate.evidence':continue
            ev=finding.get('evidence') if isinstance(finding.get('evidence'),dict) else {}
            subject=ev.get('subject')
            if isinstance(subject,dict):subjects.append(subject)
    return subjects


def build_release_subject(*,target_root:Path,results:list[dict],cfg:dict[str,Any])->tuple[dict[str,Any],list[str]]:
    """Backward-compatible view over ReleaseSet v1.

    New code should consume ``assurance.release_set.build_release_set`` directly.
    ``subject_sha256`` remains as a compatibility alias for ``release_set_digest``.
    """
    from assurance.release_set import build_release_set
    release_set,issues=build_release_set(target_root=target_root,results=results,cfg=cfg)
    identity=release_set.get('identity',{}) if isinstance(release_set.get('identity'),dict) else {}
    source=release_set.get('source',{}) if isinstance(release_set.get('source'),dict) else {}
    compatibility={
        'schema':'konnaxiondiag.release-subject.v2',
        'release_set':release_set,
        'release_set_digest':release_set.get('release_set_digest'),
        'subject_sha256':release_set.get('release_set_digest'),
        'evidence_set_sha256':release_set.get('security_evidence_set_digest'),
        'effective_security_policy_sha256':release_set.get('qualification_policy_digest'),
        'security_contract_registry_sha256':release_set.get('security_contract_registry_digest'),
        'capsule_subjects':release_set.get('capsule_subjects',[]),
        'source':{
            'commit_sha':source.get('source_commit_sha'),
            'tree_sha':str(source.get('source_tree_digest') or '').removeprefix('git-sha1:') or None,
            'branch':source.get('source_branch'),
            'worktree_clean':source.get('worktree_clean'),
            'status_sha256':source.get('worktree_status_sha256'),
        },
    }
    return compatibility,issues

def parse_time(value:Any)->datetime|None:
    text=str(value or '').strip()
    if not text:return None
    if text.endswith('Z'):text=text[:-1]+'+00:00'
    try:
        dt=datetime.fromisoformat(text)
        if dt.tzinfo is None:dt=dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:return None


def temporal_attestation_check(payload:dict[str,Any],*,issued_field:str='issued_at',expires_field:str='expires_at',max_age_seconds:int|None=None,now:datetime|None=None)->tuple[bool,dict[str,Any]]:
    now=now or datetime.now(timezone.utc)
    issued=parse_time(payload.get(issued_field));expires=parse_time(payload.get(expires_field))
    problems=[]
    if issued is None:problems.append(f'{issued_field} missing or invalid')
    else:
        if issued>now:problems.append(f'{issued_field} is in the future')
        if max_age_seconds is not None and (now-issued).total_seconds()>max_age_seconds:
            problems.append('attestation is older than the allowed maximum age')
    if payload.get(expires_field) is not None:
        if expires is None:problems.append(f'{expires_field} invalid')
        elif expires<=now:problems.append('attestation has expired')
        elif issued is not None and expires<=issued:problems.append('attestation expires before or at issuance')
    return not problems,{
        'issued_at':issued.isoformat() if issued else None,
        'expires_at':expires.isoformat() if expires else None,
        'max_age_seconds':max_age_seconds,
        'problems':problems,
    }


def resolve_trusted_public_keys(raw:Any,*,base:Path)->list[Path]:
    if raw is None:return []
    values=raw if isinstance(raw,(list,tuple)) else [raw]
    out=[]
    for item in values:
        value=item.get('path') if isinstance(item,dict) else item
        text=str(value or '').strip()
        if not text:continue
        p=Path(text).expanduser();p=p if p.is_absolute() else (base/p).resolve(strict=False)
        if p.is_file():out.append(p)
    return out


def verify_signed_attestation(payload:dict[str,Any],envelope:dict[str,Any]|None,*,purpose:str,public_keys:Iterable[Path],signature_required:bool=True)->tuple[bool,dict[str,Any]]:
    keys=list(public_keys)
    if not signature_required and not envelope:
        return True,{'required':False,'status':'UNSIGNED_ALLOWED','trusted_key_count':len(keys)}
    if not envelope:
        return False,{'required':signature_required,'status':'MISSING','reason':'signature envelope missing','trusted_key_count':len(keys)}
    if not keys:
        return False,{'required':signature_required,'status':'UNVERIFIABLE','reason':'no trusted public keys configured','trusted_key_count':0}
    ok,detail=verify_evidence(payload,envelope,keys,purpose=purpose)
    detail.update({'required':signature_required,'status':'VERIFIED' if ok else 'INVALID'})
    return ok,detail


def finding_fingerprint(level_id:str,finding:dict[str,Any])->str:
    """Stable fingerprint for the semantics of a WARN being accepted.

    Runtime evidence is intentionally excluded because timestamps/paths can vary; the
    acceptance is invalidated when the finding id/category/message semantics change.
    """
    basis={
        'level_id':str(level_id or ''),
        'finding_id':str(finding.get('id','')),
        'category':str(finding.get('category','')),
        'message':str(finding.get('message','')),
    }
    return 'sha256:'+sha256_json(basis)


def validate_warning_disposition(
    value:Any,*,policy:dict[str,Any]|None=None,subject_sha256:str|None=None,
    release_set_digest:str|None=None,finding_fingerprint_value:str|None=None,
    policy_version:str|None=None,target_root:Path|None=None,now:datetime|None=None
)->tuple[bool,dict[str,Any]]:
    policy=policy or {};now=now or datetime.now(timezone.utc)
    release_set_digest=release_set_digest or subject_sha256
    if isinstance(value,str):
        if policy.get('require_metadata',False):return False,{'reason':'structured risk acceptance metadata required'}
        return bool(value.strip()),{'legacy':True,'reason':'legacy textual disposition' if value.strip() else 'empty disposition'}
    if not isinstance(value,dict):return False,{'reason':'risk acceptance is not an object'}
    status=str(value.get('status','accepted')).strip().lower();rationale=str(value.get('rationale','')).strip()
    problems=[]
    if policy.get('require_schema',False) and value.get('schema')!='konnaxiondiag.risk-acceptance.v1':
        problems.append('risk acceptance schema missing or invalid')
    if status not in {'accepted','approved','risk-accepted'}:problems.append('status is not an accepted risk state')
    if not rationale:problems.append('rationale missing')

    approved_raw=value.get('approved_by',[])
    if isinstance(approved_raw,str):approved=[approved_raw] if approved_raw.strip() else []
    elif isinstance(approved_raw,list):approved=[str(x).strip() for x in approved_raw if str(x).strip()]
    else:approved=[]
    approved=list(dict.fromkeys(approved))
    requested_by=str(value.get('requested_by','')).strip()
    if policy.get('require_metadata',False):
        if policy.get('require_schema',False) or policy.get('require_approval_identity',False):
            if not str(value.get('approval_id','')).strip():problems.append('approval_id missing')
            if not requested_by:problems.append('requested_by missing')
        if not approved:problems.append('approved_by missing')
        if parse_time(value.get('approved_at')) is None:problems.append('approved_at missing or invalid')
    default_min=1 if policy.get('require_metadata',False) else 0
    min_approvals=int(policy.get('min_approvals',default_min) or 0)
    if len(approved)<min_approvals:problems.append(f'at least {min_approvals} distinct approver(s) required')
    if policy.get('require_requester_separation',False) and requested_by and requested_by in approved:
        problems.append('requester cannot approve their own risk acceptance')

    if policy.get('require_expiry',False):
        expiry=parse_time(value.get('expires_at'))
        if expiry is None:problems.append('expires_at missing or invalid')
        elif expiry<=now:problems.append('risk acceptance expired')
    scope=value.get('scope') if isinstance(value.get('scope'),dict) else {}
    if policy.get('require_subject_binding',False):
        bound=str(scope.get('release_set_digest') or scope.get('release_subject_sha256') or '').strip()
        if not release_set_digest or bound!=release_set_digest:problems.append('risk acceptance is not bound to this ReleaseSet')
    if policy.get('require_finding_binding',False):
        bound_fp=str(scope.get('finding_fingerprint','')).strip()
        if not finding_fingerprint_value or bound_fp!=finding_fingerprint_value:
            problems.append('risk acceptance is not bound to this finding fingerprint')
    if policy.get('require_policy_version',False):
        actual=str(value.get('policy_version','')).strip()
        if not actual:problems.append('policy_version missing')
        elif policy_version and actual!=policy_version:problems.append('policy_version mismatch')

    signature_detail=None
    if policy.get('require_signature',False):
        signature=value.get('signature') if isinstance(value.get('signature'),dict) else None
        unsigned={k:v for k,v in value.items() if k!='signature'}
        base=target_root or Path.cwd()
        keys=resolve_trusted_public_keys(policy.get('trusted_public_keys'),base=base)
        sig_ok,signature_detail=verify_signed_attestation(unsigned,signature,purpose=WARN_DISPOSITION_PURPOSE,public_keys=keys,signature_required=True)
        if not sig_ok:problems.append('risk acceptance signature is not trusted/valid')
    return not problems,{
        'problems':problems,'signature':signature_detail,'approved_by':approved,
        'requested_by':requested_by,'release_set_digest':release_set_digest,
        'finding_fingerprint':finding_fingerprint_value,
    }

