import json,subprocess,tempfile
from datetime import datetime,timedelta,timezone
from pathlib import Path
import pytest

from diagcore.assurance import (
    WARN_DISPOSITION_PURPOSE,build_release_subject,temporal_attestation_check,
    validate_warning_disposition,verify_signed_attestation,
)
from diagcore.release_gate import build_final_release_verdict
from diagcore.signing import sign_evidence


def _keys(td:Path):
    crypto=pytest.importorskip('cryptography.hazmat.primitives.asymmetric.ed25519')
    from cryptography.hazmat.primitives import serialization
    private=crypto.Ed25519PrivateKey.generate();public=private.public_key()
    priv=td/'priv.pem';pub=td/'pub.pem'
    priv.write_bytes(private.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    pub.write_bytes(public.public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
    return priv,pub


def test_domain_separated_evidence_signature_rejects_wrong_purpose():
    with tempfile.TemporaryDirectory() as td:
        td=Path(td);priv,pub=_keys(td);payload={'status':'PASS','issued_at':datetime.now(timezone.utc).isoformat()}
        env=sign_evidence(payload,priv,purpose='purpose-a')
        ok,_=verify_signed_attestation(payload,env,purpose='purpose-a',public_keys=[pub]);assert ok
        ok,_=verify_signed_attestation(payload,env,purpose='purpose-b',public_keys=[pub]);assert not ok


def test_temporal_attestation_rejects_stale_evidence():
    now=datetime.now(timezone.utc)
    payload={'issued_at':(now-timedelta(hours=2)).isoformat()}
    ok,detail=temporal_attestation_check(payload,max_age_seconds=60,now=now)
    assert not ok;assert detail['problems']


def test_strong_warning_disposition_is_signed_expiring_and_subject_bound():
    with tempfile.TemporaryDirectory() as td:
        td=Path(td);priv,pub=_keys(td);now=datetime.now(timezone.utc);subject='a'*64
        disposition={
            'status':'accepted','rationale':'time-bounded reviewed exception','approved_by':'security@example.test',
            'approved_at':now.isoformat(),'expires_at':(now+timedelta(hours=1)).isoformat(),
            'scope':{'release_subject_sha256':subject},
        }
        disposition['signature']=sign_evidence(disposition,priv,purpose=WARN_DISPOSITION_PURPOSE)
        policy={'require_metadata':True,'require_expiry':True,'require_subject_binding':True,'require_signature':True,'trusted_public_keys':[str(pub)]}
        ok,detail=validate_warning_disposition(disposition,policy=policy,subject_sha256=subject,target_root=td,now=now)
        assert ok,detail
        disposition['scope']['release_subject_sha256']='b'*64
        ok,_=validate_warning_disposition(disposition,policy=policy,subject_sha256=subject,target_root=td,now=now)
        assert not ok


def test_release_subject_requires_clean_git_and_is_stable_across_evidence_timestamps():
    if subprocess.run(['git','--version'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode:
        pytest.skip('git unavailable')
    with tempfile.TemporaryDirectory() as td:
        td=Path(td);subprocess.run(['git','init','-q'],cwd=td,check=True)
        subprocess.run(['git','config','user.email','test@example.test'],cwd=td,check=True)
        subprocess.run(['git','config','user.name','Test'],cwd=td,check=True)
        (td/'a.txt').write_text('x')
        subprocess.run(['git','add','.'],cwd=td,check=True);subprocess.run(['git','commit','-qm','init'],cwd=td,check=True)
        cfg={'release_gate':{'subject_binding':{'required':True,'require_git_identity':True,'require_clean_worktree':True},'security_warn_dispositions':{}}}
        s1,issues=build_release_subject(target_root=td,results=[{'level_id':'S01','verdict':'PASS','ended_at':'one'}],cfg=cfg)
        assert not issues
        s2,_=build_release_subject(target_root=td,results=[{'level_id':'S01','verdict':'PASS','ended_at':'two'}],cfg=cfg)
        assert s1['subject_sha256']==s2['subject_sha256']
        assert s1['evidence_set_sha256']!=s2['evidence_set_sha256']
        (td/'a.txt').write_text('changed')
        _,issues=build_release_subject(target_root=td,results=[],cfg=cfg)
        assert issues


def test_target_mutation_protection_is_inside_signed_release_decision():
    results=[{'level_id':'N00','verdict':'PASS','findings':[]},{'level_id':'S14','verdict':'PASS','findings':[]}]
    cfg={'release_gate':{'signing':{'required':False},'subject_binding':{'required':False},'security_warn_dispositions':{}}}
    with tempfile.TemporaryDirectory() as td:
        td=Path(td)
        out=build_final_release_verdict(campaign='release-all',run_id='r',target_root=td,results=results,cfg=cfg,correlation={'verdict':'PASS','chains':[]},out_dir=td,target_protection={'verdict':'ERROR','message':'mutated'})
        assert out['verdict']=='BLOCKED'
        assert out['target_protection']['verdict']=='ERROR'

from diagcore.contracts import CONTRACT_ATTESTATION_PURPOSE_PREFIX,evaluate_security_contracts,load_contract_registry


def test_security_contract_registry_contains_all_53_codex_patterns():
    root=Path(__file__).resolve().parents[1]
    registry=load_contract_registry(root)
    ids=[x['id'] for x in registry['contracts']]
    assert ids[0]=='SEC-01' and ids[-1]=='SEC-53' and len(ids)==53


def test_external_security_contract_requires_trusted_subject_bound_signature():
    root=Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory() as td:
        td=Path(td);priv,pub=_keys(td);evidence_dir=td/'attestations'/'security-contracts';evidence_dir.mkdir(parents=True)
        subject={'subject_sha256':'c'*64,'capsule_subjects':[]}
        now=datetime.now(timezone.utc)
        payload={
            'schema':'konnaxiondiag.security-contract-attestation.v1','contract_id':'SEC-01','status':'PASS',
            'issuer':'konfid-assurance','issued_at':now.isoformat(),'expires_at':(now+timedelta(hours=1)).isoformat(),
            'subject':{'release_subject_sha256':subject['subject_sha256']},'evidence_sha256':'d'*64,
        }
        env=sign_evidence(payload,priv,purpose=CONTRACT_ATTESTATION_PURPOSE_PREFIX+'SEC-01')
        (evidence_dir/'SEC-01.json').write_text(json.dumps(payload))
        (evidence_dir/'SEC-01.json.sig').write_text(json.dumps(env))
        cfg={'_tool_root':str(root),'_target_root':str(td),'security_assurance':{'enabled':True,'required_contracts':['SEC-01'],'evidence_dir':'attestations/security-contracts','signature_required':True,'trusted_public_keys':[str(pub)],'max_age_seconds':3600}}
        ok,detail=evaluate_security_contracts(cfg=cfg,results=[],release_subject=subject,subject_ok=True)
        assert ok,detail
        payload['subject']['release_subject_sha256']='e'*64
        (evidence_dir/'SEC-01.json').write_text(json.dumps(payload))
        ok,_=evaluate_security_contracts(cfg=cfg,results=[],release_subject=subject,subject_ok=True)
        assert not ok


def test_native_sec29_requires_both_immutable_images_and_signed_capsule_gate_findings():
    root=Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory() as td:
        td=Path(td)
        cfg={'_tool_root':str(root),'_target_root':str(td),'security_assurance':{'enabled':True,'required_contracts':['SEC-29']}}
        subject={'subject_sha256':'a'*64,'capsule_subjects':[{'instance_id':'i','image_digests':['sha256:x']} ]}
        results=[
          {'level_id':'S03','findings':[{'id':'supply_chain.container_images.immutable','verdict':'PASS'}]},
          {'level_id':'S09','findings':[{'id':'capsule.security_gate.evidence','verdict':'PASS'}]},
        ]
        ok,detail=evaluate_security_contracts(cfg=cfg,results=results,release_subject=subject,subject_ok=True)
        assert ok,detail
        results[1]['findings'][0]['verdict']='FAIL'
        ok,_=evaluate_security_contracts(cfg=cfg,results=results,release_subject=subject,subject_ok=True)
        assert not ok


def test_release_subject_ignores_internal_runner_paths():
    if subprocess.run(['git','--version'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode:
        pytest.skip('git unavailable')
    with tempfile.TemporaryDirectory() as td:
        td=Path(td);subprocess.run(['git','init','-q'],cwd=td,check=True)
        subprocess.run(['git','config','user.email','test@example.test'],cwd=td,check=True)
        subprocess.run(['git','config','user.name','Test'],cwd=td,check=True)
        (td/'a').write_text('x');subprocess.run(['git','add','.'],cwd=td,check=True);subprocess.run(['git','commit','-qm','init'],cwd=td,check=True)
        base={'release_gate':{'subject_binding':{'require_git_identity':True,'require_clean_worktree':True},'security_warn_dispositions':{}},'security_assurance':{'enabled':True}}
        s1,_=build_release_subject(target_root=td,results=[],cfg=base)
        enriched={**base,'_tool_root':str(Path(__file__).resolve().parents[1]),'_target_root':str(td),'_run_root':str(td/'run')}
        s2,_=build_release_subject(target_root=td,results=[],cfg=enriched)
        assert s1['subject_sha256']==s2['subject_sha256']
