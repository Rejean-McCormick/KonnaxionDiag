import json
import subprocess
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from assurance.attestation import attestation_purpose, validate_universal_attestation
from assurance.pep import verify_release_authorization
from assurance.release_set import build_release_set, validate_release_set
from diagcore.assurance import WARN_DISPOSITION_PURPOSE, finding_fingerprint, validate_warning_disposition
from diagcore.release_gate import build_final_release_verdict
from diagcore.signing import sign_evidence


def _keys(td: Path):
    crypto = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ed25519")
    from cryptography.hazmat.primitives import serialization
    private = crypto.Ed25519PrivateKey.generate(); public = private.public_key()
    priv = td / "priv.pem"; pub = td / "pub.pem"
    priv.write_bytes(private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    pub.write_bytes(public.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    return priv, pub


def _git_repo(td: Path):
    if subprocess.run(["git", "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode:
        pytest.skip("git unavailable")
    subprocess.run(["git", "init", "-q"], cwd=td, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.test"], cwd=td, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=td, check=True)
    (td / "app.txt").write_text("app-v1")
    (td / "policy.json").write_text('{"allow":true}')
    subprocess.run(["git", "add", "."], cwd=td, check=True)
    subprocess.run(["git", "commit", "-qm", "init"], cwd=td, check=True)


def _release_cfg(root: Path):
    return {
        "_tool_root": str(Path(__file__).resolve().parents[1]),
        "release_set": {
            "required": True,
            "require_git_identity": True,
            "require_clean_worktree": False,
            "required_components": ["source", "policy_bundle"],
            "components": {"policy_bundle": ["policy.json"]},
        },
        "release_gate": {
            "subject_binding": {"required": True, "require_git_identity": True, "require_clean_worktree": False},
            "authorization": {"policy_version": "policy-v1", "ttl_seconds": 3600},
            "signing": {"required": False},
            "security_warn_dispositions": {},
        },
    }


def test_release_set_binds_artifact_bytes_but_not_evidence_bytes():
    with tempfile.TemporaryDirectory() as raw:
        td = Path(raw); _git_repo(td); cfg = _release_cfg(td)
        r1 = [{"level_id": "S01", "verdict": "PASS", "ended_at": "one"}]
        rs1, issues1 = build_release_set(target_root=td, results=r1, cfg=cfg)
        assert not issues1
        r2 = [{"level_id": "S01", "verdict": "PASS", "ended_at": "two"}]
        rs2, issues2 = build_release_set(target_root=td, results=r2, cfg=cfg)
        assert not issues2
        assert rs1["release_set_digest"] == rs2["release_set_digest"]
        assert rs1["security_evidence_set_digest"] != rs2["security_evidence_set_digest"]
        cfg_changed=json.loads(json.dumps(cfg));cfg_changed["release_gate"]["authorization"]["ttl_seconds"]=7200
        rs_policy,_=build_release_set(target_root=td,results=r2,cfg=cfg_changed)
        assert rs_policy["release_set_digest"] == rs2["release_set_digest"]
        assert rs_policy["qualification_policy_digest"] != rs2["qualification_policy_digest"]
        (td / "policy.json").write_text('{"allow":false}')
        rs3, _ = build_release_set(target_root=td, results=r2, cfg=cfg)
        assert rs3["release_set_digest"] != rs2["release_set_digest"]


def test_universal_attestation_is_subject_policy_and_signature_bound():
    with tempfile.TemporaryDirectory() as raw:
        td = Path(raw); priv, pub = _keys(td); now = datetime.now(timezone.utc)
        subject = "sha256:" + "a" * 64
        payload = {
            "schema": "konnaxiondiag.attestation.v1",
            "issuer": "konfid-assurance",
            "subject": {"release_set_digest": subject},
            "evidence_type": "security.contract.SEC-01",
            "status": "PASS",
            "issued_at": now.isoformat(),
            "expires_at": (now + timedelta(hours=1)).isoformat(),
            "policy_digest": "sha256:" + "b" * 64,
            "evidence_digest": "sha256:" + "c" * 64,
            "nonce": "nonce-1234567890abcdef",
            "statement": {"contract_id": "SEC-01"},
        }
        env = sign_evidence(payload, priv, purpose=attestation_purpose(payload["evidence_type"]))
        ok, detail = validate_universal_attestation(
            payload, env, public_keys=[pub], expected_release_set_digest=subject,
            expected_evidence_type="security.contract.SEC-01", expected_issuers=["konfid-assurance"],
            expected_policy_digest=payload["policy_digest"], max_age_seconds=3600,
        )
        assert ok, detail
        bad = dict(payload); bad["subject"] = {"release_set_digest": "sha256:" + "d" * 64}
        ok, _ = validate_universal_attestation(
            bad, env, public_keys=[pub], expected_release_set_digest=subject,
            expected_evidence_type="security.contract.SEC-01", expected_issuers=["konfid-assurance"], max_age_seconds=3600,
        )
        assert not ok


def test_pep_denies_different_release_set_even_with_caller_skip_hint():
    with tempfile.TemporaryDirectory() as raw:
        td = Path(raw); _git_repo(td); priv, pub = _keys(td); cfg = _release_cfg(td)
        cfg["release_gate"]["signing"] = {"required": True, "private_key_file": str(priv)}
        results = [{"level_id": "N00", "verdict": "PASS", "findings": []}, {"level_id": "S14", "verdict": "PASS", "findings": []}]
        verdict = build_final_release_verdict(campaign="release-all", run_id="r42", target_root=td, results=results, cfg=cfg, correlation={"verdict": "PASS", "chains": []}, out_dir=td)
        assert verdict["verdict"] == "PASS"
        sig = json.loads((td / "release-verdict.sig").read_text())
        active = json.loads((td / "release-set.json").read_text())
        verdict["request"] = {"run_security_gate": False}  # caller hint cannot disable verifier
        # Because the verdict was altered after signing, this already fails closed.
        ok, _ = verify_release_authorization(verdict, sig, trusted_public_keys=[pub], active_release_set=active, expected_policy_version="policy-v1")
        assert not ok
        # Untampered authorization admits exact release.
        verdict = json.loads((td / "release-verdict.json").read_text())
        ok, detail = verify_release_authorization(verdict, sig, trusted_public_keys=[pub], active_release_set=active, expected_policy_version="policy-v1")
        assert ok, detail
        tampered = json.loads(json.dumps(active)); tampered["identity"]["policy_bundle_digest"] = "sha256:" + "f" * 64
        # Even if an attacker forgets to update the digest, canonical validation catches it.
        ok, _ = verify_release_authorization(verdict, sig, trusted_public_keys=[pub], active_release_set=tampered, expected_policy_version="policy-v1")
        assert not ok


def test_pep_denies_expired_authorization():
    with tempfile.TemporaryDirectory() as raw:
        td = Path(raw); _git_repo(td); priv, pub = _keys(td); cfg = _release_cfg(td)
        cfg["release_gate"]["signing"] = {"required": True, "private_key_file": str(priv)}
        cfg["release_gate"]["authorization"]["ttl_seconds"] = 1
        results = [{"level_id": "N00", "verdict": "PASS", "findings": []}, {"level_id": "S14", "verdict": "PASS", "findings": []}]
        build_final_release_verdict(campaign="release-all", run_id="r-exp", target_root=td, results=results, cfg=cfg, correlation={"verdict": "PASS", "chains": []}, out_dir=td)
        verdict=json.loads((td/"release-verdict.json").read_text()); sig=json.loads((td/"release-verdict.sig").read_text()); rs=json.loads((td/"release-set.json").read_text())
        expires=datetime.fromisoformat(verdict["authorization"]["expires_at"])
        ok,_=verify_release_authorization(verdict,sig,trusted_public_keys=[pub],active_release_set=rs,now=expires+timedelta(seconds=1))
        assert not ok


def test_risk_acceptance_binds_release_finding_and_separates_requester():
    with tempfile.TemporaryDirectory() as raw:
        td=Path(raw);priv,pub=_keys(td);now=datetime.now(timezone.utc)
        finding={"id":"web.warn","verdict":"WARN","category":"web","message":"review"};fp=finding_fingerprint("S04W",finding);subject="sha256:"+"a"*64
        value={
            "schema":"konnaxiondiag.risk-acceptance.v1","status":"accepted","rationale":"reviewed temporary exception",
            "requested_by":"engineer@example.test","approved_by":["security@example.test"],"approval_id":"RA-001",
            "approved_at":now.isoformat(),"expires_at":(now+timedelta(hours=1)).isoformat(),"policy_version":"policy-v1",
            "scope":{"release_set_digest":subject,"finding_fingerprint":fp},
        }
        value["signature"]=sign_evidence(value,priv,purpose=WARN_DISPOSITION_PURPOSE)
        policy={"require_schema":True,"require_metadata":True,"require_expiry":True,"require_subject_binding":True,"require_finding_binding":True,"require_policy_version":True,"require_signature":True,"min_approvals":1,"require_requester_separation":True,"trusted_public_keys":[str(pub)]}
        ok,detail=validate_warning_disposition(value,policy=policy,release_set_digest=subject,finding_fingerprint_value=fp,policy_version="policy-v1",target_root=td,now=now)
        assert ok,detail
        value["scope"]["finding_fingerprint"]="sha256:"+"b"*64
        ok,_=validate_warning_disposition(value,policy=policy,release_set_digest=subject,finding_fingerprint_value=fp,policy_version="policy-v1",target_root=td,now=now)
        assert not ok


def test_security_contract_registry_consumes_universal_attestation():
    from diagcore.contracts import evaluate_security_contracts
    with tempfile.TemporaryDirectory() as raw:
        td=Path(raw);priv,pub=_keys(td);evidence_dir=td/'attestations'/'security-contracts';evidence_dir.mkdir(parents=True)
        release_set={
            'schema':'konnaxiondiag.release-set.v1',
            'identity':{'schema':'konnaxiondiag.release-set.identity.v1','image_digests':[]},
            'release_set_digest':'sha256:'+'a'*64,
            'complete':True,
        }
        now=datetime.now(timezone.utc)
        payload={
            'schema':'konnaxiondiag.attestation.v1','issuer':'konfid-assurance',
            'subject':{'release_set_digest':release_set['release_set_digest']},
            'evidence_type':'security.contract.SEC-01','status':'PASS',
            'issued_at':now.isoformat(),'expires_at':(now+timedelta(hours=1)).isoformat(),
            'policy_digest':'sha256:'+'b'*64,'evidence_digest':'sha256:'+'c'*64,
            'nonce':'nonce-1234567890abcdef','statement':{'contract_id':'SEC-01'},
        }
        env=sign_evidence(payload,priv,purpose=attestation_purpose(payload['evidence_type']))
        (evidence_dir/'SEC-01.json').write_text(json.dumps(payload));(evidence_dir/'SEC-01.json.sig').write_text(json.dumps(env))
        root=Path(__file__).resolve().parents[1]
        cfg={'_tool_root':str(root),'_target_root':str(td),'security_assurance':{
            'enabled':True,'required_contracts':['SEC-01'],'evidence_dir':'attestations/security-contracts',
            'signature_required':True,'trusted_public_keys_by_contract':{'SEC-01':[str(pub)]},
            'trusted_issuers_by_contract':{'SEC-01':['konfid-assurance']},'max_age_seconds':3600,
            'allow_global_trust_fallback':False,'accept_legacy_attestations':False,
        }}
        ok,detail=evaluate_security_contracts(cfg=cfg,results=[],release_set=release_set,subject_ok=True)
        assert ok,detail
