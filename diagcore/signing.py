from __future__ import annotations
import base64,hashlib,json,os
from datetime import datetime,timezone
from pathlib import Path
from typing import Any,Iterable

SIGNATURE_SCHEMA='konnaxiondiag.release-signature.v1'
SIGNATURE_PURPOSE='konnaxiondiag-release-verdict'
PREFIX=b'KONNAXIONDIAG-RELEASE-VERDICT-V1\n'
ATTESTATION_SCHEMA='konnaxiondiag.detached-signature.v1'


def canonical_bytes(payload:dict[str,Any])->bytes:
    return json.dumps(payload,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode('utf-8')


def payload_bytes(payload:dict[str,Any])->bytes:
    raw=canonical_bytes(payload);return PREFIX+hashlib.sha256(raw).hexdigest().encode('ascii')+b'\n'+raw


def purpose_bytes(payload:dict[str,Any],purpose:str)->bytes:
    """Domain-separated bytes for signed evidence other than the final release verdict."""
    normalized=str(purpose).strip()
    if not normalized or any(ch in normalized for ch in '\r\n\x00'):
        raise ValueError('signature purpose is missing or unsafe')
    raw=canonical_bytes(payload)
    prefix=f'KONNAXIONDIAG-SIGNED-EVIDENCE-V1:{normalized}\n'.encode('utf-8')
    return prefix+hashlib.sha256(raw).hexdigest().encode('ascii')+b'\n'+raw


def _load_private_key(private_key_file:Path,password:bytes|None=None):
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except Exception as exc:
        raise RuntimeError('cryptography with Ed25519 support is required for signing') from exc
    key=serialization.load_pem_private_key(private_key_file.read_bytes(),password=password)
    if not isinstance(key,Ed25519PrivateKey):raise RuntimeError('signing key must be Ed25519')
    return key


def _public_fingerprint(key)->str:
    from cryptography.hazmat.primitives import serialization
    pub=key.public_bytes(encoding=serialization.Encoding.DER,format=serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(pub).hexdigest()


def sign_payload(payload:dict[str,Any],private_key_file:Path,password:bytes|None=None)->dict[str,Any]:
    key=_load_private_key(private_key_file,password)
    signed=payload_bytes(payload);sig=key.sign(signed)
    return {
      'schema':SIGNATURE_SCHEMA,'purpose':SIGNATURE_PURPOSE,'algorithm':'ed25519',
      'created_at':datetime.now(timezone.utc).isoformat(),
      'payload_sha256':hashlib.sha256(canonical_bytes(payload)).hexdigest(),
      'signature_base64':base64.b64encode(sig).decode('ascii'),
      'public_key_fingerprint_sha256':_public_fingerprint(key.public_key()),
    }


def sign_evidence(payload:dict[str,Any],private_key_file:Path,*,purpose:str,password:bytes|None=None,key_id:str|None=None)->dict[str,Any]:
    """Create a domain-separated detached Ed25519 signature for an attestation/evidence object."""
    key=_load_private_key(private_key_file,password)
    sig=key.sign(purpose_bytes(payload,purpose))
    envelope={
      'schema':ATTESTATION_SCHEMA,'purpose':purpose,'algorithm':'ed25519',
      'created_at':datetime.now(timezone.utc).isoformat(),
      'payload_sha256':hashlib.sha256(canonical_bytes(payload)).hexdigest(),
      'signature_base64':base64.b64encode(sig).decode('ascii'),
      'public_key_fingerprint_sha256':_public_fingerprint(key.public_key()),
    }
    if key_id:envelope['key_id']=str(key_id)
    return envelope


def resolve_private_key(config,target_root:Path)->Path|None:
    env=os.environ.get('KDIAG_RELEASE_SIGNING_KEY','').strip()
    raw=env or str(config.get('release_gate',{}).get('signing',{}).get('private_key_file','') or '').strip()
    if not raw:return None
    p=Path(raw).expanduser();return p if p.is_absolute() else (target_root/p).resolve(strict=False)


def _load_public_key(public_key_file:Path):
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        key=serialization.load_pem_public_key(public_key_file.read_bytes())
        return key if isinstance(key,Ed25519PublicKey) else None
    except Exception:return None


def verify_payload(payload:dict[str,Any],envelope:dict[str,Any],public_key_file:Path)->bool:
    try:
        key=_load_public_key(public_key_file)
        if key is None:return False
        if envelope.get('purpose') not in {None,SIGNATURE_PURPOSE}:return False
        if envelope.get('payload_sha256')!=hashlib.sha256(canonical_bytes(payload)).hexdigest():return False
        key.verify(base64.b64decode(envelope['signature_base64'],validate=True),payload_bytes(payload));return True
    except Exception:return False


def verify_evidence(payload:dict[str,Any],envelope:dict[str,Any],public_key_files:Iterable[Path],*,purpose:str)->tuple[bool,dict[str,Any]]:
    """Verify detached signed evidence against one of the explicitly trusted Ed25519 public keys."""
    detail={'purpose':purpose,'trusted_key_count':0,'matched_fingerprint':None,'reason':None}
    if not isinstance(envelope,dict):
        detail['reason']='signature envelope missing';return False,detail
    if envelope.get('algorithm')!='ed25519':
        detail['reason']='unsupported signature algorithm';return False,detail
    if envelope.get('purpose')!=purpose:
        detail['reason']='signature purpose/domain mismatch';return False,detail
    expected_hash=hashlib.sha256(canonical_bytes(payload)).hexdigest()
    if envelope.get('payload_sha256')!=expected_hash:
        detail['reason']='payload digest mismatch';return False,detail
    try:signature=base64.b64decode(str(envelope.get('signature_base64','')),validate=True)
    except Exception:
        detail['reason']='invalid signature encoding';return False,detail
    wanted=str(envelope.get('public_key_fingerprint_sha256','')).lower().strip()
    for path in public_key_files:
        key=_load_public_key(path)
        if key is None:continue
        detail['trusted_key_count']+=1
        fp=_public_fingerprint(key).lower()
        if wanted and fp!=wanted:continue
        try:
            key.verify(signature,purpose_bytes(payload,purpose))
            detail['matched_fingerprint']=fp;detail['reason']='verified';return True,detail
        except Exception:continue
    detail['reason']='no trusted key verified the signature'
    return False,detail
