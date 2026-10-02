from __future__ import annotations
import base64,hashlib,json,os
from datetime import datetime,timezone
from pathlib import Path
from typing import Any

SIGNATURE_SCHEMA='konnaxiondiag.release-signature.v1'
SIGNATURE_PURPOSE='konnaxiondiag-release-verdict'
PREFIX=b'KONNAXIONDIAG-RELEASE-VERDICT-V1\n'

def canonical_bytes(payload:dict[str,Any])->bytes:
    return json.dumps(payload,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode('utf-8')

def payload_bytes(payload:dict[str,Any])->bytes:
    raw=canonical_bytes(payload);return PREFIX+hashlib.sha256(raw).hexdigest().encode('ascii')+b'\n'+raw

def sign_payload(payload:dict[str,Any],private_key_file:Path,password:bytes|None=None)->dict[str,Any]:
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except Exception as exc:
        raise RuntimeError('cryptography with Ed25519 support is required for release signing') from exc
    key=serialization.load_pem_private_key(private_key_file.read_bytes(),password=password)
    if not isinstance(key,Ed25519PrivateKey):raise RuntimeError('release signing key must be Ed25519')
    signed=payload_bytes(payload);sig=key.sign(signed)
    pub=key.public_key().public_bytes(encoding=serialization.Encoding.DER,format=serialization.PublicFormat.SubjectPublicKeyInfo)
    return {
      'schema':SIGNATURE_SCHEMA,'purpose':SIGNATURE_PURPOSE,'algorithm':'ed25519',
      'created_at':datetime.now(timezone.utc).isoformat(),
      'payload_sha256':hashlib.sha256(canonical_bytes(payload)).hexdigest(),
      'signature_base64':base64.b64encode(sig).decode('ascii'),
      'public_key_fingerprint_sha256':hashlib.sha256(pub).hexdigest(),
    }

def resolve_private_key(config,target_root:Path)->Path|None:
    env=os.environ.get('KDIAG_RELEASE_SIGNING_KEY','').strip()
    raw=env or str(config.get('release_gate',{}).get('signing',{}).get('private_key_file','') or '').strip()
    if not raw:return None
    p=Path(raw).expanduser();return p if p.is_absolute() else (target_root/p).resolve(strict=False)

def verify_payload(payload:dict[str,Any],envelope:dict[str,Any],public_key_file:Path)->bool:
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        key=serialization.load_pem_public_key(public_key_file.read_bytes())
        if not isinstance(key,Ed25519PublicKey):return False
        if envelope.get('payload_sha256')!=hashlib.sha256(canonical_bytes(payload)).hexdigest():return False
        key.verify(base64.b64decode(envelope['signature_base64']),payload_bytes(payload));return True
    except Exception:return False
