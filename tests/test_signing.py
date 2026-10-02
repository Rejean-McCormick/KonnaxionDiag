import json,tempfile
from pathlib import Path
import pytest
from diagcore.signing import sign_payload,verify_payload

def test_ed25519_detached_signature_covers_exact_payload():
    crypto=pytest.importorskip('cryptography.hazmat.primitives.asymmetric.ed25519')
    from cryptography.hazmat.primitives import serialization
    private=crypto.Ed25519PrivateKey.generate();public=private.public_key()
    with tempfile.TemporaryDirectory() as td:
        td=Path(td);priv=td/'priv.pem';pub=td/'pub.pem'
        priv.write_bytes(private.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
        pub.write_bytes(public.public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
        payload={'schema':'x','verdict':'PASS','signature':{'status':'SIGNED'}}
        env=sign_payload(payload,priv);assert verify_payload(payload,env,pub)
        payload['verdict']='BLOCKED';assert not verify_payload(payload,env,pub)
