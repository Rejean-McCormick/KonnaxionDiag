import json,tempfile
from pathlib import Path
from diagcore.release_gate import build_final_release_verdict

def _result(level,verdict,findings=None):return {'level_id':level,'level_name':level,'verdict':verdict,'findings':findings or []}

def test_undispositioned_security_warn_blocks_release():
    results=[_result('N00','PASS'),_result('S04W','WARN',[{'id':'web.warn','verdict':'WARN','message':'review'}]),_result('S14','PASS')]
    cfg={'release_gate':{'signing':{'required':False},'security_warn_dispositions':{}}}
    with tempfile.TemporaryDirectory() as td:
        out=build_final_release_verdict(campaign='release-all',run_id='r1',target_root=Path(td),results=results,cfg=cfg,correlation={'verdict':'PASS','chains':[]},out_dir=Path(td))
        assert out['verdict']=='BLOCKED';assert out['security']['unresolved_warnings'][0]['finding_id']=='web.warn'

def test_dispositioned_security_warn_is_accepted():
    results=[_result('N00','PASS'),_result('S04W','WARN',[{'id':'web.warn','verdict':'WARN','message':'review'}]),_result('S14','PASS')]
    cfg={'release_gate':{'signing':{'required':False},'security_warn_dispositions':{'web.warn':{'status':'accepted','rationale':'temporary reviewed exception'}}}}
    with tempfile.TemporaryDirectory() as td:
        out=build_final_release_verdict(campaign='release-all',run_id='r1',target_root=Path(td),results=results,cfg=cfg,correlation={'verdict':'PASS','chains':[]},out_dir=Path(td))
        assert out['verdict']=='PASS';assert out['security']['unresolved_warnings']==[]

def test_release_gate_writes_verifiable_detached_signature():
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization
    except Exception:
        return
    from diagcore.signing import verify_payload
    private=Ed25519PrivateKey.generate();public=private.public_key()
    with tempfile.TemporaryDirectory() as td:
        td=Path(td);priv=td/'release-private.pem';pub=td/'release-public.pem'
        priv.write_bytes(private.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
        pub.write_bytes(public.public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
        results=[_result('N00','PASS'),_result('S14','PASS')]
        cfg={'release_gate':{'signing':{'required':True,'private_key_file':str(priv)},'security_warn_dispositions':{}}}
        out=build_final_release_verdict(campaign='release-all',run_id='r2',target_root=td,results=results,cfg=cfg,correlation={'verdict':'PASS','chains':[]},out_dir=td)
        envelope=json.loads((td/'release-verdict.sig').read_text())
        persisted=json.loads((td/'release-verdict.json').read_text())
        assert out['verdict']=='PASS';assert persisted['signature']['status']=='SIGNED';assert verify_payload(persisted,envelope,pub)
