from __future__ import annotations
import argparse,json,os,sys
from pathlib import Path
from . import VERSION,REPORT_SCHEMA,SUMMARY_SCHEMA
from .config import ConfigError,load_config
from .manifest import ManifestError,load_manifest
from .runner import run_campaign,run_named_sequence
from .worker import run_worker
from .utils import read_json,write_json,log_line
from .signing import sign_evidence,verify_evidence
from assurance.attestation import attestation_purpose, validate_universal_attestation
from assurance.release_set import build_release_set
from assurance.pep import verify_release_authorization
from .assurance import WARN_DISPOSITION_PURPOSE
from .verdicts import exit_code

def parser():
    p=argparse.ArgumentParser(prog='kdiag',description='Konnaxion functional + security diagnostic framework')
    p.add_argument('--version',action='version',version=f'KonnaxionDiag {VERSION}')
    sub=p.add_subparsers(dest='cmd',required=True)
    sub.add_parser('doctor');sub.add_parser('list');sub.add_parser('triage-current')
    rs=sub.add_parser('run-sequence');rs.add_argument('sequence');rs.add_argument('--target')
    sc=sub.add_parser('show-config');sc.add_argument('--target')
    r=sub.add_parser('run');r.add_argument('selection');r.add_argument('--target');r.add_argument('--fail-fast',action='store_true')
    v=sub.add_parser('verify-run');v.add_argument('summary')
    se=sub.add_parser('sign-evidence',help='Sign a JSON evidence object with a domain-separated Ed25519 signature')
    se.add_argument('input');se.add_argument('--purpose',required=True);se.add_argument('--key',required=True);se.add_argument('--output',required=True);se.add_argument('--key-id')
    ve=sub.add_parser('verify-evidence',help='Verify a detached signed JSON evidence object')
    ve.add_argument('input');ve.add_argument('signature');ve.add_argument('--purpose',required=True);ve.add_argument('--public-key',action='append',required=True)
    sd=sub.add_parser('sign-disposition',help='Embed a signed approval envelope into a warning disposition JSON object')
    sd.add_argument('input');sd.add_argument('--key',required=True);sd.add_argument('--output',required=True);sd.add_argument('--key-id')
    sa=sub.add_parser('sign-attestation',help='Sign a konnaxiondiag.attestation.v1 using evidence_type domain separation')
    sa.add_argument('input');sa.add_argument('--key',required=True);sa.add_argument('--output',required=True);sa.add_argument('--key-id')
    va=sub.add_parser('verify-attestation',help='Verify a universal attestation against an exact ReleaseSet')
    va.add_argument('input');va.add_argument('signature');va.add_argument('--release-set',required=True);va.add_argument('--public-key',action='append',required=True);va.add_argument('--issuer',action='append');va.add_argument('--max-age-seconds',type=int,default=86400)
    br=sub.add_parser('build-release-set',help='Build the canonical ReleaseSet v1 for a target/current run')
    br.add_argument('--target');br.add_argument('--run-root');br.add_argument('--output')
    ad=sub.add_parser('verify-admission',help='PEP-side fail-closed verification of a signed release authorization')
    ad.add_argument('verdict');ad.add_argument('signature');ad.add_argument('release_set');ad.add_argument('--public-key',action='append',required=True);ad.add_argument('--allow-warn',action='store_true');ad.add_argument('--policy-version')
    w=sub.add_parser('_worker');w.add_argument('--level',required=True);w.add_argument('--run-id',required=True);w.add_argument('--output',required=True);w.add_argument('--target')
    return p

def main(argv=None):
    args=parser().parse_args(argv);root=Path(__file__).resolve().parents[1]
    try:
        if args.cmd=='doctor':
            m=load_manifest(root);cfg=load_config(root);print(f'KonnaxionDiag {VERSION}');print(f'Target: {cfg.target_root_path}');print(f'Control: {cfg.control_root_path}');print(f'Levels: {len(m["levels"])} (N={sum(x["profile"]=="levelup" for x in m["levels"])}, S={sum(x["profile"]=="security" for x in m["levels"])})');return 0
        if args.cmd=='list':
            m=load_manifest(root)
            for x in m['levels']:print(f"{x['id']:>4}  {x['profile']:<8} {x['name']}")
            print('\nCampaigns:')
            for k,v in m.get('campaigns',{}).items():print(f'{k:22} {v.get("description","")}')
            return 0
        if args.cmd=='triage-current':
            cfg=load_config(root);summary_path=cfg.control_root_path/'current'/'summary.json'
            if not summary_path.is_file():print('No current KonnaxionDiag evidence.');return 20
            summary=read_json(summary_path);found=False
            for row in summary.get('levels',[]):
                if row.get('verdict') in {'PASS','SKIP'}:continue
                found=True;print(f"{row.get('id')} {row.get('verdict')} {row.get('name','')}")
                rp=summary_path.parent/row.get('result','')
                if rp.is_file():
                    for f in read_json(rp).get('findings',[]):
                        if f.get('verdict') not in {'PASS','SKIP'}:print(f"    {f.get('verdict')} {f.get('id')}: {f.get('message','')}")
            if not found:print('Current run has no non-PASS levels.')
            return exit_code(summary.get('verdict','ERROR'))
        if args.cmd=='run-sequence':
            cfg=load_config(root,args.target);outcomes=run_named_sequence(args.sequence,cfg)
            if not outcomes:return 30
            for outcome in outcomes:log_line(f"{outcome.get('campaign')}: {outcome.get('verdict')}")
            return max(exit_code(x.get('verdict','ERROR')) for x in outcomes)
        if args.cmd=='show-config':
            cfg=load_config(root,args.target);print(json.dumps(cfg.data,indent=2,ensure_ascii=False));return 0
        if args.cmd=='run':
            summary,code,run_root=run_campaign(args.selection,config=load_config(root,args.target),fail_fast=args.fail_fast)
            print((run_root/'summary.txt').read_text(encoding='utf-8'),end='');log_line(f'Evidence: {run_root}')
            if (run_root/'release-verdict.json').exists():log_line(f'Release verdict: {run_root/"release-verdict.json"}')
            return code
        if args.cmd=='verify-run':
            p=Path(args.summary);s=read_json(p)
            if s.get('schema')!=SUMMARY_SCHEMA:print('Invalid summary schema',file=sys.stderr);return 30
            missing=[]
            for row in s.get('levels',[]):
                rp=p.parent/row['result']
                if not rp.exists():missing.append(str(rp));continue
                if read_json(rp).get('schema')!=REPORT_SCHEMA:missing.append(str(rp)+' (schema)')
            if missing:print('INVALID');[print(' -',x) for x in missing];return 30
            print('VALID');return 0
        if args.cmd=='sign-evidence':
            payload=read_json(Path(args.input));key=Path(args.key).expanduser()
            password=os.environ.get('KDIAG_EVIDENCE_SIGNING_KEY_PASSWORD')
            env=sign_evidence(payload,key,purpose=args.purpose,password=password.encode('utf-8') if password else None,key_id=args.key_id)
            write_json(Path(args.output),env);print(f'SIGNED {args.output}');return 0
        if args.cmd=='verify-evidence':
            payload=read_json(Path(args.input));env=read_json(Path(args.signature));keys=[Path(x).expanduser() for x in args.public_key]
            ok,detail=verify_evidence(payload,env,keys,purpose=args.purpose)
            print('VALID' if ok else 'INVALID');print(json.dumps(detail,indent=2,ensure_ascii=False));return 0 if ok else 20
        if args.cmd=='sign-disposition':
            disposition=read_json(Path(args.input));disposition.pop('signature',None);key=Path(args.key).expanduser()
            password=os.environ.get('KDIAG_EVIDENCE_SIGNING_KEY_PASSWORD')
            disposition['signature']=sign_evidence(disposition,key,purpose=WARN_DISPOSITION_PURPOSE,password=password.encode('utf-8') if password else None,key_id=args.key_id)
            write_json(Path(args.output),disposition);print(f'SIGNED {args.output}');return 0
        if args.cmd=='sign-attestation':
            payload=read_json(Path(args.input));etype=str(payload.get('evidence_type','')).strip()
            if payload.get('schema')!='konnaxiondiag.attestation.v1':raise ValueError('input must use konnaxiondiag.attestation.v1')
            key=Path(args.key).expanduser();password=os.environ.get('KDIAG_EVIDENCE_SIGNING_KEY_PASSWORD')
            env=sign_evidence(payload,key,purpose=attestation_purpose(etype),password=password.encode('utf-8') if password else None,key_id=args.key_id)
            write_json(Path(args.output),env);print(f'SIGNED {args.output}');return 0
        if args.cmd=='verify-attestation':
            payload=read_json(Path(args.input));env=read_json(Path(args.signature));rs=read_json(Path(args.release_set));keys=[Path(x).expanduser() for x in args.public_key]
            ok,detail=validate_universal_attestation(payload,env,public_keys=keys,expected_release_set_digest=str(rs.get('release_set_digest','')),expected_issuers=args.issuer or [],max_age_seconds=args.max_age_seconds)
            print('VALID' if ok else 'INVALID');print(json.dumps(detail,indent=2,ensure_ascii=False));return 0 if ok else 20
        if args.cmd=='build-release-set':
            cfg_obj=load_config(root,args.target);cfg=cfg_obj.security_dict();results=[]
            run_root=Path(args.run_root).resolve(strict=False) if args.run_root else (cfg_obj.control_root_path/'current')
            level_root=run_root/'levels'
            if level_root.is_dir():
                for rp in sorted(level_root.glob('*/result.json')):
                    try:results.append(read_json(rp))
                    except Exception:pass
            rs,issues=build_release_set(target_root=cfg_obj.target_root_path,results=results,cfg=cfg)
            out=Path(args.output) if args.output else (run_root/'release-set.json')
            write_json(out,rs);print(json.dumps({'release_set_digest':rs.get('release_set_digest'),'complete':rs.get('complete'),'problems':issues,'output':str(out)},indent=2));return 0 if not issues else 20
        if args.cmd=='verify-admission':
            verdict=read_json(Path(args.verdict));env=read_json(Path(args.signature));rs=read_json(Path(args.release_set));keys=[Path(x).expanduser() for x in args.public_key]
            allowed=('PASS','WARN') if args.allow_warn else ('PASS',)
            ok,detail=verify_release_authorization(verdict,env,trusted_public_keys=keys,active_release_set=rs,allowed_verdicts=allowed,expected_policy_version=args.policy_version)
            print('ADMIT' if ok else 'DENY');print(json.dumps(detail,indent=2,ensure_ascii=False));return 0 if ok else 20
        if args.cmd=='_worker':return run_worker(root,args.level,args.run_id,Path(args.output),args.target)
    except (ConfigError,ManifestError,ValueError,OSError) as exc:
        log_line(f'KonnaxionDiag error: {type(exc).__name__}: {exc}',file=sys.stderr);return 30
    return 64
