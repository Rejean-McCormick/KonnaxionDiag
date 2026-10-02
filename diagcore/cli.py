from __future__ import annotations
import argparse,json,sys
from pathlib import Path
from . import VERSION,REPORT_SCHEMA,SUMMARY_SCHEMA
from .config import ConfigError,load_config
from .manifest import ManifestError,load_manifest
from .runner import run_campaign,run_named_sequence
from .worker import run_worker
from .utils import read_json
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
            for outcome in outcomes:print(f"{outcome.get('campaign')}: {outcome.get('verdict')}")
            return max(exit_code(x.get('verdict','ERROR')) for x in outcomes)
        if args.cmd=='show-config':
            cfg=load_config(root,args.target);print(json.dumps(cfg.data,indent=2,ensure_ascii=False));return 0
        if args.cmd=='run':
            summary,code,run_root=run_campaign(args.selection,config=load_config(root,args.target),fail_fast=args.fail_fast)
            print((run_root/'summary.txt').read_text(encoding='utf-8'),end='');print(f'Evidence: {run_root}')
            if (run_root/'release-verdict.json').exists():print(f'Release verdict: {run_root/"release-verdict.json"}')
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
        if args.cmd=='_worker':return run_worker(root,args.level,args.run_id,Path(args.output),args.target)
    except (ConfigError,ManifestError,ValueError,OSError) as exc:
        print(f'KonnaxionDiag error: {type(exc).__name__}: {exc}',file=sys.stderr);return 30
    return 64
