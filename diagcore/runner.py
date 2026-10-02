from __future__ import annotations
import os,shutil,subprocess,sys,time,uuid
from datetime import datetime,timezone
from pathlib import Path
from . import SUMMARY_SCHEMA,VERSION,REPORT_SCHEMA
from .config import AppConfig,load_config
from .manifest import load_manifest,resolve_selection
from .utils import read_json,write_json,redact,redact_data,utc_now
from .verdicts import campaign_verdict,exit_code
from .correlation import build_cross_domain
from .release_gate import build_final_release_verdict

DEFAULT_IGNORE=('frontend/next-env.d.ts',)
DEFAULT_RESTORE=('frontend/storageState.json',)

def make_run_id():return datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+uuid.uuid4().hex[:8]

def _git_status(target:Path,ignored=()):
    if not (target/'.git').exists() or shutil.which('git') is None:return None
    cmd=['git','status','--porcelain=v1','--untracked-files=no']
    ex=[]
    for rel in ignored:
        r=str(rel).replace('\\','/').strip('/')
        if r:ex.extend([f':(top,exclude){r}',f':(top,exclude){r}/**'])
    if ex:cmd+=['--','.',*ex]
    try:
        cp=subprocess.run(cmd,cwd=str(target),stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,encoding='utf-8',errors='replace',timeout=15,shell=False,check=False)
        if cp.returncode:return None
        lines=sorted(x.rstrip() for x in cp.stdout.splitlines() if x.strip())
        return '\n'.join(lines)+'\n' if lines else ''
    except Exception:return None

def _snapshot_paths(target:Path,paths):
    state={}
    for rel in paths:
        p=(target/rel).resolve(strict=False)
        try:p.relative_to(target.resolve(strict=False))
        except ValueError:continue
        state[str(rel)]=p.read_bytes() if p.is_file() else None if not p.exists() else '__DIR__'
    return state

def _restore_paths(target:Path,state):
    restored=[]
    for rel,original in state.items():
        if original=='__DIR__':continue
        p=(target/rel).resolve(strict=False)
        try:p.relative_to(target.resolve(strict=False))
        except ValueError:continue
        if original is None:
            if p.is_file() or p.is_symlink():p.unlink(missing_ok=True);restored.append(rel)
        elif not p.is_file() or p.read_bytes()!=original:
            p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(original);restored.append(rel)
    return restored

def _blocked(meta,run_id,target,deps):
    now=utc_now();return {'schema':REPORT_SCHEMA,'standard':'KonnaxionDiag','standard_version':VERSION,'profile':meta['profile'],'run_id':run_id,
      'level_id':meta['id'],'level_name':meta['name'],'purpose':meta.get('purpose',''),'target_repo_root':str(target),'started_at':now,'ended_at':now,'verdict':'BLOCKED',
      'findings':[{'id':'dependencies.required.blocked','verdict':'BLOCKED','category':'dependency','message':'A required dependency did not produce usable evidence.','evidence':{'dependencies':deps}}],
      'artifacts':[],'metrics':{}}

def _print_findings(data,evidence_chars=700):
    for f in data.get('findings',[]):
        if f.get('verdict') in {'PASS','SKIP'}:continue
        print(f"    {f.get('verdict')} {f.get('id')}: {f.get('message','')}",flush=True)
        ev=f.get('evidence')
        if ev is not None:
            text=redact(str(ev)).replace('\r','')
            if len(text)>evidence_chars:text='…'+text[-evidence_chars:]
            for line in text.splitlines()[-8:]:print(f'      {line}',flush=True)

def run_campaign(selection:str,*,levels=None,config:AppConfig|None=None,target_override=None,fail_fast=None):
    root=(config.diagnostics_root_path if config else Path(__file__).resolve().parents[1])
    cfg=config or load_config(root,target_override);m=load_manifest(root)
    if levels is None:
        selected=resolve_selection(m,selection)
        campaign_meta=m.get('campaigns',{}).get(selection,{})
    else:
        ids=[str(x) for x in levels];by={x['id']:x for x in m['levels']};selected=[by[x] for x in ids];campaign_meta={}
    target=cfg.target_root_path;control=cfg.control_root_path;current=control/'current'
    exec_cfg=cfg.get('execution',{}) if isinstance(cfg.get('execution',{}),dict) else {}
    ignore=tuple(dict.fromkeys([*DEFAULT_IGNORE,*exec_cfg.get('protect_tracked_ignore_paths',[])]))
    restore=tuple(dict.fromkeys([*DEFAULT_RESTORE,*exec_cfg.get('protect_tracked_restore_paths',[])]))
    mutation_forbidden=not bool(exec_cfg.get('allow_target_mutation',False))
    protect=bool(exec_cfg.get('protect_tracked_files',True)) or mutation_forbidden
    before=_git_status(target,(*ignore,*restore)) if protect else None
    restore_state=_snapshot_paths(target,restore) if protect else {}
    if current.exists():shutil.rmtree(current,ignore_errors=True)
    session_dir=control/'konnaxion'
    if session_dir.exists():shutil.rmtree(session_dir,ignore_errors=True)
    current.mkdir(parents=True,exist_ok=True)
    run_id=make_run_id();started=utc_now();write_json(current/'effective_config.json',redact_data(cfg.data))
    expected=[x['id'] for x in selected];expected_n=[x for x in expected if x.startswith('N')]
    env=dict(os.environ);heartbeat=int(exec_cfg.get('command_heartbeat_seconds',15) or 0)
    env.update({'KDIAG_UNIFIED':'1','KDIAG_CAMPAIGN':selection,'KDIAG_EXPECTED_LEVELS':','.join(expected),'KDIAG_RUN_ID':run_id,'KDIAG_HEARTBEAT_SECONDS':str(heartbeat),
                'LEVELUPDIAG_CAMPAIGN':selection,'LEVELUPDIAG_EXPECTED_LEVELS':','.join(expected_n),'LEVELUPDIAG_RUN_ID':run_id,'LEVELUPDIAG_HEARTBEAT_SECONDS':str(heartbeat)})
    write_json(current/'run.json',{'schema':'konnaxiondiag.run.v1','run_id':run_id,'campaign':selection,'expected_levels':expected,'started_at':started,'target_repo_root':str(target)})
    print(f'KonnaxionDiag v{VERSION} — {selection}',flush=True);print('Sequence: '+' -> '.join(expected),flush=True)
    results={};ff=bool(exec_cfg.get('fail_fast',False)) if fail_fast is None else bool(fail_fast)
    for index,meta in enumerate(selected,1):
        lid=meta['id'];deps={d:results[d].get('verdict') for d in meta.get('depends_on',[]) if d in results}
        hard_dep={'BLOCKED','ERROR','INFRA_ERROR','CONFIG_ERROR'} | ({'FAIL'} if meta['profile']=='levelup' else set())
        bad={d:v for d,v in deps.items() if v in hard_dep};out=current/'levels'/lid/'result.json';out.parent.mkdir(parents=True,exist_ok=True)
        if bad:data=_blocked(meta,run_id,target,bad);write_json(out,data)
        elif ff and any(r.get('verdict') in {'FAIL','ERROR','CONFIG_ERROR'} for r in results.values()):
            data=_blocked(meta,run_id,target,{'fail_fast':'campaign stopped'});write_json(out,data)
        else:
            timeout=int(meta.get('timeout_seconds') or exec_cfg.get('default_timeout_seconds',180))
            print(f'[{index:02d}/{len(selected):02d}] {lid} {meta["name"]} — START',flush=True)
            cmd=[sys.executable,str(root/'kdiag.py'),'_worker','--level',lid,'--run-id',run_id,'--output',str(out),'--target',str(target)]
            t0=time.monotonic()
            try:
                cp=subprocess.run(cmd,cwd=str(target),env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,encoding='utf-8',errors='replace',timeout=timeout,shell=False,check=False)
                if out.is_file():data=read_json(out)
                else:
                    now=utc_now();data={'schema':REPORT_SCHEMA,'standard':'KonnaxionDiag','standard_version':VERSION,'profile':meta['profile'],'run_id':run_id,'level_id':lid,'level_name':meta['name'],'target_repo_root':str(target),'started_at':now,'ended_at':now,'verdict':'INFRA_ERROR','findings':[{'id':'diagnostics.worker.missing_result','verdict':'INFRA_ERROR','category':'diagnostics','message':'Worker did not produce a result.','evidence':{'return_code':cp.returncode,'stderr_tail':redact((cp.stderr or '')[-2000:])}}],'artifacts':[],'metrics':{}};write_json(out,data)
            except subprocess.TimeoutExpired:
                now=utc_now();data={'schema':REPORT_SCHEMA,'standard':'KonnaxionDiag','standard_version':VERSION,'profile':meta['profile'],'run_id':run_id,'level_id':lid,'level_name':meta['name'],'target_repo_root':str(target),'started_at':now,'ended_at':now,'verdict':'INFRA_ERROR','findings':[{'id':'diagnostics.worker.timeout','verdict':'INFRA_ERROR','category':'diagnostics','message':f'Level exceeded {timeout}s timeout.'}],'artifacts':[],'metrics':{}};write_json(out,data)
            print(f'[{index:02d}/{len(selected):02d}] {lid} — {data.get("verdict")} ({time.monotonic()-t0:.1f}s)',flush=True);_print_findings(data)
        results[lid]=data
    restored=_restore_paths(target,restore_state) if protect else []
    after=_git_status(target,(*ignore,*restore)) if protect else None;protection=None
    if before is not None and after is not None and before!=after:
        protection={'verdict':'ERROR','message':'Tracked target state changed during diagnostics; execution.allow_target_mutation=false makes this release-blocking.','before':before,'after':after,'restored_paths':restored,'allow_target_mutation':not mutation_forbidden}
    ordered=[results[x['id']] for x in selected];required={x['id']:bool(x.get('required',False)) for x in selected}
    raw_verdict=campaign_verdict(ordered,required);correlation=build_cross_domain(ordered);write_json(current/'correlation.json',correlation)
    final=None
    if bool(campaign_meta.get('final_release_gate',False)):
        final=build_final_release_verdict(campaign=selection,run_id=run_id,target_root=target,results=ordered,cfg=cfg.data,correlation=correlation,out_dir=current,target_protection=protection)
    verdict=final.get('verdict') if final else raw_verdict
    if protection:verdict='ERROR'
    counts={}
    for r in ordered:counts[r.get('verdict','ERROR')]=counts.get(r.get('verdict','ERROR'),0)+1
    summary={'schema':SUMMARY_SCHEMA,'standard':'KonnaxionDiag','standard_version':VERSION,'run_id':run_id,'campaign':selection,'selection':selection,'target_repo_root':str(target),'started_at':started,'ended_at':utc_now(),'verdict':verdict,'raw_campaign_verdict':raw_verdict,'counts':counts,'expected_levels':expected,'required_levels':[x['id'] for x in selected if x.get('required')],
             'levels':[{'id':r['level_id'],'name':r.get('level_name',''),'profile':r.get('profile'),'verdict':r.get('verdict'),'result':f"levels/{r['level_id']}/result.json"} for r in ordered],
             'cross_domain_correlation':'correlation.json','final_release_verdict':'release-verdict.json' if final else None,'target_protection':protection}
    write_json(current/'summary.json',summary)
    text=[f'KonnaxionDiag {selection} - {verdict}',f'Run: {run_id}',f'Target: {target}','']+[f"{r['level_id']:>4}  {r.get('verdict','ERROR'):<12} {r.get('level_name','')}" for r in ordered]
    (current/'summary.txt').write_text('\n'.join(text)+'\n',encoding='utf-8')
    return summary,exit_code(verdict),current

def run_named_sequence(name:str,config:AppConfig):
    m=load_manifest(config.diagnostics_root_path)
    seq=m.get('sequences',{}).get(name)
    if seq is None:raise ValueError(f'unknown sequence: {name}')
    outcomes=[]
    for campaign in seq.get('campaigns',[]):
        summary,code,run_root=run_campaign(campaign,config=config)
        outcomes.append(summary)
        if code and not bool(seq.get('continue_on_failure',False)):break
    return outcomes
