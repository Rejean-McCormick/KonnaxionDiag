from __future__ import annotations
from typing import Any

BAD={'FAIL','BLOCKED','ERROR','INFRA_ERROR','CONFIG_ERROR'}

def _bad_findings(result):
    return [f for f in result.get('findings',[]) if f.get('verdict') in BAD or f.get('release_blocker') is True]

def build_cross_domain(results:list[dict[str,Any]])->dict[str,Any]:
    by_id={r.get('level_id'):r for r in results}; chains=[]
    def ids(levels):
        out=[]
        for lid in levels:
            for f in _bad_findings(by_id.get(lid,{})):out.append({'level':lid,'finding':f.get('id'),'verdict':f.get('verdict')})
        return out
    rules=[
      ('auth-and-authorization',['N07'],['S04','S04W']),
      ('frontend-web-trust',['N03','N05'],['S04W']),
      ('runtime-exposure',['N08','N09'],['S08','S09','S12']),
      ('world-scope-trust',['N04','N05','N10'],['S04W','S09']),
    ]
    for name,nlevels,slevels in rules:
        left=ids(nlevels);right=ids(slevels)
        if left and right:chains.append({'id':name,'functional_evidence':left,'security_evidence':right,'status':'CORRELATED_RISK'})
    sec_exploit=[]
    for r in results:
        if str(r.get('level_id','')).startswith('S'):
            for f in r.get('findings',[]):
                if f.get('category')=='exploit_chain' and f.get('verdict')!='PASS':
                    sec_exploit.append({'level':r.get('level_id'),'finding':f.get('id'),'verdict':f.get('verdict'),'message':f.get('message')})
    if sec_exploit:chains.append({'id':'security-exploit-chain','security_evidence':sec_exploit,'status':'CORRELATED_RISK'})
    return {'schema':'konnaxiondiag.correlation.v1','verdict':'WARN' if chains else 'PASS','chains':chains,
            'note':'Correlation never downgrades a source-domain verdict and cannot compensate for a security failure.'}
