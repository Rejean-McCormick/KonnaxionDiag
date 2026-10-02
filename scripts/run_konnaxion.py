from __future__ import annotations
import argparse,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path: sys.path.insert(0,str(ROOT))
from diagcore.config import load_config
from diagcore.runner import run_campaign
from diagcore.verdicts import exit_code
from diagcore.manifest import load_manifest

def main():
    m=load_manifest(ROOT); campaigns=m.get('campaigns',{})
    p=argparse.ArgumentParser(description='Konnaxion LevelUpDiag campaigns — upgraded engine'); p.add_argument('campaign',choices=campaigns)
    a=p.parse_args(); result=run_campaign(a.campaign,config=load_config(ROOT)); print(f'campaign {result.campaign}: {result.verdict}')
    for item in result.levels:
        print(f'  {item.level} — {item.name}: {item.verdict}')
        for finding in item.findings:
            if finding.severity not in {'PASS','SKIP'}: print(f'      {finding.severity}: {finding.id}: {finding.message}')
    return exit_code(result.verdict)
if __name__=='__main__': raise SystemExit(main())
