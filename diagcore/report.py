from __future__ import annotations
from pathlib import Path
from . import REPORT_SCHEMA,VERSION
from .utils import utc_now,write_json
from .verdicts import level_verdict

class Report:
    def __init__(self,run_id,level_id,level_name,purpose,target_root,profile='security'):
        self.run_id=run_id;self.level_id=level_id;self.level_name=level_name;self.purpose=purpose;self.target_root=str(target_root);self.profile=profile
        self.started_at=utc_now();self.findings=[];self.artifacts=[];self.metrics={}
    def add(self,finding_id,verdict,category,message,*,evidence=None,recommendation=None,path=None,data=None,release_blocker=None):
        item={'id':finding_id,'verdict':verdict,'category':category,'message':message}
        if evidence is not None:item['evidence']=evidence
        if recommendation is not None:item['recommendation']=recommendation
        if path is not None:item['path']=str(path)
        if data is not None:item['data']=data
        if release_blocker is not None:item['release_blocker']=bool(release_blocker)
        self.findings.append(item);return item
    def artifact(self,kind,path,description=None):
        a={'kind':kind,'path':str(path)}
        if description:a['description']=description
        self.artifacts.append(a)
    def to_dict(self,ended_at=None,override_verdict=None):
        return {'schema':REPORT_SCHEMA,'standard':'KonnaxionDiag','standard_version':VERSION,'profile':self.profile,'run_id':self.run_id,
          'level_id':self.level_id,'level_name':self.level_name,'purpose':self.purpose,'target_repo_root':self.target_root,
          'started_at':self.started_at,'ended_at':ended_at or utc_now(),'verdict':override_verdict or level_verdict(self.findings),
          'findings':self.findings,'artifacts':self.artifacts,'metrics':self.metrics}
    def write(self,path:Path,override_verdict=None):
        data=self.to_dict(override_verdict=override_verdict);write_json(path,data);return data
