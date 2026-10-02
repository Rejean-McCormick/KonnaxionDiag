from __future__ import annotations
from pathlib import Path
from .models import Artifact,Finding,LevelResult
from .utils import read_json,write_json

def write_level_result(path:Path,result:LevelResult,**meta):write_json(path,result.to_dict(**meta))
def read_level_result(path:Path)->LevelResult:
    d=read_json(path)
    return LevelResult(level=d.get('level_id') or d.get('level'),name=d.get('level_name') or d.get('name',''),verdict=d.get('verdict','ERROR'),
      findings=[Finding(id=f['id'],severity=f.get('verdict') or f.get('severity','ERROR'),message=f.get('message',''),category=f.get('category',''),path=f.get('path'),evidence=f.get('evidence'),recommendation=f.get('recommendation'),data=f.get('data'),release_blocker=f.get('release_blocker')) for f in d.get('findings',[])],
      artifacts=[Artifact(kind=a.get('kind','artifact'),path=a.get('path',''),description=a.get('description'),data=a.get('data')) for a in d.get('artifacts',[])],
      started_at=d.get('started_at',''),ended_at=d.get('ended_at',''),duration_seconds=float(d.get('duration_seconds',0) or 0),cwd=d.get('cwd',''),output_tail=d.get('output_tail',''),metadata=dict(d.get('metadata',{})))
