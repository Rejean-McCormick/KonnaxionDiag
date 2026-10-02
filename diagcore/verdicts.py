PASS="PASS"; WARN="WARN"; FAIL="FAIL"; SKIP="SKIP"; BLOCKED="BLOCKED"; PARTIAL="PARTIAL"; ERROR="ERROR"; INFRA_ERROR="INFRA_ERROR"; CONFIG_ERROR="CONFIG_ERROR"
VERDICTS=(PASS,WARN,FAIL,SKIP,BLOCKED,PARTIAL,ERROR,INFRA_ERROR,CONFIG_ERROR)
RANK={PASS:0,SKIP:0,WARN:1,PARTIAL:2,BLOCKED:3,INFRA_ERROR:4,FAIL:5,ERROR:6,CONFIG_ERROR:7}
HARD={FAIL,BLOCKED,ERROR,INFRA_ERROR,CONFIG_ERROR}

def aggregate_verdicts(values):
    vals=[v for v in values if v in RANK]
    return max(vals,key=lambda x:RANK[x]) if vals else PASS

def worst(values): return aggregate_verdicts(values)

def level_verdict(findings,default=PASS):
    if not findings: return default
    vals=[f.get("verdict",f.get("severity",PASS)) for f in findings]
    substantive=[v for v in vals if v!=SKIP]
    return aggregate_verdicts(substantive) if substantive else SKIP

def campaign_verdict(results,required_map=None):
    if not results: return CONFIG_ERROR
    required_map=required_map or {}
    if any(r.get("verdict") in {ERROR,CONFIG_ERROR} for r in results): return ERROR
    if any(r.get("verdict")==FAIL for r in results): return FAIL
    incomplete={SKIP,BLOCKED,PARTIAL,INFRA_ERROR}
    if any(required_map.get(r.get("level_id"),False) and r.get("verdict") in incomplete for r in results): return BLOCKED
    if any(r.get("verdict") in incomplete for r in results): return WARN
    if any(r.get("verdict")==WARN for r in results): return WARN
    return PASS

def exit_code(verdict):
    if verdict in {PASS,WARN,SKIP}: return 0
    if verdict==FAIL: return 10
    if verdict in {PARTIAL,BLOCKED}: return 20
    return 30
