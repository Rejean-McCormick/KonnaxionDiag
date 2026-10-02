import sys,tempfile
from pathlib import Path
from diagcore.commands import run_cmd
from diagcore.verdicts import PASS,INFRA_ERROR

def test_shell_false_command():
    with tempfile.TemporaryDirectory() as d:
        r=run_cmd([sys.executable,'-c','print("ok")'],cwd=Path(d),timeout=10,name='test',tail_chars=1000)
        assert r.verdict==PASS and 'ok' in r.output_tail

def test_timeout_is_infra_error():
    with tempfile.TemporaryDirectory() as d:
        r=run_cmd([sys.executable,'-c','import time; time.sleep(2)'],cwd=Path(d),timeout=1,name='timeout',tail_chars=1000)
        assert r.verdict==INFRA_ERROR and r.timed_out
