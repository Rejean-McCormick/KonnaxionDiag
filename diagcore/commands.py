from __future__ import annotations
import os, shlex, shutil, subprocess, threading, time
from collections import deque
from pathlib import Path
from .models import StepResult
from .utils import redact, tail_text
from .verdicts import PASS,FAIL,INFRA_ERROR

def find_executable(name): return shutil.which(name)

def normalize_command(command):
    if isinstance(command,str): return shlex.split(command,posix=(os.name!="nt"))
    if isinstance(command,(list,tuple)) and all(isinstance(x,(str,Path)) for x in command): return [str(x) for x in command]
    raise ValueError("command must be string or list[str]")

def run_command(command,*,cwd:Path,timeout_seconds=120,capture_limit_kb=256,env=None,input_text=None):
    argv=normalize_command(command); started=time.monotonic()
    try:
        cp=subprocess.run(argv,cwd=str(cwd),env=env,stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL,input=input_text,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,encoding="utf-8",errors="replace",timeout=timeout_seconds,shell=False,check=False)
        timed_out=False; code=cp.returncode; out=cp.stdout or ""; err=cp.stderr or ""
    except subprocess.TimeoutExpired as e:
        timed_out=True; code=None
        out=e.stdout.decode("utf-8","replace") if isinstance(e.stdout,bytes) else (e.stdout or "")
        err=e.stderr.decode("utf-8","replace") if isinstance(e.stderr,bytes) else (e.stderr or "")
    limit=int(capture_limit_kb)*1024
    return {"argv":argv,"exit_code":code,"timed_out":timed_out,"duration_seconds":round(time.monotonic()-started,3),
            "stdout_tail":tail_text(redact(out),limit),"stderr_tail":tail_text(redact(err),limit)}

def run_cmd(command,*,cwd:Path,timeout:int,name:str='',env=None,tail_chars:int=12000)->StepResult:
    args=normalize_command(command)
    if not args: raise ValueError('empty command')
    started=time.monotonic(); lines=deque(); total=[0]; lock=threading.Lock()
    try:
        proc=subprocess.Popen(args,cwd=str(cwd),env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,
                              text=True,encoding='utf-8',errors='replace',shell=False,bufsize=1)
    except (OSError,PermissionError) as exc:
        return StepResult(name or args[0],tuple(args),str(cwd),INFRA_ERROR,None,round(time.monotonic()-started,3),'',f'{type(exc).__name__}: {exc}',False)
    def reader():
        assert proc.stdout is not None
        for line in proc.stdout:
            with lock:
                lines.append(line); total[0]+=len(line)
                while lines and total[0]>max(tail_chars*2,24000): total[0]-=len(lines.popleft())
    t=threading.Thread(target=reader,daemon=True); t.start()
    heartbeat=int(os.environ.get('KDIAG_HEARTBEAT_SECONDS',os.environ.get('LEVELUPDIAG_HEARTBEAT_SECONDS','15')) or '15')
    next_hb=time.monotonic()+max(heartbeat,5); timed_out=False
    while proc.poll() is None:
        elapsed=time.monotonic()-started
        if elapsed>=timeout:
            timed_out=True
            try:proc.kill()
            except OSError:pass
            break
        if heartbeat>0 and time.monotonic()>=next_hb:
            print(f"    … {name or args[0]} still running ({int(elapsed)}s)",flush=True); next_hb=time.monotonic()+heartbeat
        time.sleep(.1)
    try:proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:proc.kill()
        except OSError:pass
    t.join(timeout=2)
    if proc.stdout is not None:
        try:proc.stdout.close()
        except OSError:pass
    with lock: output=''.join(lines)
    output=redact(output)[-tail_chars:]; duration=round(time.monotonic()-started,3)
    if timed_out:return StepResult(name or args[0],tuple(args),str(cwd),INFRA_ERROR,None,duration,output,f'timeout after {timeout}s',True)
    code=proc.returncode
    return StepResult(name or args[0],tuple(args),str(cwd),PASS if code==0 else FAIL,code,duration,output,'',False)
