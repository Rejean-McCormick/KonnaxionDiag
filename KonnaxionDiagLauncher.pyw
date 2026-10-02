from __future__ import annotations
import json, os, queue, subprocess, sys, threading
from pathlib import Path
import tkinter as tk
from tkinter import ttk, messagebox

ROOT=Path(__file__).resolve().parent
MANIFEST=ROOT/'kdiag_manifest.json'

class App(tk.Tk):
    def __init__(self):
        super().__init__();self.title('KonnaxionDiag v4');self.geometry('1040x700');self.proc=None;self.q=queue.Queue()
        m=json.loads(MANIFEST.read_text(encoding='utf-8'));self.campaigns=m.get('campaigns',{})
        top=ttk.Frame(self,padding=10);top.pack(fill='x')
        ttk.Label(top,text='Campaign').pack(side='left')
        self.selection=tk.StringVar(value='release-all');combo=ttk.Combobox(top,textvariable=self.selection,values=list(self.campaigns),state='readonly',width=32);combo.pack(side='left',padx=8)
        ttk.Button(top,text='Run',command=self.run_campaign).pack(side='left',padx=4)
        ttk.Button(top,text='Stop',command=self.stop).pack(side='left',padx=4)
        ttk.Button(top,text='Open evidence',command=self.open_evidence).pack(side='left',padx=4)
        ttk.Button(top,text='Doctor',command=lambda:self.run_command(['doctor'])).pack(side='left',padx=4)
        self.desc=tk.StringVar();ttk.Label(self,textvariable=self.desc,padding=(10,0,10,8),wraplength=1000).pack(fill='x')
        combo.bind('<<ComboboxSelected>>',lambda _e:self.update_desc());self.update_desc()
        self.text=tk.Text(self,wrap='none',font=('Consolas',10));self.text.pack(fill='both',expand=True,padx=10,pady=(0,10))
        self.after(100,self.drain)
    def update_desc(self):self.desc.set(self.campaigns.get(self.selection.get(),{}).get('description',''))
    def append(self,line):self.text.insert('end',line);self.text.see('end')
    def run_campaign(self):self.run_command(['run',self.selection.get()])
    def run_command(self,args):
        if self.proc and self.proc.poll() is None:
            messagebox.showwarning('KonnaxionDiag','A diagnostic is already running.');return
        self.text.delete('1.0','end');cmd=[sys.executable,str(ROOT/'kdiag.py'),*args]
        def worker():
            try:
                self.proc=subprocess.Popen(cmd,cwd=str(ROOT),stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,encoding='utf-8',errors='replace',shell=False,bufsize=1)
                assert self.proc.stdout is not None
                for line in self.proc.stdout:self.q.put(line)
                code=self.proc.wait();self.q.put(f'\n[process exit {code}]\n')
            except Exception as exc:self.q.put(f'\n[launcher error] {type(exc).__name__}: {exc}\n')
        threading.Thread(target=worker,daemon=True).start()
    def stop(self):
        if self.proc and self.proc.poll() is None:
            try:self.proc.terminate()
            except OSError:pass
    def drain(self):
        try:
            while True:self.append(self.q.get_nowait())
        except queue.Empty:pass
        self.after(100,self.drain)
    def open_evidence(self):
        try:
            cfg=json.loads((ROOT/'kdiag.config.json').read_text(encoding='utf-8'))
            raw=cfg.get('target_repo_root','auto')
            if str(raw).lower()=='auto':
                parent=ROOT.parent; target=(parent/'Konnaxion') if (parent/'Konnaxion').is_dir() else parent
            else:
                p=Path(str(raw)).expanduser();target=p if p.is_absolute() else ROOT/p
            evidence=(target/cfg.get('control_dir','.konnaxiondiag')/'current').resolve(strict=False);evidence.mkdir(parents=True,exist_ok=True)
            if os.name=='nt':os.startfile(evidence)  # type: ignore[attr-defined]
            elif sys.platform=='darwin':subprocess.Popen(['open',str(evidence)])
            else:subprocess.Popen(['xdg-open',str(evidence)])
        except Exception as exc:messagebox.showerror('KonnaxionDiag',str(exc))

if __name__=='__main__':App().mainloop()
