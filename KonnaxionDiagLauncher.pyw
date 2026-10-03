from __future__ import annotations

import json
import os
import queue
import subprocess
import sys
import threading
from pathlib import Path
import tkinter as tk
from tkinter import messagebox, ttk

from diagcore import VERSION
from diagcore.gui_model import campaign_names_for_profile, parse_level_event, split_levels
from diagcore.subprocesses import decode_process_output, diagnostic_subprocess_env, hidden_process_kwargs
from diagcore.utils import log_timestamp

ROOT = Path(__file__).resolve().parent
MANIFEST = ROOT / "kdiag_manifest.json"

_STATUS_TAGS = {
    "PASS": "pass",
    "WARN": "warn",
    "FAIL": "fail",
    "ERROR": "fail",
    "CONFIG_ERROR": "fail",
    "INFRA_ERROR": "fail",
    "BLOCKED": "blocked",
    "SKIP": "skip",
    "RUNNING": "running",
    "QUEUED": "queued",
}
_DONE = {"PASS", "WARN", "FAIL", "ERROR", "CONFIG_ERROR", "INFRA_ERROR", "BLOCKED", "SKIP"}


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"KonnaxionDiag v{VERSION}")
        self.geometry("1260x850")
        self.minsize(1020, 700)

        self.proc: subprocess.Popen | None = None
        self.q: queue.Queue = queue.Queue()
        self.current_campaign: str | None = None
        self.level_status: dict[str, str] = {}
        self.tree_items: dict[str, list[tuple[ttk.Treeview, str]]] = {}

        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.campaigns: dict[str, dict] = manifest.get("campaigns", {})
        self.levels: list[dict] = manifest.get("levels", [])
        self.functional_levels, self.security_levels = split_levels(self.levels)
        self.level_by_id = {str(level["id"]): level for level in self.levels}
        self.level_status = {level_id: "—" for level_id in self.level_by_id}

        self._configure_style()
        self._build_header()
        self._build_body()
        self._build_status_bar()
        self.protocol("WM_DELETE_WINDOW", self.close)
        self.after(100, self.drain)

    def _configure_style(self):
        style = ttk.Style(self)
        try:
            style.theme_use("vista" if os.name == "nt" else "clam")
        except tk.TclError:
            pass
        style.configure("Header.TLabel", font=("Segoe UI", 18, "bold"))
        style.configure("Subheader.TLabel", font=("Segoe UI", 10))
        style.configure("Section.TLabel", font=("Segoe UI", 11, "bold"))
        style.configure("KpiTitle.TLabel", font=("Segoe UI", 9))
        style.configure("KpiValue.TLabel", font=("Segoe UI", 17, "bold"))
        style.configure("Accent.TButton", font=("Segoe UI", 10, "bold"), padding=(14, 8))
        style.configure("Action.TButton", padding=(12, 7))
        style.configure("Treeview", rowheight=25)
        style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"))
        style.configure("TNotebook.Tab", padding=(14, 7))

    def _build_header(self):
        header = ttk.Frame(self, padding=(14, 10, 14, 8))
        header.pack(fill="x")
        title = ttk.Frame(header)
        title.pack(side="left", fill="x", expand=True)
        ttk.Label(title, text=f"KonnaxionDiag  {VERSION}", style="Header.TLabel").pack(anchor="w")
        ttk.Label(
            title,
            text="Qualification fonctionnelle, sécurité et release de Konnaxion",
            style="Subheader.TLabel",
        ).pack(anchor="w")

        actions = ttk.Frame(header)
        actions.pack(side="right")
        ttk.Button(actions, text="Evidence", command=self.open_evidence, style="Action.TButton").pack(side="left", padx=3)
        ttk.Button(actions, text="Doctor", command=lambda: self.run_command(["doctor"], label="Doctor"), style="Action.TButton").pack(side="left", padx=3)

    def _build_body(self):
        outer = ttk.Panedwindow(self, orient="vertical")
        outer.pack(fill="both", expand=True, padx=14, pady=(0, 8))

        top = ttk.Frame(outer)
        bottom = ttk.Frame(outer)
        outer.add(top, weight=3)
        outer.add(bottom, weight=2)

        self.notebook = ttk.Notebook(top)
        self.notebook.pack(fill="both", expand=True)

        self.general_tab = ttk.Frame(self.notebook, padding=12)
        self.functional_tab = ttk.Frame(self.notebook, padding=12)
        self.security_tab = ttk.Frame(self.notebook, padding=12)
        self.campaigns_tab = ttk.Frame(self.notebook, padding=12)
        self.notebook.add(self.general_tab, text="Santé générale")
        self.notebook.add(self.functional_tab, text="Fonctionnel N00-N11")
        self.notebook.add(self.security_tab, text="Sécurité S00-S14")
        self.notebook.add(self.campaigns_tab, text="Campagnes")

        self._build_general_tab()
        self._build_series_tab(
            self.functional_tab,
            self.functional_levels,
            campaign_names_for_profile(self.campaigns, "levelup"),
            default_campaign="full-local",
            heading="Série fonctionnelle N00-N11",
        )
        self._build_series_tab(
            self.security_tab,
            self.security_levels,
            campaign_names_for_profile(self.campaigns, "security"),
            default_campaign="security-release",
            heading="Série sécurité S00-S14",
        )
        self._build_campaigns_tab()
        self._build_log_panel(bottom)

    def _build_general_tab(self):
        actions = ttk.LabelFrame(self.general_tab, text="Actions principales", padding=10)
        actions.pack(fill="x")
        ttk.Button(actions, text="Quick test", style="Accent.TButton", command=lambda: self.start_campaign("health-quick")).pack(side="left", padx=(0, 6))
        ttk.Button(actions, text="Test All", style="Accent.TButton", command=lambda: self.start_campaign("release-all")).pack(side="left", padx=6)
        ttk.Button(actions, text="Playwright", style="Action.TButton", command=lambda: self.start_campaign("playwright")).pack(side="left", padx=6)
        self.stop_button = ttk.Button(actions, text="Stop", style="Action.TButton", command=self.stop, state="disabled")
        self.stop_button.pack(side="left", padx=6)
        ttk.Label(
            actions,
            text="Test All garde Playwright séparé; lance Playwright uniquement quand tu veux le smoke navigateur complet.",
            wraplength=600,
        ).pack(side="left", padx=(14, 0), fill="x", expand=True)

        kpis = ttk.Frame(self.general_tab)
        kpis.pack(fill="x", pady=(10, 8))
        self.kpi_run = tk.StringVar(value="Prêt")
        self.kpi_pass = tk.StringVar(value="0")
        self.kpi_warn = tk.StringVar(value="0")
        self.kpi_block = tk.StringVar(value="0")
        self.kpi_fail = tk.StringVar(value="0")
        for title, var in (
            ("État", self.kpi_run),
            ("PASS", self.kpi_pass),
            ("WARN", self.kpi_warn),
            ("BLOCKED", self.kpi_block),
            ("FAIL / ERROR", self.kpi_fail),
        ):
            card = ttk.LabelFrame(kpis, padding=(12, 8))
            card.pack(side="left", fill="x", expand=True, padx=(0, 6))
            ttk.Label(card, text=title, style="KpiTitle.TLabel").pack(anchor="w")
            ttk.Label(card, textvariable=var, style="KpiValue.TLabel").pack(anchor="w")

        ttk.Label(self.general_tab, text="Vue globale", style="Section.TLabel").pack(anchor="w", pady=(4, 4))
        self.general_tree = self._make_level_tree(self.general_tab, self.levels)
        self.general_tree.pack(fill="both", expand=True)

    def _build_series_tab(self, parent, levels, campaign_names, *, default_campaign: str, heading: str):
        ttk.Label(parent, text=heading, style="Section.TLabel").pack(anchor="w")
        top = ttk.Frame(parent)
        top.pack(fill="x", pady=(6, 8))
        ttk.Label(top, text="Campagne").pack(side="left")
        selection = tk.StringVar(value=default_campaign if default_campaign in campaign_names else (campaign_names[0] if campaign_names else ""))
        combo = ttk.Combobox(top, textvariable=selection, values=campaign_names, state="readonly", width=32)
        combo.pack(side="left", padx=8)
        ttk.Button(top, text="Lancer", style="Action.TButton", command=lambda: self.start_campaign(selection.get())).pack(side="left")
        desc = tk.StringVar()
        ttk.Label(parent, textvariable=desc, wraplength=1100).pack(fill="x", pady=(0, 8))

        def update_desc(_event=None):
            desc.set(self.campaigns.get(selection.get(), {}).get("description", ""))

        combo.bind("<<ComboboxSelected>>", update_desc)
        update_desc()
        tree = self._make_level_tree(parent, levels)
        tree.pack(fill="both", expand=True)

    def _build_campaigns_tab(self):
        ttk.Label(self.campaigns_tab, text="Toutes les campagnes", style="Section.TLabel").pack(anchor="w")
        row = ttk.Frame(self.campaigns_tab)
        row.pack(fill="x", pady=(6, 8))
        self.campaign_selection = tk.StringVar(value="release-all")
        combo = ttk.Combobox(row, textvariable=self.campaign_selection, values=list(self.campaigns), state="readonly", width=34)
        combo.pack(side="left")
        ttk.Button(row, text="Lancer la campagne", style="Action.TButton", command=lambda: self.start_campaign(self.campaign_selection.get())).pack(side="left", padx=8)
        self.campaign_desc = tk.StringVar()
        ttk.Label(self.campaigns_tab, textvariable=self.campaign_desc, wraplength=1100).pack(fill="x")
        self.campaign_levels = tk.StringVar()
        ttk.Label(self.campaigns_tab, textvariable=self.campaign_levels, wraplength=1100).pack(fill="x", pady=(6, 0))
        combo.bind("<<ComboboxSelected>>", lambda _e: self._update_campaign_details())
        self._update_campaign_details()

    def _update_campaign_details(self):
        meta = self.campaigns.get(self.campaign_selection.get(), {})
        self.campaign_desc.set(meta.get("description", ""))
        self.campaign_levels.set("Niveaux : " + " -> ".join(meta.get("levels", [])))

    def _make_level_tree(self, parent, levels):
        frame = ttk.Frame(parent)
        tree = ttk.Treeview(frame, columns=("name", "status"), show="headings", selectmode="browse")
        tree.heading("name", text="Test")
        tree.heading("status", text="Statut")
        tree.column("name", width=520, anchor="w")
        tree.column("status", width=135, anchor="center")
        scroll = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scroll.set)
        tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        tree.tag_configure("pass", foreground="#167a3c")
        tree.tag_configure("warn", foreground="#946200")
        tree.tag_configure("fail", foreground="#b42318")
        tree.tag_configure("blocked", foreground="#7a4e00")
        tree.tag_configure("skip", foreground="#667085")
        tree.tag_configure("running", foreground="#175cd3")
        tree.tag_configure("queued", foreground="#475467")
        for level in levels:
            lid = str(level["id"])
            item = tree.insert("", "end", values=(f"{lid}  {level.get('name', '')}", self.level_status.get(lid, "—")))
            self.tree_items.setdefault(lid, []).append((tree, item))
        return frame

    def _build_log_panel(self, parent):
        header = ttk.Frame(parent)
        header.pack(fill="x", pady=(4, 4))
        ttk.Label(header, text="Log", style="Section.TLabel").pack(side="left")
        ttk.Button(header, text="Effacer", command=self.clear_log).pack(side="right")
        ttk.Button(header, text="Triage actuel", command=lambda: self.run_command(["triage-current"], label="Triage", clear=False)).pack(side="right", padx=6)

        text_frame = ttk.Frame(parent)
        text_frame.pack(fill="both", expand=True)
        self.text = tk.Text(text_frame, wrap="none", font=("Consolas", 10), undo=False)
        y = ttk.Scrollbar(text_frame, orient="vertical", command=self.text.yview)
        x = ttk.Scrollbar(text_frame, orient="horizontal", command=self.text.xview)
        self.text.configure(yscrollcommand=y.set, xscrollcommand=x.set)
        self.text.grid(row=0, column=0, sticky="nsew")
        y.grid(row=0, column=1, sticky="ns")
        x.grid(row=1, column=0, sticky="ew")
        text_frame.rowconfigure(0, weight=1)
        text_frame.columnconfigure(0, weight=1)

    def _build_status_bar(self):
        bar = ttk.Frame(self, padding=(14, 0, 14, 10))
        bar.pack(fill="x")
        self.status_text = tk.StringVar(value="Prêt")
        self.progress_text = tk.StringVar(value="")
        ttk.Label(bar, textvariable=self.status_text).pack(side="left")
        self.progress = ttk.Progressbar(bar, mode="determinate", maximum=1, value=0, length=230)
        self.progress.pack(side="right", padx=(8, 0))
        ttk.Label(bar, textvariable=self.progress_text).pack(side="right")

    def clear_log(self):
        self.text.delete("1.0", "end")

    def append(self, text: str):
        self.text.insert("end", text)
        self.text.see("end")
        for line in text.splitlines():
            event = parse_level_event(line)
            if event:
                self._set_level_status(*event)

    def _set_level_status(self, level_id: str, status: str):
        if level_id not in self.level_status:
            return
        self.level_status[level_id] = status
        tag = _STATUS_TAGS.get(status, "")
        for tree, item in self.tree_items.get(level_id, []):
            values = list(tree.item(item, "values"))
            if len(values) >= 2:
                values[1] = status
                tree.item(item, values=values, tags=(tag,) if tag else ())
        self._refresh_kpis()

    def _refresh_kpis(self):
        values = list(self.level_status.values())
        self.kpi_pass.set(str(values.count("PASS")))
        self.kpi_warn.set(str(values.count("WARN")))
        self.kpi_block.set(str(values.count("BLOCKED")))
        self.kpi_fail.set(str(sum(values.count(x) for x in ("FAIL", "ERROR", "CONFIG_ERROR", "INFRA_ERROR"))))
        if self.current_campaign:
            expected = self.campaigns.get(self.current_campaign, {}).get("levels", [])
            completed = sum(1 for lid in expected if self.level_status.get(lid) in _DONE)
            self.progress.configure(maximum=max(1, len(expected)), value=completed)
            self.progress_text.set(f"{completed}/{len(expected)}" if expected else "")

    def _prepare_campaign(self, campaign: str):
        self.current_campaign = campaign
        expected = set(self.campaigns.get(campaign, {}).get("levels", []))
        for lid in self.level_status:
            self._set_level_status(lid, "QUEUED" if lid in expected else "—")
        self.progress.configure(maximum=max(1, len(expected)), value=0)
        self.progress_text.set(f"0/{len(expected)}" if expected else "")
        self.kpi_run.set(campaign)
        self.status_text.set(f"Exécution : {campaign}")

    def start_campaign(self, campaign: str):
        if not campaign:
            return
        if campaign not in self.campaigns:
            messagebox.showerror("KonnaxionDiag", f"Campagne inconnue : {campaign}")
            return
        self._prepare_campaign(campaign)
        self.run_command(["run", campaign], label=campaign, campaign=campaign)

    def run_command(self, args, *, label: str = "Commande", campaign: str | None = None, clear: bool = True):
        if self.proc and self.proc.poll() is None:
            messagebox.showwarning("KonnaxionDiag", "Un diagnostic est déjà en cours.")
            return
        if clear:
            self.clear_log()
        if campaign is None:
            self.current_campaign = None
        cmd = [sys.executable, str(ROOT / "kdiag.py"), *args]
        self.stop_button.configure(state="normal")
        self.status_text.set(f"Exécution : {label}")

        def worker():
            try:
                self.proc = subprocess.Popen(
                    cmd,
                    cwd=str(ROOT),
                    env=diagnostic_subprocess_env(),
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=False,
                    shell=False,
                    bufsize=0,
                    **hidden_process_kwargs(),
                )
                assert self.proc.stdout is not None
                for raw_line in self.proc.stdout:
                    self.q.put(("log", decode_process_output(raw_line)))
                code = self.proc.wait()
                self.q.put(("exit", code, campaign, label))
            except Exception as exc:
                self.q.put(("error", f"{type(exc).__name__}: {exc}", campaign, label))

        threading.Thread(target=worker, daemon=True).start()

    def stop(self):
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.terminate()
                self.status_text.set("Arrêt demandé…")
            except OSError:
                pass

    def close(self):
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.terminate()
            except OSError:
                pass
        self.destroy()

    def drain(self):
        try:
            while True:
                event = self.q.get_nowait()
                kind = event[0]
                if kind == "log":
                    self.append(event[1])
                elif kind == "exit":
                    _, code, campaign, label = event
                    self.append(f"\n[{log_timestamp()}] [process exit {code}]\n")
                    if campaign:
                        self._load_current_summary()
                    self.stop_button.configure(state="disabled")
                    self.status_text.set(f"Terminé : {label} (code {code})")
                    self.kpi_run.set("PASS" if code == 0 else f"code {code}")
                    self.current_campaign = campaign
                    self._refresh_kpis()
                elif kind == "error":
                    _, detail, campaign, label = event
                    self.append(f"\n[{log_timestamp()}] [launcher error] {detail}\n")
                    self.stop_button.configure(state="disabled")
                    self.status_text.set(f"Erreur : {label}")
        except queue.Empty:
            pass
        self.after(100, self.drain)

    def _load_current_summary(self):
        try:
            summary = json.loads((self._evidence_dir() / "summary.json").read_text(encoding="utf-8"))
            for row in summary.get("levels", []):
                lid = str(row.get("id", ""))
                verdict = str(row.get("verdict", ""))
                if lid and verdict:
                    self._set_level_status(lid, verdict)
        except Exception:
            pass

    def _evidence_dir(self) -> Path:
        cfg = json.loads((ROOT / "kdiag.config.json").read_text(encoding="utf-8"))
        raw = cfg.get("target_repo_root", "auto")
        if str(raw).lower() == "auto":
            parent = ROOT.parent
            target = (parent / "Konnaxion") if (parent / "Konnaxion").is_dir() else parent
        else:
            p = Path(str(raw)).expanduser()
            target = p if p.is_absolute() else ROOT / p
        return (target / cfg.get("control_dir", ".konnaxiondiag") / "current").resolve(strict=False)

    def open_evidence(self):
        try:
            evidence = self._evidence_dir()
            evidence.mkdir(parents=True, exist_ok=True)
            if os.name == "nt":
                os.startfile(evidence)  # type: ignore[attr-defined]
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(evidence)])
            else:
                subprocess.Popen(["xdg-open", str(evidence)])
        except Exception as exc:
            messagebox.showerror("KonnaxionDiag", str(exc))


if __name__ == "__main__":
    App().mainloop()
