import json
import os
from datetime import datetime
from rich.console import Console
from rich.table import Table

console = Console()


class ReportGenerator:
    def __init__(self, config):
        self.config = config
        self.output_dir = config.get("OUTPUT_DIR", "./output")
        os.makedirs(self.output_dir, exist_ok=True)

    def generate(self, target_domain, all_results, shadow_it_results):
        console.print(f"\n[bold cyan]  Generating Reports...[/bold cyan]\n")
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_path = os.path.join(self.output_dir, f"asm_{target_domain}_{ts}.json")
        html_path = os.path.join(self.output_dir, f"asm_{target_domain}_{ts}.html")
        self._json_report(target_domain, all_results, shadow_it_results, json_path)
        self._html_report(target_domain, all_results, shadow_it_results, html_path)
        self._console_summary(target_domain, all_results, shadow_it_results)
        console.print(f"\n[bold green][+] JSON: {json_path}[/bold green]")
        console.print(f"[bold green][+] HTML: {html_path}[/bold green]")

    def _json_report(self, domain, results, shadow_it, path):
        report = {"metadata": {"target": domain, "scan_date": datetime.now().isoformat(), "tool": "ASM v1.0"}, "results": {}, "shadow_it": shadow_it}
        for mod, res in results.items():
            if isinstance(res, dict):
                report["results"][mod] = self._ser(res)
        with open(path, "w") as f:
            json.dump(report, f, indent=2, default=str)

    def _html_report(self, domain, results, shadow_it, path):
        stats = self._stats(results)
        rs = shadow_it.get("risk_score", 0)
        rc = "#ff0000" if rs >= 75 else "#ff6b6b" if rs >= 50 else "#ffa502" if rs >= 25 else "#2ed573"
        html = f'<!DOCTYPE html><html><head><meta charset="UTF-8"><title>ASM - {domain}</title>'
        html += '<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:Segoe UI,sans-serif;background:#0a0a0f;color:#e0e0e0;line-height:1.6}.container{max-width:1200px;margin:0 auto;padding:20px}h1{color:#00d4ff;border-bottom:2px solid #00d4ff;padding-bottom:10px;margin-bottom:20px}h2{color:#ff6b6b;margin:20px 0 10px}h3{color:#ffa502;margin:15px 0 8px}.card{background:#1a1a2e;border:1px solid #333;border-radius:8px;padding:20px;margin:15px 0}table{width:100%;border-collapse:collapse;margin:10px 0}th,td{padding:8px 12px;text-align:left;border-bottom:1px solid #333}th{background:#16213e;color:#00d4ff}tr:hover{background:#16213e}.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:bold}.badge-critical{background:#ff0000;color:white}.badge-high{background:#ff6b6b;color:white}.badge-medium{background:#ffa502;color:black}.shadow-it{background:#2d1b69;border:1px solid #6c5ce7}.next-step{background:#1a2d1a;border:1px solid #2ed573;padding:10px;margin:5px 0;border-radius:4px}.stats{display:flex;gap:20px;flex-wrap:wrap;margin:20px 0}.stat-card{background:#16213e;padding:15px 20px;border-radius:8px;text-align:center;flex:1;min-width:150px}.stat-number{font-size:2em;font-weight:bold;color:#00d4ff}.stat-label{color:#888}.risk-score{font-size:3em;font-weight:bold;text-align:center;padding:20px}code{background:#16213e;padding:2px 6px;border-radius:3px}</style>'
        html += f'</head><body><div class="container"><h1>Attack Surface Map - {domain}</h1>'
        html += f'<p>Scan: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>'
        html += f'<div class="risk-score" style="color:{rc}">Shadow IT Risk: {rs}/100</div>'
        html += f'<div class="stats"><div class="stat-card"><div class="stat-number">{stats["ips"]}</div><div class="stat-label">IPs</div></div><div class="stat-card"><div class="stat-number">{stats["subs"]}</div><div class="stat-label">Subdomains</div></div><div class="stat-card"><div class="stat-number">{stats["certs"]}</div><div class="stat-label">Certs</div></div><div class="stat-card"><div class="stat-number">{stats["shadow"]}</div><div class="stat-label">Shadow IT</div></div></div>'
        for mod, res in results.items():
            if not isinstance(res, dict):
                continue
            html += f'<h2>{mod.replace("_"," ").title()}</h2>'
            for key, val in res.items():
                if key in ["next_steps", "shadow_it_flags"]:
                    continue
                if isinstance(val, list) and val:
                    html += f'<div class="card"><h3>{key.replace("_"," ").title()} ({len(val)})</h3><table>'
                    if isinstance(val[0], dict):
                        hdrs = list(val[0].keys())[:5]
                        html += '<tr>' + ''.join(f'<th>{h}</th>' for h in hdrs) + '</tr>'
                        for item in val[:30]:
                            html += '<tr>' + ''.join(f'<td>{str(item.get(h,""))[:80]}</td>' for h in hdrs) + '</tr>'
                    html += '</table></div>'
        html += '<h2>Shadow IT</h2>'
        for cat in shadow_it.get("shadow_it_summary", []):
            html += f'<div class="card shadow-it"><h3>{cat["category"]} ({cat["count"]})</h3><table><tr><th>Type</th><th>Asset</th><th>Reason</th></tr>'
            for i in cat.get("items", []):
                html += f'<tr><td>{i.get("type","")}</td><td><code>{i.get("asset","")}</code></td><td>{i.get("reason","")}</td></tr>'
            html += '</table></div>'
        html += '<h2>Next Steps</h2>'
        all_steps = []
        for mod, res in results.items():
            if isinstance(res, dict):
                for s in res.get("next_steps", []):
                    s["module"] = mod
                    all_steps.append(s)
        prio = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        all_steps.sort(key=lambda x: prio.get(x.get("priority", "LOW"), 4))
        for s in all_steps:
            p = s.get("priority", "MEDIUM").lower()
            html += f'<div class="next-step"><span class="badge badge-{p}">{s.get("priority","")}</span> <strong>{s.get("action","")}</strong> [{s.get("module","").replace("_"," ")}]<br>{s.get("description","")}</div>'
        html += '</div></body></html>'
        with open(path, "w") as f:
            f.write(html)

    def _console_summary(self, domain, results, shadow_it):
        stats = self._stats(results)
        table = Table(title=f"Attack Surface Summary - {domain}")
        table.add_column("Metric", style="cyan")
        table.add_column("Count", style="bold white")
        table.add_row("IPs", str(stats["ips"]))
        table.add_row("Subdomains", str(stats["subs"]))
        table.add_row("Certificates", str(stats["certs"]))
        table.add_row("Shadow IT", str(stats["shadow"]))
        table.add_row("Risk Score", f'{shadow_it.get("risk_score", 0)}/100')
        console.print(table)
        console.print("\n[bold cyan]  NEXT STEPS:[/bold cyan]")
        all_steps = []
        for mod, res in results.items():
            if isinstance(res, dict):
                for s in res.get("next_steps", []):
                    s["module"] = mod
                    all_steps.append(s)
        prio = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        all_steps.sort(key=lambda x: prio.get(x.get("priority", "LOW"), 4))
        for i, s in enumerate(all_steps, 1):
            p = s.get("priority", "MEDIUM")
            c = "bold red" if p == "CRITICAL" else "bold yellow" if p == "HIGH" else "white"
            console.print(f"\n  [{c}]{i}. [{p}] {s.get('action', '')}[/{c}]")
            console.print(f"     {s.get('description', '')}")

    def _stats(self, results):
        s = {"ips": 0, "subs": 0, "certs": 0, "shadow": 0}
        for mod, res in results.items():
            if not isinstance(res, dict):
                continue
            s["shadow"] += len(res.get("shadow_it_flags", []))
            if mod == "asn_ip":
                s["ips"] += len(res.get("ip_addresses", []))
            elif mod == "domain_subdomain":
                s["subs"] += len(res.get("subdomains", []))
            elif mod == "ssl_cert":
                s["certs"] += len(res.get("certificates", []))
                s["subs"] += len(res.get("cert_subdomains", []))
        return s

    def _ser(self, obj):
        if isinstance(obj, dict):
            return {k: self._ser(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._ser(i) for i in obj]
        elif isinstance(obj, (int, float, str, bool, type(None))):
            return obj
        return str(obj)
