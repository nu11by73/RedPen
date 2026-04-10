from rich.console import Console

console = Console()


class ShadowITDetector:
    def __init__(self, config):
        self.config = config
        self.results = {"shadow_it_summary": [], "risk_score": 0, "recommendations": []}

    def run(self, all_module_results):
        console.print(f"\n[bold cyan]{'='*60}[/bold cyan]")
        console.print(f"[bold cyan]  Shadow IT Detection & Analysis[/bold cyan]")
        console.print(f"[bold cyan]{'='*60}[/bold cyan]\n")
        all_flags = []
        for mod, res in all_module_results.items():
            if isinstance(res, dict):
                for f in res.get("shadow_it_flags", []):
                    f["module"] = mod
                    all_flags.append(f)
        self._categorize(all_flags)
        self._score(all_flags)
        self._recommend()
        return self.results

    def _categorize(self, flags):
        cats = {"Cloud Services": [], "Devices & Endpoints": [], "Dev/Test Environments": [], "Exposed Infrastructure": [], "SaaS Shadow IT": [], "Code & Credential Leaks": [], "Legacy Systems": [], "Other": []}
        for f in flags:
            t = f.get("type", "").lower()
            if any(k in t for k in ["cloud", "s3", "bucket", "azure", "gcp"]):
                cats["Cloud Services"].append(f)
            elif any(k in t for k in ["device", "iot", "physical"]):
                cats["Devices & Endpoints"].append(f)
            elif any(k in t for k in ["suspicious subdomain"]):
                cats["Dev/Test Environments"].append(f)
            elif any(k in t for k in ["exposed", "kubernetes", "database", "network"]):
                cats["Exposed Infrastructure"].append(f)
            elif any(k in t for k in ["saas"]):
                cats["SaaS Shadow IT"].append(f)
            elif any(k in t for k in ["code", "secret", "credential"]):
                cats["Code & Credential Leaks"].append(f)
            elif any(k in t for k in ["legacy", "eol", "weak tls"]):
                cats["Legacy Systems"].append(f)
            else:
                cats["Other"].append(f)
        for cat, items in cats.items():
            if items:
                console.print(f"\n[bold magenta]  {cat} ({len(items)} findings)[/bold magenta]")
                for item in items:
                    console.print(f"    [bold]{item.get('type')}[/bold]: {item.get('asset', 'N/A')}")
                    console.print(f"      {item.get('reason', '')}")
                self.results["shadow_it_summary"].append({"category": cat, "count": len(items), "items": items})

    def _score(self, flags):
        score = 0
        for f in flags:
            t = f.get("type", "").lower()
            if any(k in t for k in ["database", "credential", "code leak", "kubernetes", "cloud storage"]):
                score += 10
            elif any(k in t for k in ["iot", "device", "legacy", "network"]):
                score += 7
            else:
                score += 4
        mx = len(flags) * 10 if flags else 1
        self.results["risk_score"] = min(100, int((score / mx) * 100))
        rs = self.results["risk_score"]
        color = "bold red" if rs >= 75 else "bold yellow" if rs >= 50 else "yellow" if rs >= 25 else "green"
        console.print(f"\n[{color}]  Shadow IT Risk Score: {rs}/100[/{color}]")

    def _recommend(self):
        self.results["recommendations"] = [
            {"title": "Monthly ASM Scans", "description": "Run attack surface scans monthly.", "priority": "HIGH"},
            {"title": "Deploy CASB", "description": "Detect unauthorized cloud services.", "priority": "HIGH"},
            {"title": "Asset Reconciliation", "description": "Cross-reference findings with CMDB.", "priority": "CRITICAL"},
            {"title": "Developer Training", "description": "Secure deployment and secret management.", "priority": "MEDIUM"},
            {"title": "Self-Service IT", "description": "Provide approved tools to reduce shadow IT.", "priority": "MEDIUM"},
        ]
        console.print("\n[bold cyan]  Recommendations:[/bold cyan]")
        for r in self.results["recommendations"]:
            console.print(f"    [{r['priority']}] {r['title']}: {r['description']}")
