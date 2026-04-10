#!/usr/bin/env python3
import argparse
import time
import urllib3
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from config import CONFIG
from modules import (
    ASNIPEnumerator, DomainSubdomainEnumerator, SSLCertEnumerator,
    WebAppAPIScanner, CloudMisconfigScanner, InternalInfraScanner,
    SocialEngineeringRecon, ThirdPartyExposureScanner, PhysicalAssetScanner,
    ShadowITDetector, ReportGenerator,
)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
console = Console()

# Map numbers AND names to module keys
MODULE_MAP = {
    "1": "asn", "asn": "asn",
    "2": "domains", "domains": "domains",
    "3": "certs", "certs": "certs",
    "4": "webapps", "webapps": "webapps",
    "5": "cloud", "cloud": "cloud",
    "6": "internal", "internal": "internal",
    "7": "social", "social": "social",
    "8": "thirdparty", "thirdparty": "thirdparty",
    "9": "physical", "physical": "physical",
}

def banner():
    console.print(Panel('''
    ATTACK SURFACE MAPPING TOOL (ASM) v1.0

    Modules (use number or name with -m):
    [1] asn          ASN & IP Enumeration
    [2] domains      Domain & Subdomain Enumeration
    [3] certs        SSL/TLS Certificate Analysis
    [4] webapps      Web App & API Scanning
    [5] cloud        Cloud Misconfiguration
    [6] internal     Internal Infrastructure
    [7] social       Social Engineering Recon
    [8] thirdparty   Third-Party Exposure
    [9] physical     Physical Asset Discovery

    Examples:
      python main.py -d target.com -m 1
      python main.py -d target.com -m asn,domains,certs
      python main.py -d target.com -m 1,2,3
      python main.py -d target.com              (runs all)
    ''', style="bold cyan"))

def resolve_modules(mod_input):
    if mod_input == "all":
        return ["asn", "domains", "certs", "webapps", "cloud", "internal", "social", "thirdparty", "physical"]
    resolved = []
    for m in mod_input.split(","):
        m = m.strip().lower()
        if m in MODULE_MAP:
            resolved.append(MODULE_MAP[m])
        else:
            console.print(f"[bold red][!] Unknown module: '{m}' — skipping[/bold red]")
            console.print(f"    Valid: 1-9 or asn,domains,certs,webapps,cloud,internal,social,thirdparty,physical")
    if not resolved:
        console.print("[bold red][!] No valid modules selected. Running all.[/bold red]")
        return ["asn", "domains", "certs", "webapps", "cloud", "internal", "social", "thirdparty", "physical"]
    return resolved

def main():
    banner()
    parser = argparse.ArgumentParser(description="Attack Surface Mapper")
    parser.add_argument("-d", "--domain", required=True)
    parser.add_argument("-c", "--company", default=None)
    parser.add_argument("-m", "--modules", default="all")
    parser.add_argument("-o", "--output", default="./output")
    parser.add_argument("--no-report", action="store_true")
    args = parser.parse_args()

    domain = args.domain.strip().lower()
    company = args.company
    CONFIG["OUTPUT_DIR"] = args.output
    mods = resolve_modules(args.modules)

    console.print(f"\n[bold green]Target: {domain}[/bold green]")
    if company:
        console.print(f"[bold green]Company: {company}[/bold green]")
    console.print(f"[bold green]Modules: {', '.join(mods)}[/bold green]")
    console.print(f"[bold green]Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/bold green]\n")

    results = {}
    start = time.time()

    def run_mod(name, cls, *a, **kw):
        try:
            results[name] = cls(CONFIG).run(*a, **kw)
        except Exception as e:
            console.print(f"[red][-] {name} error: {e}[/red]")
            results[name] = {"error": str(e), "shadow_it_flags": [], "next_steps": []}

    if "asn" in mods:
        run_mod("asn_ip", ASNIPEnumerator, domain, company)
    if "domains" in mods:
        run_mod("domain_subdomain", DomainSubdomainEnumerator, domain, company)

    subs = results.get("domain_subdomain", {}).get("subdomains", [])

    if "certs" in mods:
        run_mod("ssl_cert", SSLCertEnumerator, domain, subs)
        subs.extend(results.get("ssl_cert", {}).get("cert_subdomains", []))
    if "webapps" in mods:
        run_mod("web_app_api", WebAppAPIScanner, domain, subs)
    if "cloud" in mods:
        run_mod("cloud_misconfig", CloudMisconfigScanner, domain, company, subs)
    if "internal" in mods:
        run_mod("internal_infra", InternalInfraScanner, domain, subs, results.get("asn_ip", {}).get("open_ports", {}))
    if "social" in mods:
        run_mod("social_engineering", SocialEngineeringRecon, domain, company)
    if "thirdparty" in mods:
        run_mod("third_party", ThirdPartyExposureScanner, domain, subs, None)
    if "physical" in mods:
        run_mod("physical_assets", PhysicalAssetScanner, domain, company, None, results.get("asn_ip", {}).get("open_ports", {}))

    shadow = ShadowITDetector(CONFIG).run(results)

    if not args.no_report:
        ReportGenerator(CONFIG).generate(domain, results, shadow)

    console.print(f"\n[bold green]Done in {time.time()-start:.1f}s[/bold green]")
    console.print(f"[bold green]Output: {CONFIG['OUTPUT_DIR']}[/bold green]")

if __name__ == "__main__":
    main()