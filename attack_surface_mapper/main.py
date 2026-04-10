#!/usr/bin/env python3
import argparse
import time
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

console = Console()

def banner():
    console.print(Panel('''
    ATTACK SURFACE MAPPING TOOL (ASM) v1.0
    [1] ASN/IP  [2] Domains  [3] SSL/TLS  [4] WebApps  [5] Cloud
    [6] Internal  [7] Social Eng  [8] Third-Party  [9] Physical  [10] Shadow IT
    ''', style="bold cyan"))

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
    mods = (["asn","domains","certs","webapps","cloud","internal","social","thirdparty","physical"]
            if args.modules == "all" else [m.strip() for m in args.modules.split(",")])

    console.print(f"\n[bold green]Target: {domain}[/bold green]")
    if company: console.print(f"[bold green]Company: {company}[/bold green]")
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

    if "asn" in mods: run_mod("asn_ip", ASNIPEnumerator, domain, company)
    if "domains" in mods: run_mod("domain_subdomain", DomainSubdomainEnumerator, domain, company)
    subs = results.get("domain_subdomain", {}).get("subdomains", [])
    if "certs" in mods:
        run_mod("ssl_cert", SSLCertEnumerator, domain, subs)
        subs.extend(results.get("ssl_cert", {}).get("cert_subdomains", []))
    if "webapps" in mods: run_mod("web_app_api", WebAppAPIScanner, domain, subs)
    if "cloud" in mods: run_mod("cloud_misconfig", CloudMisconfigScanner, domain, company, subs)
    if "internal" in mods: run_mod("internal_infra", InternalInfraScanner, domain, subs, results.get("asn_ip", {}).get("open_ports", {}))
    if "social" in mods: run_mod("social_engineering", SocialEngineeringRecon, domain, company)
    if "thirdparty" in mods: run_mod("third_party", ThirdPartyExposureScanner, domain, subs, None)
    if "physical" in mods: run_mod("physical_assets", PhysicalAssetScanner, domain, company, None, results.get("asn_ip", {}).get("open_ports", {}))

    shadow = ShadowITDetector(CONFIG).run(results)
    if not args.no_report:
        ReportGenerator(CONFIG).generate(domain, results, shadow)

    console.print(f"\n[bold green]Done in {time.time()-start:.1f}s[/bold green]")
    console.print(f"[bold green]Output: {CONFIG['OUTPUT_DIR']}[/bold green]")

if __name__ == "__main__":
    main()
