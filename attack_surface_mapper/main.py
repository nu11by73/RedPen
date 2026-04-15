#!/usr/bin/env python3
import argparse
import time
import urllib3
import requests
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from config import CONFIG

from modules import (
    ASNIPEnumerator, DomainSubdomainEnumerator, SSLCertEnumerator,
    WebAppAPIScanner, CloudMisconfigScanner, InternalInfraScanner,
    SocialEngineeringRecon, ThirdPartyExposureScanner, PhysicalAssetScanner,
    ShadowITDetector, ReportGenerator, SecretScanner, WebVulnScanner,
)

from modules import (
    ASNIPEnumerator, DomainSubdomainEnumerator, SSLCertEnumerator,
    WebAppAPIScanner, CloudMisconfigScanner, InternalInfraScanner,
    SocialEngineeringRecon, ThirdPartyExposureScanner, PhysicalAssetScanner,
    ShadowITDetector, ReportGenerator, SecretScanner, WebVulnScanner,
)

# ADD THIS:
from modules.cf_scanner import CloudflareScanner
# Import post-filter for exposed endpoint false positives
try:
    from modules.web_app_api import _post_filter_exposed_endpoints
    HAS_POST_FILTER = True
except ImportError:
    HAS_POST_FILTER = False

# Import Google dorking
try:
    from modules.google_dorking import GoogleDorker
    HAS_DORKING = True
except ImportError:
    HAS_DORKING = False
try:
    from modules.dork_alternative import DorkAlternative
    HAS_PASSIVE_DORKING = True
except ImportError:
    HAS_PASSIVE_DORKING = False

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

console = Console()

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
    "10": "secrets", "secrets": "secrets",
    "11": "vulnscan", "vulnscan": "vulnscan",
    "12": "cloudflare", "cloudflare": "cloudflare",
}


def banner():
    console.print(Panel('''
    ╔══════════════════════════════════════════════════════════════╗
    ║           ATTACK SURFACE MAPPER  v2.0                        ║
    ║           Comprehensive Reconnaissance Framework             ║
    ╚══════════════════════════════════════════════════════════════╝
    ''', style="bold cyan"))


# ══════════════════════════════════════════════════════════════
#  GENERAL HELP
# ══════════════════════════════════════════════════════════════

def print_help_general():
    help_text = """
  [bold white]USAGE:[/bold white]
    python main.py -d <domain> [OPTIONS]

  [bold white]REQUIRED:[/bold white]
    -d, --domain <domain>       Target domain (e.g., example.com)

  [bold white]OPTIONS:[/bold white]
    -c, --company <name>        Company name (improves ASN/social results)
    -m, --modules <modules>     Modules to run (comma-separated, number, or "all")
    -o, --output <dir>          Output directory (default: ./output)
    --no-report                 Skip HTML report generation
    --no-dorking                Skip Google dorking
    -v, --verbose               Enable verbose/debug output
    -h, --help                  Show help (add -m <module> for module-specific help)

  [bold white]═══════════════════════════════════════════════════════════════[/bold white]
  [bold white] #    MODULE         DESCRIPTION[/bold white]
  [bold white]═══════════════════════════════════════════════════════════════[/bold white]
   [cyan][1][/cyan]   asn            ASN & IP range enumeration
   [cyan][2][/cyan]   domains        Domain & subdomain discovery
   [cyan][3][/cyan]   certs          SSL/TLS certificate transparency
   [cyan][4][/cyan]   webapps        Web application & API scanning
   [cyan][5][/cyan]   cloud          Cloud misconfiguration detection
   [cyan][6][/cyan]   internal       Internal infrastructure recon
   [cyan][7][/cyan]   social         Social engineering reconnaissance
   [cyan][8][/cyan]   thirdparty     Third-party exposure scanning
   [cyan][9][/cyan]   physical       Physical asset discovery
   [cyan][10][/cyan]  secrets        Secret & credential scanning
   [cyan][11][/cyan]  vulnscan       Web vulnerability scanner
   [cyan][12][/cyan]  cloudflare     Cloudflare detection & origin IP discovery
  [bold white]═══════════════════════════════════════════════════════════════[/bold white]

  [bold yellow]QUICK START:[/bold yellow]
    python main.py -d example.com                        Run all modules
    python main.py -d example.com -m domains,certs       Quick recon
    python main.py -d example.com -m vulnscan            Vuln scan only
    python main.py -d example.com -m 1,2,3               By number

  [bold yellow]MODULE-SPECIFIC HELP:[/bold yellow]
    python main.py -m asn -h          Detailed help for ASN module
    python main.py -m vulnscan -h     Detailed help for vuln scanner
    python main.py -m 1 -h            By number works too
"""
    console.print(help_text)


# ══════════════════════════════════════════════════════════════
#  PER-MODULE HELP
# ══════════════════════════════════════════════════════════════

MODULE_HELP = {
    "asn": {
        "name": "ASN & IP Enumeration",
        "number": 1,
        "description": """
    Discovers Autonomous System Numbers (ASNs) and IP ranges
    associated with the target. Identifies network blocks owned
    or operated by the organization.""",
        "what_it_does": [
            "ASN lookup via BGP data sources",
            "IP range enumeration per ASN",
            "Reverse WHOIS on organization name",
            "Port scanning on discovered IPs (top ports)",
            "Network block ownership identification",
        ],
        "config_keys": [
            ("REQUEST_TIMEOUT", "10", "HTTP request timeout in seconds"),
        ],
        "examples": [
            ("Basic ASN scan", "python main.py -d example.com -m asn"),
            ("With company name (better results)", "python main.py -d example.com -c 'Example Corp' -m asn"),
            ("ASN + domain recon", "python main.py -d example.com -c 'Example Corp' -m asn,domains"),
            ("Network mapping combo", "python main.py -d example.com -m asn,domains,certs"),
            ("Full infra mapping", "python main.py -d example.com -c 'Example Corp' -m asn,domains,certs,internal"),
        ],
        "tips": [
            "Provide -c (company name) for much better ASN discovery",
            "ASN results feed into the 'internal' module for deeper infra scanning",
            "Run with 'domains' to correlate IP ranges with subdomains",
        ],
    },

    "domains": {
        "name": "Domain & Subdomain Discovery",
        "number": 2,
        "description": """
    Enumerates subdomains using multiple passive and active sources.
    Discovered subdomains are passed to all subsequent modules.""",
        "what_it_does": [
            "Passive subdomain enumeration (multiple APIs)",
            "DNS brute-forcing common subdomain names",
            "Google dorking for indexed subdomains (if enabled)",
            "Wildcard DNS detection",
            "Subdomain validation and deduplication",
            "Zone transfer attempts",
        ],
        "config_keys": [
            ("GOOGLE_API_KEY", '""', "Google Custom Search API key (avoids CAPTCHA)"),
            ("GOOGLE_CX_ID", '""', "Google Custom Search Engine ID"),
            ("GOOGLE_DORKING_ENABLED", "True", "Enable/disable Google dorking"),
            ("GOOGLE_DORKING_MAX_PAGES", "5", "Pages per dork query"),
        ],
        "examples": [
            ("Basic subdomain scan", "python main.py -d example.com -m domains"),
            ("Domains + certs (recommended)", "python main.py -d example.com -m domains,certs"),
            ("Skip Google dorking", "python main.py -d example.com -m domains --no-dorking"),
            ("With company name", "python main.py -d example.com -c 'Example Corp' -m domains"),
            ("Feed into vuln scanner", "python main.py -d example.com -m domains,certs,vulnscan"),
            ("Feed into everything", "python main.py -d example.com -m domains,certs,webapps,cloud,vulnscan"),
        ],
        "tips": [
            "Always run 'domains' before other modules — subdomains feed into all scanners",
            "Pair with 'certs' — certificate transparency adds many subdomains",
            "Set GOOGLE_API_KEY in config.py to avoid CAPTCHA during dorking",
            "Use --no-dorking if you don't have API keys and keep getting blocked",
        ],
    },

    "certs": {
        "name": "SSL/TLS Certificate Transparency",
        "number": 3,
        "description": """
    Queries Certificate Transparency logs to discover subdomains,
    analyzes SSL/TLS certificates for security issues, and identifies
    certificate misconfigurations.""",
        "what_it_does": [
            "Certificate Transparency log queries (crt.sh)",
            "Subdomain discovery from certificate SANs",
            "Certificate expiry checking",
            "Weak cipher suite detection",
            "Self-signed certificate detection",
            "Wildcard certificate identification",
            "Certificate chain validation",
        ],
        "config_keys": [
            ("REQUEST_TIMEOUT", "10", "Timeout for crt.sh queries"),
        ],
        "examples": [
            ("Cert scan only", "python main.py -d example.com -m certs"),
            ("Domains + certs (recommended pair)", "python main.py -d example.com -m domains,certs"),
            ("Full recon chain", "python main.py -d example.com -m domains,certs,webapps"),
            ("Cert + secrets (find exposed keys)", "python main.py -d example.com -m certs,secrets"),
        ],
        "tips": [
            "crt.sh can be slow/timeout — the module retries up to 3 times",
            "Certificate SANs often reveal subdomains not found by other methods",
            "Discovered cert subdomains automatically merge into the master list",
        ],
    },

    "webapps": {
        "name": "Web Application & API Scanning",
        "number": 4,
        "description": """
    Scans web applications and APIs for technologies, frameworks,
    exposed endpoints, default credentials, and misconfigurations.""",
        "what_it_does": [
            "Technology fingerprinting (CMS, frameworks, servers)",
            "Exposed admin panel detection",
            "API endpoint discovery",
            "Default credential checking",
            "WAF detection",
            "JavaScript library enumeration",
            "HTTP header analysis",
            "Exposed database tool detection (phpMyAdmin, Adminer, etc.)",
        ],
        "config_keys": [
            ("REQUEST_TIMEOUT", "10", "HTTP request timeout"),
            ("USER_AGENT", "...", "User-Agent string for requests"),
        ],
        "examples": [
            ("Web app scan only", "python main.py -d example.com -m webapps"),
            ("With subdomain discovery first", "python main.py -d example.com -m domains,certs,webapps"),
            ("Web scan + vuln scan", "python main.py -d example.com -m webapps,vulnscan"),
            ("Full web assessment", "python main.py -d example.com -m domains,certs,webapps,vulnscan,secrets"),
        ],
        "tips": [
            "Run 'domains' and 'certs' first so webapps scans ALL subdomains",
            "Results feed into the 'secrets' module for deeper analysis",
            "False positive filtering runs automatically on exposed endpoints",
        ],
    },

    "cloud": {
        "name": "Cloud Misconfiguration Detection",
        "number": 5,
        "description": """
    Checks for cloud infrastructure misconfigurations across AWS,
    Azure, and GCP. Detects exposed storage, misconfigured services,
    and cloud-specific vulnerabilities.""",
        "what_it_does": [
            "S3 bucket enumeration and permission checking",
            "Azure Blob storage discovery",
            "GCP storage bucket testing",
            "Cloud metadata endpoint detection",
            "Subdomain-based cloud service identification",
            "Public snapshot and AMI detection",
            "Cloud CDN misconfiguration checks",
        ],
        "config_keys": [
            ("REQUEST_TIMEOUT", "10", "HTTP request timeout"),
        ],
        "examples": [
            ("Cloud scan only", "python main.py -d example.com -m cloud"),
            ("Cloud + third-party", "python main.py -d example.com -m cloud,thirdparty"),
            ("With company name (better bucket guessing)", "python main.py -d example.com -c 'Example Corp' -m cloud"),
            ("Cloud exposure audit", "python main.py -d example.com -m domains,certs,cloud,thirdparty"),
            ("Full cloud assessment", "python main.py -d example.com -c 'Example Corp' -m domains,certs,cloud,secrets"),
        ],
        "tips": [
            "Provide -c (company name) for better S3/Azure bucket name guessing",
            "Run 'domains' first so cloud checks cover all subdomains",
            "Combine with 'secrets' to find leaked cloud credentials",
        ],
    },

    "internal": {
        "name": "Internal Infrastructure Recon",
        "number": 6,
        "description": """
    Discovers internal infrastructure exposure including private
    network leaks, internal hostnames, VPN endpoints, and
    infrastructure management interfaces.""",
        "what_it_does": [
            "Internal hostname and IP leak detection",
            "VPN endpoint discovery",
            "Management interface detection (IPMI, iLO, DRAC)",
            "Internal subdomain pattern identification",
            "Network device fingerprinting",
            "DNS configuration analysis",
            "Private IP address disclosure detection",
        ],
        "config_keys": [
            ("REQUEST_TIMEOUT", "10", "HTTP request timeout"),
        ],
        "examples": [
            ("Internal scan only", "python main.py -d example.com -m internal"),
            ("With ASN data (feeds open ports)", "python main.py -d example.com -m asn,internal"),
            ("Internal + cloud", "python main.py -d example.com -m internal,cloud"),
            ("Full infra assessment", "python main.py -d example.com -m asn,domains,certs,internal,cloud"),
        ],
        "tips": [
            "Run 'asn' first — discovered open ports feed into internal scanning",
            "Run 'domains' first — subdomains like vpn.*, internal.* get flagged",
            "Internal findings often reveal shadow IT infrastructure",
        ],
    },

    "social": {
        "name": "Social Engineering Reconnaissance",
        "number": 7,
        "description": """
    Gathers social engineering intelligence including employee
    information, email formats, social media presence, and
    organizational data useful for phishing assessments.""",
        "what_it_does": [
            "Email format detection (first.last@, f.last@, etc.)",
            "Employee name harvesting from public sources",
            "Social media profile discovery",
            "Organizational chart inference",
            "Job posting analysis (reveals tech stack)",
            "Public document metadata extraction",
            "Email address pattern validation",
        ],
        "config_keys": [
            ("REQUEST_TIMEOUT", "10", "HTTP request timeout"),
        ],
        "examples": [
            ("Social recon only", "python main.py -d example.com -m social"),
            ("With company name (much better results)", "python main.py -d example.com -c 'Example Corp' -m social"),
            ("Social engineering prep", "python main.py -d example.com -c 'Example Corp' -m social,domains,thirdparty"),
            ("Phishing assessment prep", "python main.py -d example.com -c 'Example Corp' -m social,domains"),
        ],
        "tips": [
            "Always provide -c (company name) — dramatically improves results",
            "Combine with 'thirdparty' to find leaked credentials for discovered employees",
            "Job postings often reveal internal technology stacks",
        ],
    },

    "thirdparty": {
        "name": "Third-Party Exposure Scanning",
        "number": 8,
        "description": """
    Discovers third-party services, SaaS integrations, and external
    dependencies that expand the attack surface. Checks for data
    leaks on paste sites and code repositories.""",
        "what_it_does": [
            "Third-party SaaS integration detection",
            "GitHub/GitLab code leak scanning",
            "Paste site monitoring (Pastebin, etc.)",
            "DNS TXT record analysis (SPF, DKIM reveals services)",
            "JavaScript third-party library detection",
            "Supply chain dependency mapping",
            "Breach database references",
        ],
        "config_keys": [
            ("REQUEST_TIMEOUT", "10", "HTTP request timeout"),
        ],
        "examples": [
            ("Third-party scan only", "python main.py -d example.com -m thirdparty"),
            ("Cloud + third-party exposure", "python main.py -d example.com -m cloud,thirdparty"),
            ("External exposure audit", "python main.py -d example.com -m domains,certs,cloud,thirdparty,secrets"),
            ("Supply chain check", "python main.py -d example.com -m thirdparty,webapps"),
        ],
        "tips": [
            "DNS TXT records (SPF/DKIM) reveal which third-party services are authorized",
            "Run 'domains' first so all subdomains are checked for third-party references",
            "Combine with 'secrets' to find API keys for discovered third-party services",
        ],
    },

    "physical": {
        "name": "Physical Asset Discovery",
        "number": 9,
        "description": """
    Discovers physical and IoT assets associated with the target
    including office locations, network devices, printers, cameras,
    and other connected hardware.""",
        "what_it_does": [
            "IoT device discovery (cameras, printers, SCADA)",
            "Shodan/Censys integration for internet-facing devices",
            "Network device identification",
            "Office location inference",
            "Building management system detection",
            "Physical security system identification",
            "Industrial control system (ICS) detection",
        ],
        "config_keys": [
            ("REQUEST_TIMEOUT", "10", "HTTP request timeout"),
        ],
        "examples": [
            ("Physical asset scan", "python main.py -d example.com -m physical"),
            ("With company name", "python main.py -d example.com -c 'Example Corp' -m physical"),
            ("With ASN data (feeds open ports)", "python main.py -d example.com -m asn,physical"),
            ("Full physical assessment", "python main.py -d example.com -c 'Example Corp' -m asn,domains,physical"),
        ],
        "tips": [
            "Run 'asn' first — open port data feeds into physical device detection",
            "Provide -c (company name) for better results",
            "Look for IoT devices on non-standard ports discovered by ASN scanning",
        ],
    },

    "secrets": {
        "name": "Secret & Credential Scanner",
        "number": 10,
        "description": """
    Scans discovered web pages, JavaScript files, and API responses
    for leaked secrets including API keys, tokens, passwords,
    database connection strings, and private keys.""",
        "what_it_does": [
            "API key detection (AWS, Google, Azure, Stripe, etc.)",
            "Private key detection (RSA, SSH, PGP)",
            "Database connection string detection",
            "JWT token extraction and analysis",
            "Hardcoded password detection",
            "Environment variable leaks",
            "JavaScript source map analysis",
            "Regex-based pattern matching (100+ patterns)",
        ],
        "config_keys": [
            ("REQUEST_TIMEOUT", "10", "HTTP request timeout"),
        ],
        "examples": [
            ("Secret scan only", "python main.py -d example.com -m secrets"),
            ("With web app data (recommended)", "python main.py -d example.com -m webapps,secrets"),
            ("Full secret audit", "python main.py -d example.com -m domains,certs,webapps,secrets"),
            ("Web attack surface + secrets", "python main.py -d example.com -m domains,certs,webapps,vulnscan,secrets"),
        ],
        "tips": [
            "Run 'webapps' first — discovered pages/JS files feed into secret scanning",
            "Run 'domains' + 'certs' first for maximum subdomain coverage",
            "JavaScript files are a goldmine for leaked API keys",
            "Check results carefully — some patterns may have false positives",
        ],
    },

    "vulnscan": {
        "name": "Web Vulnerability Scanner",
        "number": 11,
        "description": """
    Active vulnerability scanner that tests discovered web
    applications for common security flaws including injection
    attacks, misconfigurations, and information disclosure.""",
        "what_it_does": [
            "SQL Injection (error-based, time-based blind)",
            "Cross-Site Scripting (reflected XSS)",
            "Path Traversal / Local File Inclusion (LFI)",
            "Command Injection",
            "Open Redirect detection",
            "CORS misconfiguration testing",
            "CRLF Injection",
            "CSRF token absence detection",
            "Security header analysis (HSTS, CSP, X-Frame-Options)",
            "Insecure cookie detection",
            "Server version/technology disclosure",
            "Sensitive path discovery (.git, .env, .svn, actuator)",
            "HTTP method testing (PUT, DELETE, TRACE)",
            "Subdomain takeover checks",
            "Directory listing detection",
            "Debug/error page exposure",
            "Automatic crawling and form discovery",
        ],
        "config_keys": [
            ("VULN_SCAN_LEVEL", '"standard"', "light | standard | thorough"),
            ("VULN_MAX_TARGETS", "30", "Max subdomains to scan"),
            ("VULN_MAX_PARAMS_PER_PAGE", "15", "Max parameters to test per page"),
            ("VULN_THREADS", "5", "Concurrent scan threads"),
            ("VULN_SQLI_TIME_THRESHOLD", "5", "Seconds delay for time-based SQLi"),
            ("VULN_CRAWL_DEPTH", "2", "How many levels deep to crawl"),
        ],
        "examples": [
            ("Vuln scan only", "python main.py -d example.com -m vulnscan"),
            ("With subdomain discovery first", "python main.py -d example.com -m domains,certs,vulnscan"),
            ("Full web assessment", "python main.py -d example.com -m domains,certs,webapps,vulnscan,secrets"),
            ("Verbose vuln scan", "python main.py -d example.com -m vulnscan -v"),
            ("Red team full chain", "python main.py -d example.com -m asn,domains,certs,webapps,cloud,vulnscan,secrets"),
        ],
        "scan_levels": [
            ("light", "Headers, cookies, path discovery only", "~1 min"),
            ("standard", "+ SQLi, XSS, CORS, crawling, forms", "~5 min"),
            ("thorough", "+ Time-based SQLi, cmd injection, all payloads", "~15 min"),
        ],
        "tips": [
            "Set VULN_SCAN_LEVEL in config.py: 'light', 'standard', or 'thorough'",
            "Run 'domains' + 'certs' first so all subdomains get scanned",
            "Use 'thorough' for time-based blind SQLi and command injection tests",
            "'light' is fast and safe — good for a quick header/config check",
            "Crawl depth of 2 is usually enough; increase for deep web apps",
        ],
    },
    "cloudflare": {
    "name": "Cloudflare Detection & Origin Discovery",
    "number": 12,
    "description": """
    Detects which hosts are behind Cloudflare CDN/WAF and attempts
    to discover the real origin IP addresses behind the proxy.""",
    "what_it_does": [
        "Cloudflare detection via IP ranges and HTTP headers",
        "Origin IP discovery via DNS subdomain brute-forcing",
        "MX/SPF/TXT record analysis for origin leaks",
        "DNS history lookups (SecurityTrails)",
        "Origin IP verification (confirms real server)",
        "CF challenge page detection",
    ],
    "config_keys": [
        ("REQUEST_TIMEOUT", "10", "HTTP request timeout"),
    ],
    "examples": [
        ("CF scan only", "python main.py -d example.com -m cloudflare"),
        ("With subdomain discovery", "python main.py -d example.com -m domains,certs,cloudflare"),
        ("Cloud + CF combo", "python main.py -d example.com -m domains,certs,cloud,cloudflare"),
        ("Full infra mapping", "python main.py -d example.com -m domains,certs,cloud,cloudflare,internal"),
    ],
    "tips": [
        "Run 'domains' and 'certs' first — more subdomains means more targets to check",
        "Origin IPs found with HIGH confidence should be verified manually",
        "Combine with 'cloud' module for full CDN/cloud assessment",
        "MX and SPF records are the most reliable origin leak vectors",
    ],
},
}


def print_module_help(module_key):
    """Print detailed help for a specific module."""
    info = MODULE_HELP.get(module_key)
    if not info:
        console.print(f"[bold red]  ✘ No help available for module: '{module_key}'[/bold red]")
        console.print(f"[bold red]    Valid modules: {', '.join(MODULE_HELP.keys())}[/bold red]\n")
        return

    console.print(f"\n[bold white]{'='*62}[/bold white]")
    console.print(f"[bold cyan]  [{info['number']}] {info['name'].upper()}[/bold cyan]")
    console.print(f"[bold white]{'='*62}[/bold white]")

    console.print(f"\n[bold white]  DESCRIPTION:[/bold white]")
    console.print(f"  {info['description'].strip()}")

    console.print(f"\n[bold white]  WHAT IT DOES:[/bold white]")
    for item in info['what_it_does']:
        console.print(f"    [cyan]•[/cyan] {item}")

    if info.get('config_keys'):
        console.print(f"\n[bold white]  CONFIG OPTIONS (config.py):[/bold white]")
        for key, default, desc in info['config_keys']:
            console.print(f"    [yellow]{key:<35}[/yellow] [dim](default: {default})[/dim]")
            console.print(f"      {desc}")

    if info.get('scan_levels'):
        console.print(f"\n[bold white]  SCAN LEVELS:[/bold white]")
        for level, desc, time_est in info['scan_levels']:
            color = {'light': 'green', 'standard': 'yellow', 'thorough': 'red'}.get(level, 'white')
            console.print(f"    [{color}]{level:<12}[/{color}] {desc:<50} {time_est}")

    console.print(f"\n[bold white]  EXAMPLES:[/bold white]")
    for label, cmd in info['examples']:
        console.print(f"    [bold yellow]{label}:[/bold yellow]")
        console.print(f"      [green]{cmd}[/green]")

    if info.get('tips'):
        console.print(f"\n[bold white]  TIPS:[/bold white]")
        for tip in info['tips']:
            console.print(f"    [cyan]💡[/cyan] {tip}")

    console.print(f"\n[bold white]{'='*62}[/bold white]\n")

def resolve_modules(mod_input):
    if mod_input == "all":
        return ["asn", "domains", "certs", "webapps", "cloud", "cloudflare", "internal", "social", "thirdparty", "physical", "secrets", "vulnscan"]
    resolved = []
    for m in mod_input.split(","):
        m = m.strip().lower()
        if m in MODULE_MAP:
            resolved.append(MODULE_MAP[m])
        else:
            console.print(f"[bold red][!] Unknown module: '{m}' — skipping[/bold red]")
            console.print(f"    Valid: 1-12 or asn,domains,certs,webapps,cloud,cloudflare,internal,social,thirdparty,physical,secrets,vulnscan")
    if not resolved:
        console.print("[bold red][!] No valid modules selected. Running all.[/bold red]")
        return ["asn", "domains", "certs", "webapps", "cloud", "internal", "social", "thirdparty", "physical", "secrets"]
    return resolved


def dedup_subdomains(subs):
    """Deduplicate and clean subdomain list. Handles strings and dicts."""
    seen = set()
    clean = []
    for s in subs:
        # Handle dicts: extract the subdomain string
        if isinstance(s, dict):
            s = s.get('subdomain', s.get('domain', s.get('name', s.get('host', ''))))
        # Handle anything else that isn't a string
        if not isinstance(s, str):
            try:
                s = str(s)
            except Exception:
                continue
        s_clean = s.strip().lower().rstrip('.')
        if s_clean and s_clean not in seen:
            seen.add(s_clean)
            clean.append(s_clean)
    return clean


def post_filter_results(results, shadow):
    """Remove false positive exposed endpoints from all result sections."""
    if not HAS_POST_FILTER:
        return results, shadow

    try:
        session = requests.Session()
        session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})
        session.verify = False

        # Filter web_app_api findings
        webapp = results.get("web_app_api", {})
        if isinstance(webapp, dict):
            for key in list(webapp.keys()):
                if isinstance(webapp[key], list) and webapp[key]:
                    # Only filter lists that might contain exposed endpoint findings
                    if any(isinstance(item, dict) and
                           any(kw in str(item.get('type', '')).lower() + str(item.get('reason', '')).lower()
                               for kw in ['exposed', 'phpmyadmin', 'adminer', 'database', 'panel'])
                           for item in webapp[key]):
                        webapp[key] = _post_filter_exposed_endpoints(webapp[key], session)

        # Filter shadow_it findings
        if isinstance(shadow, dict):
            for cat in shadow.get('shadow_it_summary', []):
                cat_name = cat.get('category', '')
                if 'Exposed' in cat_name or 'Infrastructure' in cat_name or 'Database' in cat_name:
                    cat['items'] = _post_filter_exposed_endpoints(cat.get('items', []), session)
                    cat['count'] = len(cat['items'])

        console.print("[green][+] Post-filter: exposed endpoint validation complete[/green]")
    except Exception as e:
        console.print(f"[yellow][!] Post-filter warning: {e}[/yellow]")

    return results, shadow


def main():
    banner()

    parser = argparse.ArgumentParser(
        description="Attack Surface Mapper",
        add_help=False,
    )
    parser.add_argument("-d", "--domain", type=str, default=None)
    parser.add_argument("-c", "--company", default=None)
    parser.add_argument("-m", "--modules", default="all")
    parser.add_argument("-o", "--output", default="./output")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--no-report", action="store_true")
    parser.add_argument("--no-dorking", action="store_true", help="Skip Google dorking")
    parser.add_argument("-h", "--help", action="store_true")
    args = parser.parse_args()

    # ── Help routing ──
    if args.help:
        mod_input = args.modules.strip().lower() if args.modules else "all"

        # If user specified a single module with -h, show module help
        if mod_input != "all":
            # Resolve module name (handle numbers)
            resolved = MODULE_MAP.get(mod_input)
            if resolved and resolved in MODULE_HELP:
                print_module_help(resolved)
                return
            # Maybe comma-separated — show help for first one
            first = mod_input.split(",")[0].strip()
            resolved = MODULE_MAP.get(first)
            if resolved and resolved in MODULE_HELP:
                print_module_help(resolved)
                if "," in mod_input:
                    console.print(f"  [dim](Showing help for '{resolved}'. For other modules, run: python main.py -m <module> -h)[/dim]\n")
                return

        # Default: show general help
        print_help_general()
        return

    # No domain provided — show general help with error
    if not args.domain:
        print_help_general()
        console.print("[bold red]  ✘ Error: -d / --domain is required.[/bold red]")
        console.print("[bold red]    Example: python main.py -d example.com[/bold red]\n")
        return

    # ── Normal execution ──
    domain = args.domain.strip().lower()
    company = args.company
    CONFIG["OUTPUT_DIR"] = args.output
    mods = resolve_modules(args.modules)

    if args.verbose:
        import logging
        logging.basicConfig(level=logging.DEBUG)

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

    # ── Phase 1: ASN & Domain Enumeration ──
    if "asn" in mods:
        run_mod("asn_ip", ASNIPEnumerator, domain, company)

    if "domains" in mods:
        run_mod("domain_subdomain", DomainSubdomainEnumerator, domain, company)

    # Normalize to clean strings IMMEDIATELY
    subs = dedup_subdomains(results.get("domain_subdomain", {}).get("subdomains", []))
    console.print(f"[cyan]  [+] Domain enumeration found {len(subs)} subdomain(s)[/cyan]")

    # ── Phase 2: Certificate Enumeration (adds more subdomains) ──
    if "certs" in mods:
        run_mod("ssl_cert", SSLCertEnumerator, domain, subs)
        cert_subs = dedup_subdomains(results.get("ssl_cert", {}).get("cert_subdomains", []))
        if cert_subs:
            existing = set(subs)
            new_cert = [s for s in cert_subs if s not in existing]
            subs.extend(new_cert)
            console.print(f"[cyan]  [+] Certificates added {len(new_cert)} new subdomain(s)[/cyan]")

    # ── Phase 2b: Dorking ──
    if not args.no_dorking and "domains" in mods:
        dorker = None

        # Prefer Google API if keys are set
        if HAS_DORKING:
            api_key = CONFIG.get('GOOGLE_API_KEY', '').strip()
            cx_id = CONFIG.get('GOOGLE_CX_ID', '').strip()
            if api_key and cx_id:
                dorker = GoogleDorker(CONFIG)
                console.print("[cyan]  [*] Using Google Custom Search API[/cyan]")

        # Fall back to passive dorking
        if dorker is None and HAS_PASSIVE_DORKING:
            dorker = DorkAlternative(CONFIG)
            console.print("[cyan]  [*] Using passive dorking (Wayback/URLScan/CommonCrawl/OTX)[/cyan]")

        if dorker:
            try:
                dork_results = dorker.run(domain)
                results["google_dorking"] = dork_results

                dork_subs = dedup_subdomains(dork_results.get("subdomains", []))
                if dork_subs:
                    existing = set(subs)
                    new_dork = [s for s in dork_subs if s not in existing]
                    subs.extend(new_dork)
                    console.print(f"[cyan]  [+] Dorking added {len(new_dork)} new subdomain(s)[/cyan]")
            except Exception as e:
                console.print(f"[yellow][!] Dorking error: {e}[/yellow]")
                results["google_dorking"] = {"error": str(e)}
        else:
            console.print("[yellow][!] No dorking module available[/yellow]")
 
 # ── Phase 2c: Social Engineering / Hunter.io (adds emails + subdomains) ──
    if "social" in mods:
        run_mod("social_engineering", SocialEngineeringRecon, domain, company)
        hunter_subs = dedup_subdomains(
            results.get("social_engineering", {}).get("subdomains", [])
        )
        if hunter_subs:
            existing = set(subs)
            new_hunter = [s for s in hunter_subs if s not in existing]
            subs.extend(new_hunter)
            console.print(f"[cyan]  [+] Hunter.io added {len(new_hunter)} new subdomain(s)[/cyan]")

    # ── Final dedup (safety net) ──
    subs = dedup_subdomains(subs)
    console.print(f"\n[bold cyan][*] Total unique subdomains: {len(subs)}[/bold cyan]\n")

    # ── Phase 3: Active Scanning (uses full subdomain list) ──
    if "webapps" in mods:
        run_mod("web_app_api", WebAppAPIScanner, domain, subs)

    if "cloud" in mods:
        run_mod("cloud_misconfig", CloudMisconfigScanner, domain, company, subs)

    if "cloudflare" in mods:
        run_mod("cloudflare", CloudflareScanner, domain, subs)

    if "internal" in mods:
        run_mod("internal_infra", InternalInfraScanner, domain, subs, results.get("asn_ip", {}).get("open_ports", {}))

    if "thirdparty" in mods:
        run_mod("third_party", ThirdPartyExposureScanner, domain, subs, None)

    if "physical" in mods:
        run_mod("physical_assets", PhysicalAssetScanner, domain, company, None, results.get("asn_ip", {}).get("open_ports", {}))

    # ── Merge subdomains discovered by Phase 3 modules ──
    phase3_sub_sources = {
        "web_app_api": ["subdomains", "discovered_hosts"],
        "cloud_misconfig": ["subdomains", "discovered_domains"],
        "cloudflare": ["direct_hosts", "cloudflare_hosts"],
        "internal_infra": ["subdomains", "internal_hosts"],
        "third_party": ["subdomains"],
    }

    pre_count = len(subs)
    existing = set(subs)

    for mod_key, field_names in phase3_sub_sources.items():
        mod_result = results.get(mod_key, {})
        if not isinstance(mod_result, dict):
            continue
        for field in field_names:
            items = mod_result.get(field, [])
            if not isinstance(items, list):
                continue
            for item in items:
                # Handle dicts with hostname/host keys (cloudflare returns these)
                if isinstance(item, dict):
                    hostname = item.get("hostname", item.get("host", item.get("domain", "")))
                else:
                    hostname = item
                if not isinstance(hostname, str):
                    continue
                hostname = hostname.strip().lower().rstrip(".")
                if hostname and hostname not in existing:
                    existing.add(hostname)
                    subs.append(hostname)

    if len(subs) > pre_count:
        console.print(f"[cyan]  [+] Phase 3 modules added {len(subs) - pre_count} new subdomain(s)[/cyan]")
        console.print(f"[bold cyan][*] Updated total subdomains: {len(subs)}[/bold cyan]\n")

    if "secrets" in mods:
        run_mod("secret_scanner", SecretScanner, domain, subs, results.get("web_app_api"))
        
    

    if "vulnscan" in mods:
        run_mod("web_vuln_scan", WebVulnScanner, domain, subs)

    # ── Phase 4: Shadow IT Detection ──
    shadow = ShadowITDetector(CONFIG).run(results)

    # ── Phase 5: Post-filter false positives ──
    results, shadow = post_filter_results(results, shadow)

    # ── Phase 6: Report Generation ──
    if not args.no_report:
        ReportGenerator(CONFIG).generate(domain, results, shadow)

    elapsed = time.time() - start
    console.print(f"\n[bold green]Done in {elapsed:.1f}s[/bold green]")
    console.print(f"[bold green]Output: {CONFIG['OUTPUT_DIR']}[/bold green]")



if __name__ == "__main__":
    main()