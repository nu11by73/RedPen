import ssl
import socket
import requests
import time
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from rich.console import Console
from concurrent.futures import ThreadPoolExecutor, as_completed

console = Console()


class SSLCertEnumerator:
    def __init__(self, config):
        self.config = config
        self.results = {"certificates": [], "cert_subdomains": [], "expired_certs": [], "weak_certs": [], "tls_versions": {}, "next_steps": [], "shadow_it_flags": []}

    def run(self, target_domain, subdomains=None):
        console.print(f"\n[bold cyan]{'='*60}[/bold cyan]")
        console.print(f"[bold cyan]  Module 3: SSL/TLS Certificate Enumeration - {target_domain}[/bold cyan]")
        console.print(f"[bold cyan]{'='*60}[/bold cyan]\n")
        self._ct_logs(target_domain)
        targets = [target_domain]
        if subdomains:
            for sub in subdomains[:50]:
                s = sub.get("subdomain", "") if isinstance(sub, dict) else sub
                if s and s not in targets:
                    targets.append(s)
        self._analyze_certs(targets)
        self._next_steps()
        return self.results

    def _ct_logs(self, domain):
        console.print("[yellow][*] Enumerating CT logs...[/yellow]")
        for attempt in range(3):
            try:
                resp = requests.get(
                    f"https://crt.sh/?q=%.{domain}&output=json",
                    timeout=60,
                    headers={"User-Agent": "Mozilla/5.0"}
                )
                if resp.status_code == 200:
                    seen = set()
                    for entry in resp.json():
                        for name in entry.get("name_value", "").split("\n"):
                            name = name.strip().lower()
                            if name.endswith(domain) and "*" not in name and name not in seen:
                                seen.add(name)
                                self.results["cert_subdomains"].append({
                                    "subdomain": name,
                                    "issuer": entry.get("issuer_name", ""),
                                    "source": "CT Log"
                                })
                    console.print(f"  [green][+] CT Logs: {len(seen)} subdomains[/green]")
                    return
            except Exception as e:
                console.print(f"  [yellow][!] crt.sh attempt {attempt+1}/3 failed: {e}[/yellow]")
                time.sleep(3)

        # Fallback
        console.print("[yellow][*] Falling back to CertSpotter...[/yellow]")
        try:
            resp = requests.get(
                f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names",
                timeout=30
            )
            if resp.status_code == 200:
                seen = set()
                for entry in resp.json():
                    for name in entry.get("dns_names", []):
                        name = name.strip().lower()
                        if name.endswith(domain) and "*" not in name and name not in seen:
                            seen.add(name)
                            self.results["cert_subdomains"].append({
                                "subdomain": name,
                                "issuer": "",
                                "source": "CertSpotter"
                            })
                console.print(f"  [green][+] CertSpotter: {len(seen)} subdomains[/green]")
        except Exception as e:
            console.print(f"  [red][-] CertSpotter also failed: {e}[/red]")

    def _analyze_certs(self, targets):
        console.print("[yellow][*] Analyzing SSL certificates (threaded)...[/yellow]")

        def _analyze_one(hostname):
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with socket.create_connection((hostname, 443), timeout=7) as sock:
                    with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert_der = ssock.getpeercert(binary_form=True)
                        cert = x509.load_der_x509_certificate(
                            cert_der, default_backend()
                        )
                        subject = cert.subject.rfc4514_string()
                        issuer = cert.issuer.rfc4514_string()
                        not_after = cert.not_valid_after_utc
                        key_size = cert.public_key().key_size
                        sans = []
                        try:
                            san_ext = cert.extensions.get_extension_for_class(
                                x509.SubjectAlternativeName
                            )
                            sans = san_ext.value.get_values_for_type(x509.DNSName)
                        except Exception:
                            pass
                        return {
                            "hostname": hostname,
                            "subject": subject,
                            "issuer": issuer,
                            "not_after": str(not_after),
                            "not_after_dt": not_after,
                            "key_size": key_size,
                            "sans": sans,
                            "self_signed": subject == issuer,
                        }
            except (ssl.SSLError, socket.timeout, socket.gaierror,
                    ConnectionRefusedError, OSError):
                return None
            except Exception as e:
                console.print(
                    f"  [red][-] Cert analysis failed for {hostname}: {e}[/red]"
                )
                return None

        with ThreadPoolExecutor(max_workers=15) as executor:
            futures = {
                executor.submit(_analyze_one, h): h
                for h in targets[:30]
            }
            for future in as_completed(futures):
                info = future.result()
                if info is None:
                    continue

                hostname = info["hostname"]
                not_after_dt = info.pop("not_after_dt")

                self.results["certificates"].append(info)
                console.print(
                    f"  [green][+] {hostname}: Valid until"
                    f" {info['not_after']}, Key: {info['key_size']}bit,"
                    f" SANs: {len(info['sans'])}[/green]"
                )

                now = datetime.utcnow()
                na = (
                    not_after_dt.replace(tzinfo=None)
                    if not_after_dt.tzinfo else not_after_dt
                )
                if na < now:
                    self.results["expired_certs"].append(info)
                    console.print(
                        f"      [bold red][!] EXPIRED![/bold red]"
                    )

                if info["key_size"] < 2048:
                    self.results["weak_certs"].append(info)
                    console.print(
                        f"      [bold red][!] WEAK KEY:"
                        f" {info['key_size']}[/bold red]"
                    )

                if info["self_signed"]:
                    console.print(
                        f"      [bold yellow][!] SELF-SIGNED[/bold yellow]"
                    )
                    self.results["shadow_it_flags"].append({
                        "type": "Self-Signed Certificate",
                        "asset": hostname,
                        "reason": (
                            "Not enrolled in org PKI/"
                            "certificate management."
                        ),
                    })

                for san in info["sans"]:
                    san = san.lower().strip()
                    if "*" not in san:
                        existing = [
                            s["subdomain"]
                            for s in self.results["cert_subdomains"]
                        ]
                        if san not in existing:
                            self.results["cert_subdomains"].append({
                                "subdomain": san,
                                "source": f"SAN from {hostname}",
                            })

    def _next_steps(self):
        steps = []
        if self.results["expired_certs"]:
            steps.append({"action": "Renew Expired Certificates", "description": f"{len(self.results['expired_certs'])} expired certs. Renew immediately.", "priority": "CRITICAL"})
        if self.results["weak_certs"]:
            steps.append({"action": "Replace Weak Certificates", "description": f"{len(self.results['weak_certs'])} weak keys. Use 2048+ RSA or 256+ ECC.", "priority": "HIGH"})
        steps.append({"action": "Certificate Monitoring", "description": "Set up CT log monitoring and expiry alerts.", "priority": "MEDIUM"})
        self.results["next_steps"] = steps
