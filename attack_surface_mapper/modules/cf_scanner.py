import socket
import struct
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.panel import Panel

console = Console()

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def fetch_cloudflare_ranges():
    ranges = []
    for url in [
        "https://www.cloudflare.com/ips-v4/",
        "https://www.cloudflare.com/ips-v6/",
    ]:
        try:
            resp = requests.get(url, timeout=10)
            if resp.status_code == 200:
                for line in resp.text.strip().splitlines():
                    line = line.strip()
                    if line and "/" in line:
                        ranges.append(line)
        except Exception:
            pass

    if not ranges:
        ranges = [
            "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
            "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
            "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
            "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
            "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
        ]
    return ranges


# Pre-compute CF ranges into integer tuples for fast lookup
def _compile_cf_ranges(cf_ranges):
    compiled = []
    for cidr in cf_ranges:
        if ":" in cidr:
            continue
        try:
            network, prefix_len = cidr.split("/")
            prefix_len = int(prefix_len)
            network_int = struct.unpack("!I", socket.inet_aton(network))[0]
            mask = (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF
            compiled.append((network_int & mask, mask))
        except (ValueError, TypeError, socket.error):
            continue
    return compiled


def is_cloudflare_ip(ip, compiled_ranges):
    try:
        ip_int = struct.unpack("!I", socket.inet_aton(ip))[0]
    except (socket.error, OSError):
        return False
    for network_masked, mask in compiled_ranges:
        if (ip_int & mask) == network_masked:
            return True
    return False


def check_cloudflare_headers(host, timeout=8):
    result = {"is_cloudflare": False, "evidence": []}

    cf_signatures = {
        "server": ["cloudflare"],
        "cf-ray": None,
        "cf-cache-status": None,
        "cf-request-id": None,
        "cf-connecting-ip": None,
    }

    for scheme in ["https", "http"]:
        try:
            resp = requests.get(
                f"{scheme}://{host}/",
                timeout=timeout,
                allow_redirects=True,
                verify=False,
                headers={"User-Agent": "Mozilla/5.0"},
            )
            headers = {k.lower(): v for k, v in resp.headers.items()}

            for header_name, signatures in cf_signatures.items():
                val = headers.get(header_name, "")
                if not val:
                    continue
                if signatures is None:
                    result["is_cloudflare"] = True
                    result["evidence"].append(f"{header_name}: {val}")
                else:
                    for sig in signatures:
                        if sig in val.lower():
                            result["is_cloudflare"] = True
                            result["evidence"].append(f"{header_name}: {val}")
                            break

            if result["is_cloudflare"]:
                return result

        except Exception:
            continue

    return result


def _resolve_host(host):
    """Quick DNS resolve, returns (host, ip) or (host, None)."""
    try:
        return (host, socket.gethostbyname(host))
    except socket.gaierror:
        return (host, None)


def get_real_ip_attempts(host, compiled_ranges, timeout=8):
    origins = []
    seen_ips = set()

    base_domain = host
    parts = host.split(".")
    if len(parts) > 2:
        base_domain = ".".join(parts[-2:])

    origin_prefixes = [
        "direct", "origin", "real", "backend", "server",
        "mail", "ftp", "cpanel", "webmail", "pop", "imap",
        "smtp", "mx", "ns1", "ns2", "dev", "staging",
        "old", "legacy", "api", "admin",
    ]

    # Parallel DNS lookups for all origin subdomains
    subdomains = [f"{p}.{base_domain}" for p in origin_prefixes]

    with ThreadPoolExecutor(max_workers=15) as executor:
        futures = {executor.submit(_resolve_host, sd): sd for sd in subdomains}
        for future in as_completed(futures):
            sd, ip = future.result()
            if ip and ip not in seen_ips:
                seen_ips.add(ip)
                if not is_cloudflare_ip(ip, compiled_ranges):
                    origins.append({
                        "ip": ip,
                        "method": f"DNS subdomain ({sd})",
                        "confidence": "MEDIUM",
                    })

    # MX records
    try:
        import dns.resolver
        try:
            mx_records = dns.resolver.resolve(base_domain, "MX", lifetime=5)
            for mx in mx_records:
                mx_host = str(mx.exchange).rstrip(".")
                try:
                    ip = socket.gethostbyname(mx_host)
                    if ip not in seen_ips:
                        seen_ips.add(ip)
                        if not is_cloudflare_ip(ip, compiled_ranges):
                            origins.append({
                                "ip": ip,
                                "method": f"MX record ({mx_host})",
                                "confidence": "LOW",
                            })
                except socket.gaierror:
                    pass
        except Exception:
            pass
    except ImportError:
        pass

    # SPF records
    try:
        import dns.resolver
        try:
            txt_records = dns.resolver.resolve(base_domain, "TXT", lifetime=5)
            for txt in txt_records:
                txt_str = str(txt).strip('"')
                if "v=spf1" in txt_str:
                    for part in txt_str.split():
                        if part.startswith("ip4:"):
                            ip = part[4:].split("/")[0]
                            if ip not in seen_ips:
                                seen_ips.add(ip)
                                if not is_cloudflare_ip(ip, compiled_ranges):
                                    origins.append({
                                        "ip": ip,
                                        "method": "SPF record",
                                        "confidence": "MEDIUM",
                                    })
        except Exception:
            pass
    except ImportError:
        pass

    return origins


def _verify_origin(origin, host, timeout):
    """Verify a single origin IP responds."""
    try:
        resp = requests.get(
            f"https://{origin['ip']}",
            headers={"Host": host},
            timeout=timeout,
            verify=False,
            allow_redirects=False,
        )
        origin["verified"] = resp.status_code < 500
        origin["status_code"] = resp.status_code
        origin["server"] = resp.headers.get("Server", "unknown")
    except Exception:
        origin["verified"] = False
    return origin


class CloudflareScanner:
    def __init__(self, config):
        self.config = config
        self.timeout = config.get("REQUEST_TIMEOUT", 8)

    def _scan_single_host(self, host, compiled_ranges):
        """Scan one host: DNS + header check. Returns result dict."""
        try:
            ip = socket.gethostbyname(host)
        except socket.gaierror:
            return {"status": "failed", "hostname": host}

        ip_is_cf = is_cloudflare_ip(ip, compiled_ranges)
        header_result = check_cloudflare_headers(host, self.timeout)
        header_is_cf = header_result["is_cloudflare"]
        evidence = ", ".join(header_result["evidence"][:3]) if header_result["evidence"] else ""
        is_cf = ip_is_cf or header_is_cf

        if ip_is_cf and header_is_cf:
            method = "IP Range + Headers"
        elif header_is_cf:
            method = "Headers Only"
        elif ip_is_cf:
            method = "IP Range Only"
        else:
            method = "Direct"

        if is_cf:
            return {
                "status": "cloudflare",
                "hostname": host, "ip": ip,
                "method": method, "evidence": evidence,
            }
        else:
            return {"status": "direct", "hostname": host, "ip": ip}

    def run(self, domain, subs=None):
        console.print(Panel("[bold cyan]Module 12: Cloudflare Detection & Origin Discovery[/bold cyan]"))

        results = {
            "cloudflare_hosts": [],
            "direct_hosts": [],
            "failed_hosts": [],
            "origin_discoveries": {},
            "cf_ranges_loaded": 0,
            "shadow_it_flags": [],
            "next_steps": [],
        }

        hostnames = [domain]
        if subs:
            for s in subs:
                s = s.strip().lower()
                if s and s != domain:
                    hostnames.append(s)

        # Fetch & compile CF ranges once
        console.print("[yellow][*] Fetching current Cloudflare IP ranges...[/yellow]")
        cf_ranges = fetch_cloudflare_ranges()
        compiled_ranges = _compile_cf_ranges(cf_ranges)
        results["cf_ranges_loaded"] = len(cf_ranges)
        console.print(f"  [green][+] Loaded {len(cf_ranges)} Cloudflare CIDR ranges[/green]")
        console.print(f"[yellow][*] Scanning {len(hostnames)} targets for Cloudflare...[/yellow]\n")

        # Parallel host scanning
        max_workers = min(20, len(hostnames))
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(self._scan_single_host, host, compiled_ranges): host
                for host in hostnames
            }
            for future in as_completed(futures):
                r = future.result()
                if r["status"] == "failed":
                    results["failed_hosts"].append(r["hostname"])
                elif r["status"] == "cloudflare":
                    results["cloudflare_hosts"].append(r)
                    console.print(f"  [red][!] {r['hostname']} -> {r['ip']} [CLOUDFLARE] ({r['method']})[/red]")
                else:
                    results["direct_hosts"].append(r)
                    console.print(f"  [green][+] {r['hostname']} -> {r['ip']} [DIRECT][/green]")

        # Parallel origin discovery
        if results["cloudflare_hosts"]:
            console.print(f"\n[bold yellow][*] Attempting origin discovery for {len(results['cloudflare_hosts'])} CF-protected hosts...[/bold yellow]\n")

            with ThreadPoolExecutor(max_workers=10) as executor:
                origin_futures = {
                    executor.submit(
                        get_real_ip_attempts, entry["hostname"], compiled_ranges, self.timeout
                    ): entry["hostname"]
                    for entry in results["cloudflare_hosts"]
                }
                for future in as_completed(origin_futures):
                    host = origin_futures[future]
                    origins = future.result()
                    results["origin_discoveries"][host] = origins

                    for origin in origins:
                        console.print(f"  [green][+] {host} -> Origin: {origin['ip']} via {origin['method']} ({origin['confidence']})[/green]")

                    if origins:
                        results["shadow_it_flags"].append({
                            "type": "CF Origin Bypass",
                            "asset": host,
                            "reason": f"Origin IP(s) exposed behind Cloudflare for {host}",
                        })

            # Parallel origin verification
            all_verifications = []
            for host, origins in results["origin_discoveries"].items():
                for origin in origins:
                    all_verifications.append((origin, host))

            if all_verifications:
                with ThreadPoolExecutor(max_workers=15) as executor:
                    verify_futures = {
                        executor.submit(_verify_origin, origin, host, self.timeout): (origin, host)
                        for origin, host in all_verifications
                    }
                    for future in as_completed(verify_futures):
                        future.result()  # updates origin dict in place

        # Next steps
        cf_count = len(results["cloudflare_hosts"])
        direct_count = len(results["direct_hosts"])
        origin_count = sum(len(v) for v in results["origin_discoveries"].values())

        if cf_count > 0:
            results["next_steps"].append({
                "action": "Verify Origin IP Restrictions",
                "description": f"{cf_count} hosts behind Cloudflare - check origin IP restrictions.",
                "priority": "HIGH",
            })
        if origin_count > 0:
            results["next_steps"].append({
                "action": "Audit Origin Firewall Rules",
                "description": f"{origin_count} potential origin IPs found - verify firewall rules.",
                "priority": "CRITICAL",
            })
        if direct_count > 0:
            results["next_steps"].append({
                "action": "Direct Host Scanning",
                "description": f"{direct_count} hosts are direct (no CDN) - scan directly.",
                "priority": "MEDIUM",
            })

        console.print(f"\n[bold cyan]  CF Summary: {cf_count} behind CF, {direct_count} direct, {origin_count} origins found[/bold cyan]")

        return results