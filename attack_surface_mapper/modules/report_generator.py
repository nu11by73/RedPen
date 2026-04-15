"""
Report Generator v2.0 - Fixed
Fixes: argument order to match main.py calling convention
"""

import json
import os
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class ReportGenerator:
    def __init__(self, config=None):
        self.config = config

    def generate(self, domain, results, shadow=None, output_dir=None):
        """
        Generate JSON and HTML reports.

        Args:
            domain: Target domain string (e.g., 'lpl.com')
            results: Dict of all module results
            shadow: Shadow IT detection results (optional)
            output_dir: Output directory (defaults to CONFIG['OUTPUT_DIR'] or './output')
        """
        # Determine output directory
        if output_dir is None:
            if isinstance(self.config, dict):
                output_dir = self.config.get('OUTPUT_DIR', './output')
            elif self.config and hasattr(self.config, 'OUTPUT_DIR'):
                output_dir = self.config.OUTPUT_DIR
            else:
                output_dir = './output'

        # Merge shadow into results if provided
        if shadow and isinstance(shadow, dict):
            results['shadow_it'] = shadow

        target = domain
        os.makedirs(output_dir, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        clean_target = target.replace("https://", "").replace("http://", "").replace("/", "_").rstrip("_")
        base = f"asm_{clean_target}_{ts}"
        json_path = os.path.join(output_dir, f"{base}.json")
        html_path = os.path.join(output_dir, f"{base}.html")

        full_data = {
            'target': target,
            'scan_date': datetime.now().isoformat(),
            'generated_by': 'Attack Surface Mapper v2.0',
        }
        full_data.update(results)

        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(full_data, f, indent=2, default=str)
        print(f"[+] JSON report: {json_path}")

        html = self._build_html(full_data, target)
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html)
        print(f"[+] HTML report: {html_path}")

        return html_path, json_path

    def _sev_badge(self, severity):
        colors = {
            'CRITICAL': '#dc3545', 'HIGH': '#fd7e14', 'MEDIUM': '#ffc107',
            'LOW': '#0dcaf0', 'INFO': '#6c757d'
        }
        c = colors.get(severity, '#6c757d')
        return f'<span style="background:{c};color:#fff;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:bold;">{severity}</span>'

    def _build_html(self, data, target):
        scan_date = data.get('scan_date', 'Unknown')
        secrets = data.get('secret_scanning', data.get('secret_scanner', {}))
        shadow = data.get('shadow_it', {})
        domains = data.get('domain_subdomain', {})
        ssl = data.get('ssl_cert', data.get('ssl_certificates', {}))
        webapp = data.get('web_app_api', {})
        cloud = data.get('cloud_misconfig', {})
        cloudflare = data.get('cloudflare', {})
        social = data.get('social_engineering', {})
        third_party = data.get('third_party', data.get('third_party_exposure', {}))
        asn = data.get('asn_ip', {})
        internal = data.get('internal_infra', {})
        physical = data.get('physical_assets', {})
        dorking = data.get('google_dorking', {})
        vulnscan = data.get('web_vuln_scan', {})
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ASM Report - {target}</title>
<style>
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background:#0f172a; color:#e2e8f0; line-height:1.6; }}
.container {{ max-width:1200px; margin:0 auto; padding:20px; }}
.header {{ background:linear-gradient(135deg, #1e293b, #334155); padding:30px; border-radius:12px; margin-bottom:24px; border:1px solid #475569; }}
.header h1 {{ color:#60a5fa; font-size:28px; margin-bottom:8px; }}
.header .meta {{ color:#94a3b8; font-size:14px; }}
.nav {{ display:flex; flex-wrap:wrap; gap:8px; margin-bottom:24px; }}
.nav a {{ background:#1e293b; color:#60a5fa; padding:8px 16px; border-radius:8px; text-decoration:none; font-size:13px; border:1px solid #334155; }}
.nav a:hover {{ background:#334155; }}
.section {{ background:#1e293b; border-radius:12px; padding:24px; margin-bottom:20px; border:1px solid #334155; }}
.section h2 {{ color:#60a5fa; font-size:20px; margin-bottom:16px; padding-bottom:8px; border-bottom:1px solid #334155; }}
.section h3 {{ color:#93c5fd; font-size:16px; margin:16px 0 8px 0; }}
table {{ width:100%; border-collapse:collapse; margin:12px 0; font-size:13px; }}
th {{ background:#334155; color:#e2e8f0; padding:10px 12px; text-align:left; font-weight:600; }}
td {{ padding:8px 12px; border-bottom:1px solid #334155; vertical-align:top; }}
tr:hover td {{ background:#334155; }}
.stat-grid {{ display:grid; grid-template-columns:repeat(auto-fit, minmax(200px, 1fr)); gap:16px; margin:16px 0; }}
.stat-card {{ background:#0f172a; border:1px solid #475569; border-radius:8px; padding:16px; text-align:center; }}
.stat-card .number {{ font-size:32px; font-weight:bold; color:#60a5fa; }}
.stat-card .label {{ font-size:12px; color:#94a3b8; text-transform:uppercase; }}
.ctx {{ font-family:monospace; font-size:11px; color:#94a3b8; word-break:break-all; max-width:500px; }}
.badge {{ padding:2px 8px; border-radius:4px; font-size:11px; font-weight:bold; color:#fff; }}
.badge-critical {{ background:#dc3545; }}
.badge-high {{ background:#fd7e14; }}
.badge-medium {{ background:#ffc107; color:#000; }}
.badge-low {{ background:#0dcaf0; color:#000; }}
.badge-info {{ background:#6c757d; }}
</style>
</head>
<body>
<div class="container">

<div class="header">
  <h1>Attack Surface Mapping Report</h1>
  <div class="meta">
    Target: <strong>{target}</strong> &nbsp;|&nbsp;
    Scan Date: <strong>{scan_date}</strong> &nbsp;|&nbsp;
    Generated by Attack Surface Mapper v2.0
  </div>
</div>

<div class="nav">
  <a href="#summary">Summary</a>
  <a href="#secrets">Secrets</a>
  <a href="#secrets-detail">Secret Locations</a>
  <a href="#domains">Domains</a>
  <a href="#dorking">Google Dorking</a>
  <a href="#vulnscan">Vulnscan</a>
  <a href="#cloud">Cloud</a>
  <a href="#internal">Internal</a>
  <a href="#social">Social</a>
  <a href="#physical">Physical</a>
  <a href="#vulnscan">Vuln Scan</a>
  <a href="#asn">ASN & IP</a>
  <a href="#ssl">SSL/TLS</a>
  <a href="#webapp">Web/API</a>
  <a href="#cloudflare">Cloudflare</a>
  <a href="#shadowit">Shadow IT</a>
  <a href="#thirdparty">Third Party</a>
  <a href="#recommendations">Recommendations</a>
</div>
"""

        # ── EXECUTIVE SUMMARY ──
        creds = secrets.get('credentials_found', [])
        apikeys = secrets.get('api_keys_found', [])
        hardcoded = secrets.get('hardcoded_passwords', [])
        tok = secrets.get('exposed_tokens', [])
        unique_count = secrets.get('unique_secrets_count', len(creds)+len(apikeys)+len(hardcoded)+len(tok))
        fp_filtered = secrets.get('false_positives_filtered', 0)
        subdomains_list = domains.get('subdomains', [])
        risk_score = shadow.get('risk_score', 0)
        sev_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}

        all_secrets = creds + apikeys + hardcoded + tok
        crit = sum(1 for s in all_secrets if s.get('severity') == 'CRITICAL')
        high = sum(1 for s in all_secrets if s.get('severity') == 'HIGH')
        med = sum(1 for s in all_secrets if s.get('severity') == 'MEDIUM')

        html += f"""
<div class="section" id="summary">
  <h2>Executive Summary</h2>
  <div class="stat-grid">
    <div class="stat-card"><div class="number" style="color:#dc3545;">{crit}</div><div class="label">Critical Findings</div></div>
    <div class="stat-card"><div class="number" style="color:#fd7e14;">{high}</div><div class="label">High Findings</div></div>
    <div class="stat-card"><div class="number" style="color:#ffc107;">{med}</div><div class="label">Medium Findings</div></div>
    <div class="stat-card"><div class="number">{unique_count}</div><div class="label">Unique Secrets</div></div>
    <div class="stat-card"><div class="number">{fp_filtered}</div><div class="label">Duplicates Filtered</div></div>
    <div class="stat-card"><div class="number">{len(subdomains_list)}</div><div class="label">Subdomains</div></div>
    <div class="stat-card"><div class="number">{risk_score}</div><div class="label">Risk Score</div></div>
  </div>
</div>
"""

        # ── SECRETS SUMMARY ──
        html += '<div class="section" id="secrets"><h2>Exposed Secrets Summary</h2>'
        if all_secrets:
            html += '<table><thead><tr><th>#</th><th>Type</th><th>Severity</th><th>Value (Masked)</th><th>Found On</th><th>Pages</th></tr></thead><tbody>'
            for i, s in enumerate(sorted(all_secrets, key=lambda x: sev_order.get(x.get('severity','INFO'), 5)), 1):
                occ = s.get('occurrence_count', 1)
                sev = s.get('severity', 'INFO')
                badge_cls = f"badge-{sev.lower()}"
                html += f'<tr><td>{i}</td><td>{s["type"]}</td><td><span class="badge {badge_cls}">{sev}</span></td>'
                html += f'<td><code>{s["masked_value"]}</code></td><td style="font-size:12px;">{s.get("source_url","")}</td><td>{occ}</td></tr>'
            html += '</tbody></table>'
        else:
            html += '<p style="color:#22c55e;">No exposed secrets found.</p>'
        html += '</div>'

        # ── DETAILED SECRET LOCATIONS ──
        html += '<div class="section" id="secrets-detail"><h2>Detailed Secret Locations</h2>'
        if all_secrets:
            for i, s in enumerate(sorted(all_secrets, key=lambda x: sev_order.get(x.get('severity','INFO'), 5)), 1):
                sev = s.get('severity', 'INFO')
                badge_cls = f"badge-{sev.lower()}"
                locs = s.get('locations', [{'url': s.get('source_url',''), 'source_type': s.get('source_type','')}])
                html += f"""
<div style="background:#0f172a;border:1px solid #475569;border-radius:8px;padding:16px;margin-bottom:12px;">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
    <strong>#{i} {s['type']}</strong>
    <span class="badge {badge_cls}">{sev}</span>
  </div>
  <div style="margin-bottom:6px;"><span style="color:#94a3b8;">Value:</span> <code style="color:#60a5fa;">{s['masked_value']}</code></div>
  <div style="margin-bottom:6px;"><span style="color:#94a3b8;">Found on {len(locs)} page(s):</span></div>
  <table style="margin:0;"><thead><tr><th>URL</th><th>Source</th></tr></thead><tbody>"""
                for loc in locs:
                    url = loc.get('url', '')
                    st = loc.get('source_type', '')
                    html += f'<tr><td style="font-size:12px;"><a href="{url}" style="color:#60a5fa;" target="_blank">{url}</a></td><td>{st}</td></tr>'
                html += '</tbody></table>'
                ctx = s.get('context', '')
                if ctx:
                    html += f'<div style="margin-top:8px;"><span style="color:#94a3b8;">Context:</span><div class="ctx">{self._escape_html(ctx)}</div></div>'
                html += '</div>'
        else:
            html += '<p style="color:#22c55e;">No secrets to detail.</p>'
        html += '</div>'

        # ── DOMAINS ──
        html += '<div class="section" id="domains"><h2>Domains & Subdomains</h2>'
        html += self._render_generic_section(domains)
        html += '</div>'

        # ── GOOGLE DORKING ──
        if dorking:
            html += '<div class="section" id="dorking"><h2>Google Dorking Results</h2>'
            html += self._render_generic_section(dorking)
            html += '</div>'
# ── ASN & IP (dedicated section with Shodan vs Verified port tables) ──
        if asn:
            html += '<div class="section" id="asn"><h2>ASN & IP Intelligence</h2>'

            # Render everything EXCEPT the port dicts generically
            asn_generic = {
                k: v for k, v in asn.items()
                if k not in ('open_ports', 'verified_ports')
            }
            html += self._render_generic_section(asn_generic)

            # ── Table 1: Shodan-Reported Ports (Unverified) ──
            open_ports = asn.get('open_ports', {})
            if open_ports:
                html += '<h3>Shodan-Reported Ports (Unverified)</h3>'
                html += '<table><thead><tr>'
                html += '<th>IP</th><th>Ports</th><th>OS</th><th>CVEs</th>'
                html += '</tr></thead><tbody>'
                for ip, pdata in open_ports.items():
                    ports_str = ', '.join(str(p) for p in pdata.get('ports', []))
                    vulns_str = ', '.join(pdata.get('vulns', [])) or 'None'
                    os_str = pdata.get('os', 'Unknown') or 'Unknown'
                    html += f'<tr><td>{ip}</td><td>{ports_str}</td>'
                    html += f'<td>{os_str}</td><td>{vulns_str}</td></tr>'
                html += '</tbody></table>'

            # ── Table 2: Live-Verified Ports (Confirmed Open) ──
            verified_ports = asn.get('verified_ports', {})
            if verified_ports:
                html += '<h3>Live-Verified Ports (Confirmed Open)</h3>'
                html += '<table><thead><tr>'
                html += '<th>IP</th><th>Confirmed Open</th><th>Closed/Filtered</th>'
                html += '<th>OS</th><th>CVEs</th>'
                html += '</tr></thead><tbody>'
                for ip, vdata in verified_ports.items():
                    open_str = ', '.join(
                        str(p) for p in vdata.get('open', [])
                    ) or 'None'
                    closed_str = ', '.join(
                        str(p) for p in vdata.get('closed_or_filtered', [])
                    ) or 'None'
                    vulns_str = ', '.join(vdata.get('vulns', [])) or 'None'
                    os_str = vdata.get('os', 'Unknown') or 'Unknown'
                    html += f'<tr><td>{ip}</td>'
                    html += f'<td style="color:#22c55e;">{open_str}</td>'
                    html += f'<td style="color:#ef4444;">{closed_str}</td>'
                    html += f'<td>{os_str}</td><td>{vulns_str}</td></tr>'
                html += '</tbody></table>'
            elif open_ports:
                html += '<h3>Live-Verified Ports</h3>'
                html += '<p style="color:#94a3b8;">Port verification data not available. '
                html += 'Ensure the scanner includes the verification step.</p>'

            html += '</div>'

        # ── REMAINING SECTIONS ──
        for section_id, section_title, section_data in [
            ('ssl', 'SSL/TLS Certificates', ssl),
            ('webapp', 'Web Application & API', webapp),
            ('cloud', 'Cloud Misconfiguration', cloud),
            ('cloudflare', 'Cloudflare / CDN Analysis', cloudflare),
           # ('asn', 'ASN & IP', asn),
            ('vulnscan', 'Vulnerability Scan Results', vulnscan),
            ('internal', 'Internal Infrastructure', internal),
            ('social', 'Social Engineering', social),
            ('thirdparty', 'Third-Party Exposure', third_party),
            ('physical', 'Physical Assets', physical),
        ]:
            if section_data:
                html += f'<div class="section" id="{section_id}"><h2>{section_title}</h2>'
                html += self._render_generic_section(section_data)
                html += '</div>'

        # ── SHADOW IT ──
        html += '<div class="section" id="shadowit"><h2>Shadow IT Detection</h2>'
        summary_items = shadow.get('shadow_it_summary', [])
        if summary_items:
            for cat_group in summary_items:
                cat_name = cat_group.get('category', 'Unknown')
                items = cat_group.get('items', [])
                html += f'<h3>{cat_name} ({len(items)} items)</h3>'
                if items:
                    html += '<table><thead><tr><th>Type</th><th>Asset</th><th>Reason</th></tr></thead><tbody>'
                    seen_shadow = set()
                    for item in items:
                        dedup = (item.get('type',''), item.get('asset',''))
                        if dedup in seen_shadow:
                            continue
                        seen_shadow.add(dedup)
                        html += f'<tr><td>{item.get("type","")}</td><td style="font-size:12px;">{item.get("asset","")}</td><td style="font-size:12px;">{item.get("reason","")}</td></tr>'
                    html += '</tbody></table>'
        else:
            html += '<p>No shadow IT detected.</p>'
        html += '</div>'

        # ── RECOMMENDATIONS ──
       # Aggregate next_steps from ALL modules
        next_steps = []
        for mod_key, mod_data in data.items():
            if isinstance(mod_data, dict) and 'next_steps' in mod_data:
                mod_steps = mod_data['next_steps']
                if isinstance(mod_steps, list):
                    for step in mod_steps:
                        if isinstance(step, dict):
                            next_steps.append(step)
                        elif isinstance(step, str):
                            # Handle modules that return strings (cloudflare)
                            next_steps.append({
                                "action": step,
                                "description": step,
                                "priority": "MEDIUM",
                            })
        recs = shadow.get('recommendations', [])
        if next_steps or recs:
            html += '<div class="section" id="recommendations"><h2>Recommendations</h2>'
            html += '<table><thead><tr><th>Priority</th><th>Action</th><th>Details</th></tr></thead><tbody>'
            for ns in next_steps:
                p = ns.get('priority', 'MEDIUM')
                badge_cls = f"badge-{p.lower()}"
                html += f'<tr><td><span class="badge {badge_cls}">{p}</span></td><td><strong>{ns.get("action","")}</strong></td><td>{ns.get("description","")}</td></tr>'
            for r in recs:
                p = r.get('priority', 'MEDIUM')
                badge_cls = f"badge-{p.lower()}"
                html += f'<tr><td><span class="badge {badge_cls}">{p}</span></td><td><strong>{r.get("title","")}</strong></td><td>{r.get("description","")}</td></tr>'
            html += '</tbody></table></div>'

        html += "</div></body></html>"
        return html

    def _escape_html(self, text):
        return str(text).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;')

    def _render_generic_section(self, data):
        if not data:
            return '<p style="color:#94a3b8;">No data.</p>'
        if isinstance(data, dict):
            html = ''
            for key, value in data.items():
                if key.startswith('_'):
                    continue
                display_key = key.replace('_', ' ').title()
                if isinstance(value, list):
                    if not value:
                        continue
                    elif isinstance(value[0], dict):
                        html += f'<h3>{display_key} ({len(value)})</h3>'
                        html += self._render_table(value)
                    else:
                        html += f'<h3>{display_key} ({len(value)})</h3>'
                        html += '<ul style="list-style:none;padding:0;max-height:300px;overflow-y:auto;">'
                        for item in value[:100]:
                            html += f'<li style="padding:2px 0;font-size:13px;">{self._escape_html(str(item))}</li>'
                        if len(value) > 100:
                            html += f'<li style="color:#94a3b8;">... and {len(value)-100} more</li>'
                        html += '</ul>'
                elif isinstance(value, dict):
                    html += f'<h3>{display_key}</h3>'
                    html += self._render_generic_section(value)
                elif value:
                    html += f'<p><strong>{display_key}:</strong> {self._escape_html(str(value))}</p>'
            return html
        elif isinstance(data, list):
            if not data:
                return ''
            if isinstance(data[0], dict):
                return self._render_table(data)
            return '<ul>' + ''.join(f'<li>{self._escape_html(str(x))}</li>' for x in data[:100]) + '</ul>'
        return f'<p>{self._escape_html(str(data))}</p>'

    def _render_table(self, items):
        if not items:
            return ''
        keys = []
        for item in items[:5]:
            for k in item.keys():
                if k not in keys and not k.startswith('_'):
                    keys.append(k)
        html = '<div style="overflow-x:auto;"><table><thead><tr>'
        for k in keys:
            html += f'<th>{k.replace("_"," ").title()}</th>'
        html += '</tr></thead><tbody>'
        for item in items[:200]:
            html += '<tr>'
            for k in keys:
                val = item.get(k, '')
                if isinstance(val, list):
                    val = f'{len(val)} items'
                if isinstance(val, dict):
                    val = json.dumps(val)[:100]
                cell = self._escape_html(str(val))
                if k == 'severity':
                    badge_cls = f"badge-{str(val).lower()}"
                    cell = f'<span class="badge {badge_cls}">{val}</span>'
                elif k in ('url', 'source_url', 'asset') and str(val).startswith('http'):
                    cell = f'<a href="{val}" style="color:#60a5fa;font-size:12px;" target="_blank">{val}</a>'
                html += f'<td>{cell}</td>'
            html += '</tr>'
        if len(items) > 200:
            html += f'<tr><td colspan="{len(keys)}" style="color:#94a3b8;">... and {len(items)-200} more</td></tr>'
        html += '</tbody></table></div>'
        return html


def generate_report(domain, results, shadow=None, output_dir="output", config=None):
    """Module-level convenience function."""
    gen = ReportGenerator(config)
    return gen.generate(domain, results, shadow, output_dir=output_dir)