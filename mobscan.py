#!/usr/bin/env python3
"""
mobscan.py - Unified APK/IPA vulnerability scanner with false-positive validation.

Usage:
    python3 mobscan.py <path-to-apk-or-ipa> [--json report.json]

Requirements (all optional, tool degrades gracefully):
    pip install androguard        # richer APK parsing
    Tools on PATH: unzip, aapt (optional), otool/class-dump (macOS, optional)
"""

import argparse
import hashlib
import json
import os
import plistlib
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List, Dict, Optional


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #
class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Confidence(str, Enum):
    LIKELY_FALSE_POSITIVE = "LIKELY_FALSE_POSITIVE"
    NEEDS_REVIEW = "NEEDS_REVIEW"
    CONFIRMED = "CONFIRMED"


@dataclass
class Finding:
    check_id: str
    title: str
    severity: Severity
    confidence: Confidence
    location: str
    evidence: str
    description: str
    validation: str  # why we rated it this way / how to confirm
    remediation: str = ""

    def to_dict(self):
        d = asdict(self)
        d["severity"] = self.severity.value
        d["confidence"] = self.confidence.value
        return d


# --------------------------------------------------------------------------- #
# Known-benign SDK allowlist (drives false-positive suppression)
# --------------------------------------------------------------------------- #
# Package/namespace fragments for well-known, vetted SDKs. A raw dangerous-API
# hit inside these is downgraded unless corroborated by other evidence.
BENIGN_SDK_MARKERS = {
    "com.dynatrace":        "Dynatrace monitoring SDK",
    "com.medallia.digital": "Medallia Digital survey SDK",
    "com.google.firebase":  "Firebase SDK",
    "com.google.android.gms":"Google Play Services",
    "com.facebook":         "Facebook SDK",
    "androidx.":            "AndroidX",
    "com.squareup.okhttp":  "OkHttp",
    "io.sentry":            "Sentry SDK",
    "com.appsflyer":        "AppsFlyer SDK",
    "com.newrelic":         "New Relic SDK",
}


def in_benign_sdk(path_or_pkg: str) -> Optional[str]:
    for marker, name in BENIGN_SDK_MARKERS.items():
        if marker in path_or_pkg:
            return name
    return None


# --------------------------------------------------------------------------- #
# Secret detection patterns (with validators to reduce noise)
# --------------------------------------------------------------------------- #
SECRET_PATTERNS = [
    # (id, human name, regex, entropy_required)
    ("aws_access_key", "AWS Access Key ID", re.compile(r"AKIA[0-9A-Z]{16}"), False),
    ("aws_secret",     "AWS Secret Key",     re.compile(r"(?i)aws.{0,20}?['\"][0-9a-zA-Z/+]{40}['\"]"), True),
    ("google_api",     "Google API Key",     re.compile(r"AIza[0-9A-Za-z\-_]{35}"), False),
    ("private_key",    "Private Key Block",  re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"), False),
    ("slack_token",    "Slack Token",        re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}"), False),
    ("jwt",            "JWT",                re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), False),
    ("generic_secret", "Generic secret assignment",
        re.compile(r"(?i)(api[_-]?key|secret|passwd|password|token)\s*[:=]\s*['\"][^'\"]{8,}['\"]"), True),
]

# Strings that indicate a "secret" match is actually a placeholder / test value.
FALSE_SECRET_MARKERS = re.compile(
    r"(?i)(example|sample|dummy|test|placeholder|your[_-]?key|xxxx|changeme|123456|foobar|redacted)"
)


def shannon_entropy(s: str) -> float:
    import math
    if not s:
        return 0.0
    freq = {c: s.count(c) for c in set(s)}
    return -sum((n / len(s)) * math.log2(n / len(s)) for n in freq.values())


# --------------------------------------------------------------------------- #
# Utility
# --------------------------------------------------------------------------- #
def sha256_of(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def run(cmd: List[str]) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=120).stdout
    except Exception:
        return ""


def extract_zip(path: str, dest: str):
    with zipfile.ZipFile(path, "r") as z:
        z.extractall(dest)


def walk_files(root: str):
    for dirpath, _, files in os.walk(root):
        for f in files:
            yield os.path.join(dirpath, f)


def read_text(path: str, limit: int = 5_000_000) -> str:
    try:
        with open(path, "rb") as f:
            data = f.read(limit)
        return data.decode("utf-8", errors="ignore")
    except Exception:
        return ""


# --------------------------------------------------------------------------- #
# Shared secret scan (runs on extracted files of either platform)
# --------------------------------------------------------------------------- #
def scan_secrets(root: str) -> List[Finding]:
    findings = []
    text_ext = (".xml", ".json", ".plist", ".txt", ".properties",
                ".js", ".html", ".strings", ".cfg", ".conf", ".dex", ".c", ".m", ".swift")
    for path in walk_files(root):
        rel = os.path.relpath(path, root)
        if not (path.endswith(text_ext) or os.path.getsize(path) < 2_000_000):
            continue
        content = read_text(path)
        if not content:
            continue
        for sid, name, rx, need_entropy in SECRET_PATTERNS:
            for m in rx.finditer(content):
                match = m.group(0)
                snippet = match[:80]

                # --- Validation layer ---
                confidence = Confidence.CONFIRMED
                severity = Severity.HIGH
                validation = "Pattern matched a high-signal secret format."

                if FALSE_SECRET_MARKERS.search(match):
                    confidence = Confidence.LIKELY_FALSE_POSITIVE
                    severity = Severity.INFO
                    validation = "Match contains placeholder/test markers; almost certainly not a live secret."
                elif need_entropy:
                    # Extract the quoted value and entropy-check it
                    val = re.search(r"['\"]([^'\"]{8,})['\"]", match)
                    if val and shannon_entropy(val.group(1)) < 3.5:
                        confidence = Confidence.NEEDS_REVIEW
                        severity = Severity.LOW
                        validation = (f"Low entropy ({shannon_entropy(val.group(1)):.2f}); "
                                      "may be a config string rather than a real secret.")
                    else:
                        validation = "High-entropy value in a secret-like assignment."

                sdk = in_benign_sdk(rel)
                if sdk and confidence != Confidence.CONFIRMED:
                    validation += f" Located inside vetted SDK ({sdk})."

                findings.append(Finding(
                    check_id=f"SECRET_{sid.upper()}",
                    title=f"Possible hardcoded secret: {name}",
                    severity=severity,
                    confidence=confidence,
                    location=rel,
                    evidence=snippet,
                    description="A string matching a known secret/credential format was found in the package.",
                    validation=validation,
                    remediation="Move secrets to a secure backend; never ship live credentials in the binary. "
                                "Rotate any confirmed exposed key.",
                ))
    return findings


# --------------------------------------------------------------------------- #
# ANDROID (APK) analyzer
# --------------------------------------------------------------------------- #
def analyze_apk(path: str, work: str) -> List[Finding]:
    findings: List[Finding] = []
    extract_zip(path, work)

    manifest_text = get_android_manifest(path, work)

    # ---- Manifest checks ----
    if manifest_text:
        findings += check_android_manifest(manifest_text)

    # ---- Dangerous WebView / JS bridge (with corroboration) ----
    findings += check_android_webview(work)

    # ---- Cleartext / networking ----
    findings += check_android_network(work, manifest_text)

    # ---- Native lib / binary presence ----
    if any(f.endswith(".so") for f in walk_files(work)):
        findings.append(Finding(
            check_id="ANDROID_NATIVE_LIBS",
            title="Native libraries present",
            severity=Severity.INFO,
            confidence=Confidence.CONFIRMED,
            location="lib/",
            evidence="*.so found",
            description="App ships native code; consider separate binary hardening review.",
            validation="Informational.",
        ))
    return findings


def get_android_manifest(apk_path: str, work: str) -> str:
    """Try aapt first (decodes binary XML), then androguard, else raw."""
    aapt = shutil.which("aapt") or shutil.which("aapt2")
    if aapt:
        out = run([aapt, "dump", "xmltree", apk_path, "AndroidManifest.xml"])
        if out:
            return out
    try:
        from androguard.core.bytecodes.apk import APK  # type: ignore
        return APK(apk_path).get_android_manifest_axml().get_xml()
    except Exception:
        pass
    # Fallback: raw (binary) manifest — strings still leak useful markers
    mpath = os.path.join(work, "AndroidManifest.xml")
    return read_text(mpath)


def check_android_manifest(mtext: str) -> List[Finding]:
    findings = []
    checks = [
        ("android:debuggable", "true", "ANDROID_DEBUGGABLE",
         "Application is debuggable", Severity.HIGH,
         "A debuggable release build lets attackers attach a debugger and inspect/modify runtime state.",
         "Debuggable flag found set to true in manifest.",
         "Set android:debuggable=false (or omit it) in release builds."),
        ("android:allowBackup", "true", "ANDROID_ALLOWBACKUP",
         "Backups allowed (allowBackup=true)", Severity.MEDIUM,
         "App data can be extracted via adb backup on some devices.",
         "allowBackup=true present.",
         "Set android:allowBackup=false unless backups are required."),
        ("android:usesCleartextTraffic", "true", "ANDROID_CLEARTEXT_FLAG",
         "Cleartext traffic permitted", Severity.MEDIUM,
         "App is allowed to send/receive unencrypted HTTP traffic.",
         "usesCleartextTraffic=true present.",
         "Disable cleartext traffic; enforce HTTPS via network security config."),
    ]
    for needle, val, cid, title, sev, desc, ev, rem in checks:
        # crude but works across aapt/androguard/raw output
        if needle in mtext and val in mtext:
            # Confidence: aapt/androguard output is authoritative; raw fallback less so
            conf = Confidence.CONFIRMED
            findings.append(Finding(
                check_id=cid, title=title, severity=sev, confidence=conf,
                location="AndroidManifest.xml", evidence=f"{needle}={val}",
                description=desc,
                validation=ev + " Confirm the value applies to the release build config.",
                remediation=rem,
            ))

    # Exported components without permission (heuristic)
    if "android:exported" in mtext and "true" in mtext:
        findings.append(Finding(
            check_id="ANDROID_EXPORTED_COMPONENT",
            title="Exported component(s) detected",
            severity=Severity.MEDIUM,
            confidence=Confidence.NEEDS_REVIEW,
            location="AndroidManifest.xml",
            evidence="android:exported=true",
            description="One or more components are exported and may be invokable by other apps.",
            validation="Heuristic: verify each exported activity/service/receiver enforces a "
                       "signature/permission and validates incoming intents. Exported alone is not a vuln.",
            remediation="Add permission guards, validate all intent extras, or set exported=false.",
        ))
    return findings


def check_android_webview(work: str) -> List[Finding]:
    """
    Detect addJavascriptInterface + setJavaScriptEnabled in decompiled/smali/dex strings,
    then CORROBORATE with evidence of remote/untrusted content before rating HIGH.
    This directly addresses the Dynatrace/Medallia false-positive scenario.
    """
    findings = []
    has_js_bridge = False
    bridge_locations = set()
    loads_remote_http = False
    ssl_bypass = False

    js_bridge_rx = re.compile(r"addJavascriptInterface")
    loadurl_http_rx = re.compile(r"loadUrl$$\s*[\"']http://")
    ssl_bypass_rx = re.compile(r"onReceivedSslError")
    ssl_proceed_rx = re.compile(r"\.proceed$$")

    for path in walk_files(work):
        if os.path.getsize(path) > 20_000_000:
            continue
        content = read_text(path)
        if not content:
            continue
        rel = os.path.relpath(path, work)
        if js_bridge_rx.search(content):
            has_js_bridge = True
            bridge_locations.add(rel)
        if loadurl_http_rx.search(content):
            loads_remote_http = True
        if ssl_bypass_rx.search(content) and ssl_proceed_rx.search(content):
            ssl_bypass = True

    if has_js_bridge:
        # Determine if the bridge lives entirely inside benign SDKs
        sdk_only = all(in_benign_sdk(loc) for loc in bridge_locations) if bridge_locations else False
        benign_name = next((in_benign_sdk(l) for l in bridge_locations if in_benign_sdk(l)), None)

        if loads_remote_http or ssl_bypass:
            sev, conf = Severity.HIGH, Confidence.CONFIRMED
            validation = ("Corroborated: JS bridge PLUS " +
                          ("cleartext HTTP loadUrl " if loads_remote_http else "") +
                          ("and SSL-error bypass (handler.proceed) " if ssl_bypass else "") +
                          "means untrusted content can reach native code.")
        elif sdk_only:
            sev, conf = Severity.LOW, Confidence.LIKELY_FALSE_POSITIVE
            validation = (f"JS bridge exists only inside vetted SDK ({benign_name}). "
                          "No evidence of untrusted/HTTP content. Standard hybrid pattern — "
                          "review only the SDK's exposed @JavascriptInterface methods.")
        else:
            sev, conf = Severity.MEDIUM, Confidence.NEEDS_REVIEW
            validation = ("JS bridge present but no HTTP load or SSL bypass observed statically. "
                          "Confirm the WebView loads only trusted HTTPS/local content and that "
                          "exposed @JavascriptInterface methods handle no sensitive data.")

        findings.append(Finding(
            check_id="ANDROID_JS_BRIDGE",
            title="WebView JavaScript bridge (addJavascriptInterface)",
            severity=sev, confidence=conf,
            location="; ".join(sorted(bridge_locations))[:300] or "dex/smali",
            evidence="addJavascriptInterface" +
                     (" + loadUrl(http://)" if loads_remote_http else "") +
                     (" + onReceivedSslError.proceed()" if ssl_bypass else ""),
            description="Native code is exposed to JavaScript via a WebView bridge.",
            validation=validation,
            remediation="Load only trusted HTTPS/local content, annotate exposed methods with "
                        "@JavascriptInterface, restrict navigation with a WebViewClient whitelist, "
                        "and never bypass SSL errors.",
        ))
    return findings


def check_android_network(work: str, manifest_text: str) -> List[Finding]:
    findings = []
    # network_security_config.xml presence & cleartext permission
    for path in walk_files(work):
        if path.endswith("network_security_config.xml") or path.endswith("network_security_config"):
            content = read_text(path)
            if 'cleartextTrafficPermitted="true"' in content:
                findings.append(Finding(
                    check_id="ANDROID_NSC_CLEARTEXT",
                    title="Network security config permits cleartext",
                    severity=Severity.MEDIUM, confidence=Confidence.CONFIRMED,
                    location=os.path.relpath(path, work),
                    evidence='cleartextTrafficPermitted="true"',
                    description="Network security config explicitly allows cleartext HTTP.",
                    validation="Confirm which domains this applies to; scoped exceptions may be acceptable.",
                    remediation="Restrict to specific domains or remove; enforce HTTPS globally.",
                ))
    return findings


# --------------------------------------------------------------------------- #
# iOS (IPA) analyzer
# --------------------------------------------------------------------------- #
def analyze_ipa(path: str, work: str) -> List[Finding]:
    findings: List[Finding] = []
    extract_zip(path, work)

    app_dir = find_app_dir(work)
    if not app_dir:
        findings.append(Finding(
            check_id="IPA_STRUCTURE",
            title="No .app bundle found",
            severity=Severity.INFO, confidence=Confidence.CONFIRMED,
            location="Payload/", evidence="missing .app",
            description="Could not locate the .app bundle inside Payload/.",
            validation="Verify this is a valid IPA.",
        ))
        return findings

    info_plist = os.path.join(app_dir, "Info.plist")
    plist = load_plist(info_plist)

    findings += check_ios_ats(plist, os.path.relpath(info_plist, work))
    findings += check_ios_urlschemes(plist, os.path.relpath(info_plist, work))
    findings += check_ios_binary(app_dir, work)
    findings += check_ios_encryption(app_dir, work)
    return findings


def find_app_dir(work: str) -> Optional[str]:
    payload = os.path.join(work, "Payload")
    base = payload if os.path.isdir(payload) else work
    for entry in os.listdir(base):
        if entry.endswith(".app"):
            return os.path.join(base, entry)
    return None


def load_plist(path: str) -> dict:
    try:
        with open(path, "rb") as f:
            return plistlib.load(f)
    except Exception:
        # Binary plist may need `plutil -convert xml1`; try that
        if shutil.which("plutil"):
            tmp = path + ".xml"
            run(["plutil", "-convert", "xml1", "-o", tmp, path])
            try:
                with open(tmp, "rb") as f:
                    return plistlib.load(f)
            except Exception:
                return {}
        return {}


def check_ios_ats(plist: dict, loc: str) -> List[Finding]:
    findings = []
    ats = plist.get("NSAppTransportSecurity", {})
    if ats.get("NSAllowsArbitraryLoads") is True:
        # Corroboration: is it globally on, or scoped by exception domains?
        has_exceptions = bool(ats.get("NSExceptionDomains"))
        if has_exceptions:
            sev, conf = Severity.LOW, Confidence.NEEDS_REVIEW
            validation = ("Arbitrary loads enabled but exception domains are defined — "
                          "on iOS 10+ scoped exceptions may override the global flag. Review the domain list.")
        else:
            sev, conf = Severity.HIGH, Confidence.CONFIRMED
            validation = "NSAllowsArbitraryLoads=true with no scoping disables ATS app-wide (cleartext allowed everywhere)."
        findings.append(Finding(
            check_id="IOS_ATS_DISABLED",
            title="App Transport Security weakened",
            severity=sev, confidence=conf,
            location=loc, evidence="NSAllowsArbitraryLoads=true",
            description="ATS is disabled or weakened, permitting insecure HTTP connections.",
            validation=validation,
            remediation="Remove NSAllowsArbitraryLoads; use narrowly scoped NSExceptionDomains only where required.",
        ))
    return findings


def check_ios_urlschemes(plist: dict, loc: str) -> List[Finding]:
    findings = []
    schemes = []
    for entry in plist.get("CFBundleURLTypes", []) or []:
        schemes += entry.get("CFBundleURLSchemes", []) or []
    if schemes:
        findings.append(Finding(
            check_id="IOS_CUSTOM_URL_SCHEME",
            title="Custom URL scheme(s) registered",
            severity=Severity.LOW, confidence=Confidence.NEEDS_REVIEW,
            location=loc, evidence=", ".join(schemes)[:120],
            description="App registers custom URL schemes that other apps can invoke.",
            validation="Not a vuln by itself. Verify deep-link handlers validate/sanitize all incoming "
                       "parameters and don't perform sensitive actions without authorization.",
            remediation="Validate all deep-link input; prefer Universal Links for sensitive flows.",
        ))
    return findings


def check_ios_binary(app_dir: str, work: str) -> List[Finding]:
    """Binary hardening checks via otool (macOS). Degrades gracefully off-macOS."""
    findings = []
    binary = find_macho_binary(app_dir)
    if not binary:
        return findings
    rel = os.path.relpath(binary, work)
    otool = shutil.which("otool")
    if not otool:
        findings.append(Finding(
            check_id="IOS_BINARY_TOOLING",
            title="Binary hardening not checked (otool unavailable)",
            severity=Severity.INFO, confidence=Confidence.CONFIRMED,
            location=rel, evidence="otool not on PATH",
            description="Skipped PIE/stack-canary/ARC checks; run on macOS with Xcode tools.",
            validation="Informational.",
        ))
        return findings

    headers = run([otool, "-hv", binary])
    loadcmds = run([otool, "-l", binary])
    symbols = run([otool, "-Iv", binary])

    if "PIE" not in headers:
        findings.append(Finding(
            check_id="IOS_NO_PIE",
            title="Binary not compiled with PIE",
            severity=Severity.MEDIUM, confidence=Confidence.CONFIRMED,
            location=rel, evidence="PIE flag absent in Mach-O header",
            description="No Position Independent Executable — weakens ASLR.",
            validation="Confirmed from otool -hv header flags.",
            remediation="Compile with -fPIE -pie (default in modern Xcode).",
        ))
    if "stack_chk" not in symbols:
        findings.append(Finding(
            check_id="IOS_NO_STACK_CANARY",
            title="No stack canary detected",
            severity=Severity.MEDIUM, confidence=Confidence.NEEDS_REVIEW,
            location=rel, evidence="__stack_chk_* symbols not found",
            description="Stack-smashing protection may be absent.",
            validation="Heuristic: absence of __stack_chk symbols. May be stripped; verify with a second tool.",
            remediation="Build with -fstack-protector-all.",
        ))
    if "_objc_release" not in symbols and "_objc_autorelease" not in symbols:
        findings.append(Finding(
            check_id="IOS_NO_ARC",
            title="ARC possibly not enabled",
            severity=Severity.LOW, confidence=Confidence.NEEDS_REVIEW,
            location=rel, evidence="ARC-related symbols not found",
            description="Automatic Reference Counting may be disabled (memory-safety risk).",
            validation="Heuristic based on symbol presence; confirm manually.",
            remediation="Enable ARC.",
        ))
    return findings


def check_ios_encryption(app_dir: str, work: str) -> List[Finding]:
    findings = []
    binary = find_macho_binary(app_dir)
    if not binary:
        return findings
    rel = os.path.relpath(binary, work)
    otool = shutil.which("otool")
    if not otool:
        return findings
    out = run([otool, "-l", binary])
    m = re.search(r"cryptid\s+(\d+)", out)
    if m and m.group(1) == "0":
        findings.append(Finding(
            check_id="IOS_NOT_ENCRYPTED",
            title="Binary is not FairPlay-encrypted (cryptid=0)",
            severity=Severity.INFO, confidence=Confidence.CONFIRMED,
            location=rel, evidence="cryptid 0",
            description="Binary is decrypted — static analysis (strings/secrets) will be reliable.",
            validation="Good for analysis. Encrypted App Store binaries need frida-ios-dump first.",
        ))
    elif m:
        findings.append(Finding(
            check_id="IOS_ENCRYPTED",
            title="Binary is FairPlay-encrypted (cryptid=1)",
            severity=Severity.INFO, confidence=Confidence.CONFIRMED,
            location=rel, evidence="cryptid 1",
            description="Encrypted binary — static secret/string findings will be incomplete.",
            validation="Decrypt with frida-ios-dump on a jailbroken/Corellium device, then re-scan for full coverage.",
        ))
    return findings


def find_macho_binary(app_dir: str) -> Optional[str]:
    # Executable name is in Info.plist CFBundleExecutable
    plist = load_plist(os.path.join(app_dir, "Info.plist"))
    exe = plist.get("CFBundleExecutable")
    if exe:
        cand = os.path.join(app_dir, exe)
        if os.path.isfile(cand):
            return cand
    # Fallback: largest file without extension
    best, best_size = None, 0
    for f in os.listdir(app_dir):
        full = os.path.join(app_dir, f)
        if os.path.isfile(full) and "." not in f and os.path.getsize(full) > best_size:
            best, best_size = full, os.path.getsize(full)
    return best


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #
SEV_ORDER = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2,
             Severity.LOW: 3, Severity.INFO: 4}


def print_report(target: str, filetype: str, digest: str, findings: List[Finding]):
    findings.sort(key=lambda f: (SEV_ORDER[f.severity], f.confidence.value))
    print("=" * 78)
    print(f" Mobile App Scan Report")
    print(f" Target : {target}")
    print(f" Type   : {filetype}")
    print(f" SHA256 : {digest}")
    print(f" Findings: {len(findings)}")
    print("=" * 78)

    # Summary counts
    counts = {}
    for f in findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
    print(" Severity summary: " +
          ", ".join(f"{k}={v}" for k, v in counts.items()))
    fp = sum(1 for f in findings if f.confidence == Confidence.LIKELY_FALSE_POSITIVE)
    print(f" Likely false positives (auto-downgraded): {fp}")
    print("-" * 78)

    for f in findings:
        flag = " [LIKELY FP]" if f.confidence == Confidence.LIKELY_FALSE_POSITIVE else ""
        print(f"\n[{f.severity.value}]{flag} {f.title}  ({f.check_id})")
        print(f"  Confidence : {f.confidence.value}")
        print(f"  Location   : {f.location}")
        print(f"  Evidence   : {f.evidence}")
        print(f"  Detail     : {f.description}")
        print(f"  Validation : {f.validation}")
        if f.remediation:
            print(f"  Fix        : {f.remediation}")
    print("\n" + "=" * 78)


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def detect_type(path: str) -> str:
    lower = path.lower()
    if lower.endswith(".apk"):
        return "APK"
    if lower.endswith(".ipa"):
        return "IPA"
    # Sniff contents
    try:
        with zipfile.ZipFile(path) as z:
            names = z.namelist()
            if any(n == "AndroidManifest.xml" or n.startswith("classes") for n in names):
                return "APK"
            if any(n.startswith("Payload/") for n in names):
                return "IPA"
    except Exception:
        pass
    return "UNKNOWN"


def main():
    ap = argparse.ArgumentParser(description="APK/IPA vulnerability scanner with FP validation.")
    ap.add_argument("target", help="Path to .apk or .ipa file")
    ap.add_argument("--json", help="Write JSON report to this path")
    ap.add_argument("--min-severity", default="INFO",
                    choices=[s.value for s in Severity],
                    help="Only show findings at or above this severity")
    args = ap.parse_args()

    if not os.path.isfile(args.target):
        print(f"error: file not found: {args.target}", file=sys.stderr)
        sys.exit(1)

    ftype = detect_type(args.target)
    if ftype == "UNKNOWN":
        print("error: could not determine file type (not a valid APK/IPA zip).", file=sys.stderr)
        sys.exit(1)

    digest = sha256_of(args.target)
    findings: List[Finding] = []

    with tempfile.TemporaryDirectory() as work:
        if ftype == "APK":
            findings += analyze_apk(args.target, work)
        else:
            findings += analyze_ipa(args.target, work)
        # Shared secret scan across extracted contents
        findings += scan_secrets(work)

    # Filter by min severity
    threshold = SEV_ORDER[Severity(args.min_severity)]
    findings = [f for f in findings if SEV_ORDER[f.severity] <= threshold]

    print_report(args.target, ftype, digest, findings)

    if args.json:
        report = {
            "target": args.target,
            "type": ftype,
            "sha256": digest,
            "findings": [f.to_dict() for f in findings],
        }
        with open(args.json, "w") as f:
            json.dump(report, f, indent=2)
        print(f"JSON report written to {args.json}")


if __name__ == "__main__":
    main()