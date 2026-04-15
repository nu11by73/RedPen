#!/usr/bin/env python3
"""
Re-validate exposed endpoint findings from an existing JSON report.
Removes false positives and saves a cleaned report.

Usage: python revalidate_findings.py output/asm_lpl.com_XXXXXX.json
"""

import sys
import json
import re
import requests

# Import the validator
sys.path.insert(0, '.')
from modules.web_app_api import (
    _validate_exposed_endpoint,
    ENDPOINT_SIGNATURES,
    FALSE_POSITIVE_INDICATORS
)


def revalidate(json_path):
    with open(json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    })
    session.verify = False

    import urllib3
    urllib3.disable_warnings()

    total_removed = 0

    # Check shadow_it_summary
    shadow = data.get('shadow_it', {})
    summary = shadow.get('shadow_it_summary', [])

    for category in summary:
        cat_name = category.get('category', '')
        items = category.get('items', [])

        if 'Exposed' not in cat_name and 'Infrastructure' not in cat_name:
            continue

        original_count = len(items)
        cleaned = []

        for item in items:
            itype = item.get('type', '').lower()
            asset = item.get('asset', '')

            if 'exposed database' not in itype and 'exposed' not in itype:
                cleaned.append(item)
                continue

            if not asset.startswith('http'):
                cleaned.append(item)
                continue

            # Determine tool
            tool_key = 'default'
            for key in ENDPOINT_SIGNATURES:
                if key != 'default' and (
                    key.replace('_', '') in asset.lower() or
                    key.replace('_', ' ') in item.get('reason', '').lower()
                ):
                    tool_key = key
                    break

            try:
                resp = session.get(asset, timeout=10, allow_redirects=True)
                is_valid, confidence, reason = _validate_exposed_endpoint(asset, resp, tool_key)

                if is_valid:
                    item['validated'] = True
                    item['confidence'] = confidence
                    cleaned.append(item)
                    print(f"  [VALID]   {asset} ({confidence}: {reason})")
                else:
                    total_removed += 1
                    print(f"  [REMOVED] {asset} ({reason})")
            except Exception as e:
                item['validated'] = False
                item['validation_error'] = str(e)
                cleaned.append(item)
                print(f"  [ERROR]   {asset} ({e})")

        category['items'] = cleaned
        category['count'] = len(cleaned)

        removed = original_count - len(cleaned)
        if removed:
            print(f"  Removed {removed} false positive(s) from {cat_name}")

    # Save cleaned report
    out_path = json_path.replace('.json', '_validated.json')
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, default=str)

    print(f"\nTotal false positives removed: {total_removed}")
    print(f"Validated report saved: {out_path}")


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python revalidate_findings.py <path_to_json_report>")
        print("Example: python revalidate_findings.py output/asm_lpl.com_20260413_140459.json")
        sys.exit(1)

    revalidate(sys.argv[1])
