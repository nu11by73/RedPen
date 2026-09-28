***Scanner to identify mcp servers***

**Requirements Install**
python -m pip install httpx ipwhois

**Discover Ranges**
python mcp_perimeter_scanner.py discover \
  --domain example.com \
  --domain api.example.com \
  --output discovery.json \
  --approval-template approved-cidrs.txt

**Scanning Approved Ranges**
python mcp_perimeter_scanner.py scan \
  --cidr-file approved-cidrs.txt \
  --hostname example.com \
  --hostname api.example.com \
  --output mcp-findings.json

**Custom Ports and Paths**
python mcp_perimeter_scanner.py scan \
  --cidr-file approved-cidrs.txt \
  --hostname mcp.example.com \
  --ports 80,443,3000,8000,8080,8443,9000 \
  --paths /mcp,/sse,/api/mcp,/internal/mcp \
  --concurrency 150 \
  --timeout 5 \
  --max-hosts 8192 \
  --output mcp-findings.json

**Approval Template Example**
# Review every CIDR before removing the leading '#'.
# Approve only company-owned or explicitly authorized ranges.

# 192.0.2.0/24
# 198.51.100.0/24
