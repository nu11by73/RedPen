# Setup:
pip install -r requirements.txt

notepad config.py
Add your API keys, save, close notepad
Note: For the GitHub key it is a read-only, fine grained, token

# Run Modes:
# Single module
python main.py -d target.com -c "Company Name" -m asn
python main.py -d target.com -c "Company Name" -m domains
python main.py -d target.com -c "Company Name" -m webapps

# Multiple modules
python main.py -d target.com -c "Company Name" -m asn,domains,certs

# All modules (default)
python main.py -d target.com -c "Company Name"


# Cloudflare Check:
# Feed it your ASM scan output directly
python cf_check.py output\asm_target_20260410_123456.json

# Or a text file of IPs (one per line)
python cf_check.py ips.txt

# Or a single domain
python cf_check.py example.com

# Or comma-separated IPs
python cf_check.py 104.16.1.1,8.8.8.8,192.168.1.1

# Export results to JSON
python cf_check.py output\asm_target.json --export


# API Endpoint Identification:
# Run just the secret scanner
python main.py -d target.com -m 10

# Run with subdomain discovery first (recommended)
python main.py -d target.com -m 2,10

# Run everything including secrets
python main.py -d target.com -c "Company Name"
