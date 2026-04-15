CONFIG = {
    "SHODAN_API_KEY": "ch3B9acvBQSytoXxLC22hVtBfxSenqmX",
    "VIRUSTOTAL_API_KEY": "1fed4afd6df5435727e7ee6b1e256e825fa8f68713db8f7fe0b4b64ee82ae83d",
    "CENSYS_API_ID": "",
    "CENSYS_API_SECRET": "",
    "HUNTER_API_KEY": "cb114799b2cece87eb1363de9c985b5287b05fa2",
    "GITHUB_TOKEN": "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",
    "HIBP_API_KEY": "",
    "BUILTWITH_API_KEY": "",
    "SECURITYTRAILS_API_KEY": "",
    "REQUEST_TIMEOUT": 10,
    "REQUEST_DELAY": 1,
    "MAX_SUBDOMAINS": 500,
    "MAX_IPS_TO_SCAN": 500,
    "SECRET_MAX_TARGETS": 150,
    "THREADS": 30,
    "OUTPUT_DIR": "./output",
    "USER_AGENT": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "GOOGLE_API_KEY": "",          # Your Google API key
    "GOOGLE_CX_ID": "",           # Your Custom Search Engine ID
    "GOOGLE_DORKING_ENABLED": True,
    "GOOGLE_DORKING_MAX_PAGES": 5, # Pages per dork (API: 1 page = 10 results, max 10 pages)
    # ── Web Vulnerability Scanner ──
    "VULN_MAX_TARGETS": 300,          # Max subdomains to scan
    "VULN_MAX_PARAMS_PER_PAGE": 15,  # Max params to test per page
    "VULN_THREADS": 20,               # Concurrent threads
    "VULN_SQLI_TIME_THRESHOLD": 2,   # Seconds for time-based SQLi
    "VULN_CRAWL_DEPTH": 5,           # How deep to crawl
    "VULN_SCAN_LEVEL": "standard",   # light, standard, thorough
}
