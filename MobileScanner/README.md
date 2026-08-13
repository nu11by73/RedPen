# Install optional deps for full power
pip install androguard macholib python-docx

# Basic scan
python3 mobscan.py app-release.apk

# With baseline suppression (first run seeds it, later runs respect it)
python3 mobscan.py app-release.apk --baseline baseline.json --auto-suppress

# Word report
python3 mobscan.py MyApp.ipa --format word --output report.docx

# CI-friendly: JSON, medium+ only, suppress known FPs
python3 mobscan.py app.apk --format json --output out.json \
    --min-severity MEDIUM --baseline baseline.json
