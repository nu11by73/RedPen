pip install androguard macholib python-docx frida frida-tools
# optional PATH tools: jadx, apktool, trivy, grype

# Static only
python3 mobscan.py app.apk
python3 mobscan.py MyApp.ipa --format word --output report.docx

# Static + dynamic (device/emulator/Corellium with frida-server running)
python3 mobscan.py app.apk --dynamic --dyn-target com.example.app --dyn-duration 45
python3 mobscan.py MyApp.ipa --dynamic --dyn-target "AppName" --dyn-host 10.11.1.1

# CI with baseline suppression
python3 mobscan.py app.apk --format json --output out.json \
    --min-severity MEDIUM --baseline baseline.json --auto-suppress
# Basic scan
python3 mobscan.py app-release.apk

# With baseline suppression (first run seeds it, later runs respect it)
python3 mobscan.py app-release.apk --baseline baseline.json --auto-suppress


Connect to Android in Corellium:
python3 mobscan.py app.apk \
    --dynamic \
    --dyn-target com.example.app \
    --dyn-host <CORELLIUM_DEVICE_IP> \
    --dyn-duration 45
