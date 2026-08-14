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
- Download the ovpn file
- Connect to adb
- Connect to Corellium with app:
python3 mobscan.py app.apk \
    --dynamic \
    --dyn-target com.example.app \
    --dyn-host <CORELLIUM_DEVICE_IP> \
    --dyn-duration 45
  
If androguard is enabled at start up use the attach function:
python3 mobscan.py app.apk --dynamic \
    --dyn-target com.example.app \
    --dyn-host 10.11.1.1:27042



FullExample:
# 1. Connect Corellium VPN (via your VPN client using downloaded config)

# 2. Verify device reachable
frida-ps -H 10.11.1.1

# 3. Find the target
frida-ps -H 10.11.1.1 -ai

# 4. Run static + dynamic scan against Corellium, output Word report
python3 mobscan.py MyApp.ipa \
    --dynamic \
    --dyn-target "MyApp" \
    --dyn-host 10.11.1.1 \
    --dyn-duration 60 \
    --format word \
    --output corellium_report.docx

# 5. When the console says "EXERCISE THE APP NOW" — interact with the app
#    in the Corellium device screen (log in, submit forms, open deep links)
