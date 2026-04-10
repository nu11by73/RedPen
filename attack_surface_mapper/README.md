# Setup:
pip install -r requirements.txt
notepad config.py
Add your API keys, save, close notepad

# Run Modes:
# Single module
python main.py -d target.com -c "Company Name" -m asn
python main.py -d target.com -c "Company Name" -m domains
python main.py -d target.com -c "Company Name" -m webapps

# Multiple modules
python main.py -d target.com -c "Company Name" -m asn,domains,certs

# All modules (default)
python main.py -d target.com -c "Company Name"
