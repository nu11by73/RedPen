# setup.ps1 — Creates venv, installs dependencies, prepares workspace.
# Run once from the pentest-app folder:  .\setup.ps1

$ErrorActionPreference = "Stop"

Write-Host "=== LLM Pentest Workbench Setup ===" -ForegroundColor Cyan

# Check Python
$pythonCmd = Get-Command python -ErrorAction SilentlyContinue
if (-not $pythonCmd) {
    Write-Host "Python not found in PATH. Install Python 3.11+ from python.org first." -ForegroundColor Red
    exit 1
}
$pyVersion = & python --version
Write-Host "Found: $pyVersion" -ForegroundColor Green

# Create venv
if (-not (Test-Path ".\venv")) {
    Write-Host "Creating virtual environment..." -ForegroundColor Yellow
    python -m venv venv
} else {
    Write-Host "venv already exists, skipping creation." -ForegroundColor Yellow
}

# Activate
Write-Host "Activating venv..." -ForegroundColor Yellow
& .\venv\Scripts\Activate.ps1

# Upgrade pip
python -m pip install --upgrade pip

# Install core requirements
Write-Host "Installing core dependencies..." -ForegroundColor Yellow
pip install -r requirements.txt

# Ask about optional scanners
$installGarak = Read-Host "Install garak (external scanner)? [y/N]"
if ($installGarak -eq "y") {
    pip install garak
}
$installPyrit = Read-Host "Install PyRIT (Microsoft red-team framework)? [y/N]"
if ($installPyrit -eq "y") {
    pip install pyrit
}

Write-Host ""
Write-Host "✅ Setup complete." -ForegroundColor Green
Write-Host "Launch the app with:  .\run.ps1" -ForegroundColor Cyan