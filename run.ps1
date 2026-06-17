# run.ps1 — Activates venv and launches the Streamlit app.

$ErrorActionPreference = "Stop"
if (-not (Test-Path ".\venv")) {
    Write-Host "venv not found. Run .\setup.ps1 first." -ForegroundColor Red
    exit 1
}
& .\venv\Scripts\Activate.ps1
streamlit run app.py