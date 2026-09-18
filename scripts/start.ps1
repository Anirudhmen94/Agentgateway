# Start Agent Trust Gateway on 127.0.0.1:8000 (Windows PowerShell)
$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)

if (-not (Test-Path ".env")) {
    Copy-Item ".env.example" ".env"
    Write-Host "Copied .env.example to .env — set GATEWAY_TOKEN before a real demo."
}

if (-not $env:GATEWAY_HOST) { $env:GATEWAY_HOST = "127.0.0.1" }
if (-not $env:GATEWAY_PORT) { $env:GATEWAY_PORT = "8000" }

Write-Host "Listening on http://$($env:GATEWAY_HOST):$($env:GATEWAY_PORT)  (GET /health, GET /ready)"
python -m src.app
