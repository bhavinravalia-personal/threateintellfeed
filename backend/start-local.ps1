$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Push-Location $scriptDir

if (-not (Test-Path 'node_modules')) {
  Write-Host 'Installing backend dependencies...'
  npm install
}

if (-not (Test-Path '.env') -and Test-Path '.env.example') {
  Copy-Item '.env.example' '.env' -Force
  Write-Host 'Created .env from .env.example'
}

Write-Host 'Starting local threat intelligence dashboard...'
node index.js

Pop-Location
