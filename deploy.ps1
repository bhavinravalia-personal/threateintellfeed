$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$backend = Join-Path $root 'backend'

if (-not (Test-Path $backend)) {
  Write-Error "Backend folder not found at $backend"
  exit 1
}

Write-Host "Preparing deployment helper in: $backend"
Push-Location $backend

if (-not (Test-Path '.env')) {
  if (Test-Path '.env.example') {
    Copy-Item '.env.example' '.env' -Force
    Write-Host "Created .env from .env.example"
  } else {
    Write-Warning "No .env.example file found. Please create .env manually."
  }
}

Write-Host 'Installing backend dependencies...'
npm install

if (Get-Command git -ErrorAction SilentlyContinue) {
  if (-not (Test-Path '.git')) {
    Write-Host 'Initializing local git repository...'
    git init
    git add .
    git commit -m 'Prepare deployment' | Out-Null
    Write-Host 'Git repository initialized and initial commit created.'
  } else {
    Write-Host 'Git repository already exists.'
  }
} else {
  Write-Warning 'Git is not available in this terminal. Install Git to push the repo to GitHub.'
}

Write-Host ''
Write-Host 'Deployment helper is ready.'
Write-Host 'Next steps:'
Write-Host ' 1. Push this repository to GitHub.'
Write-Host ' 2. Open DEPLOYMENT.md for Render/Railway/Azure instructions.'
Write-Host ' 3. On your host, set build command: npm install'
Write-Host ' 4. On your host, set start command: npm start'
Write-Host ' 5. Add environment variables: PORT, FETCH_INTERVAL_SECONDS, OTX_API_KEY, ABUSEIPDB_API_KEY'
Write-Host ''
Write-Host 'If you want to test locally, run:'
Write-Host '  cd backend'
Write-Host '  node index.js'

Pop-Location
