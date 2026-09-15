# start-demo.ps1 - one-click demo prep. Run from anywhere:
#   & "<repo>\examples\recruiting-demo\start-demo.ps1"
# Activates the repo venv, seeds Alice/Bob/Carol, opens the verifier page,
# and leaves this shell in the demo dir ready for the run-of-show (RUNBOOK.md).
# DEMO_DATABASE_URL is read from the environment or prompted - never stored.

$ErrorActionPreference = "Stop"

$demo = $PSScriptRoot
$repo = Split-Path -Parent (Split-Path -Parent $demo)
$verifier = Join-Path $demo "verify.html"

$activate = Join-Path $repo ".venv\Scripts\Activate.ps1"
if (-not (Test-Path $activate)) {
    throw "venv not found at $activate - create it first: python -m venv .venv; .venv\Scripts\pip install -e ."
}
. $activate

Set-Location $demo

if (-not $env:DEMO_DATABASE_URL) {
    $env:DEMO_DATABASE_URL = Read-Host "DEMO_DATABASE_URL (throwaway Postgres + pgvector, e.g. Neon)"
}
if (-not $env:DEMO_SALT) {
    # No committed default: the salt pseudonymizes subjects in the ledger.
    # Generated per session and PRINTED, because setup.py and forget.py must
    # use the same one - a second shell needs this value, not a fresh one.
    # A GUID is plenty for a throwaway demo over synthetic data; it is not a
    # recipe for generating a production secret.
    $env:DEMO_SALT = [guid]::NewGuid().ToString("N")
    Write-Host "Generated DEMO_SALT for this session: $env:DEMO_SALT" -ForegroundColor Yellow
    Write-Host "  Running the demo from another shell? Set the same value there." -ForegroundColor DarkGray
}

python setup.py
if ($LASTEXITCODE -ne 0) { throw "setup.py failed - check DEMO_DATABASE_URL and that the venv has lethe installed" }

if (Test-Path $verifier) {
    Start-Process $verifier
} else {
    Write-Warning "verifier page not found at $verifier - open verify.html in this directory manually"
}

Write-Host ""
Write-Host "Demo ready. Run-of-show (full script: RUNBOOK.md):" -ForegroundColor Green
Write-Host '  1. python search.py "senior React engineer in Berlin, fintech"'
Write-Host "  2. python forget.py alice.chen@demo.test"
Write-Host '  3. python search.py "senior React engineer in Berlin, fintech"   # <- the money moment'
Write-Host "  4. open cert.json; paste it + the public key printed above into the verifier tab"
Write-Host "  Reset between demos: python setup.py"
