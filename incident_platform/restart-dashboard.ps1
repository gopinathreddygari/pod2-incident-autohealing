<#
.SYNOPSIS
  Restart the live demo dashboard, optionally switching between real GPT and the mock first.

.EXAMPLE
  .\restart-dashboard.cmd            # restart, keeping whatever .env says
  .\restart-dashboard.cmd gpt        # set INCIDENT_PLATFORM_USE_REAL_LLM=true in .env, then restart
  .\restart-dashboard.cmd mock       # set it to false, then restart
  .\restart-dashboard.cmd gpt -Port 8001 -Pii heuristic -NoBrowser
  .\restart-dashboard.cmd mock -NoRestart   # only flip the switch

.NOTES
  Only the INCIDENT_PLATFORM_USE_REAL_LLM line of .env is ever changed. The API key is never
  read out or printed. The server runs in this window: press Ctrl+C to stop it.
#>
param(
    [ValidateSet("gpt", "mock", "")] [string]$Llm = "",
    [int]$Port = 8000,
    [ValidateSet("off", "heuristic", "spacy")] [string]$Pii = "spacy",
    [switch]$NoBrowser,
    [switch]$NoRestart,     # only update the switch in .env; leave the running dashboard alone
    [string]$EnvFile = ""   # for testing; defaults to .env next to this script
)
$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $here
if (-not $EnvFile) { $EnvFile = Join-Path $here ".env" }
$utf8 = New-Object Text.UTF8Encoding $false

# --- 1. Flip the GPT/mock switch in .env (only that line) --------------------------------
if ($Llm) {
    if (-not (Test-Path $EnvFile)) { Copy-Item (Join-Path $here ".env.example") $EnvFile }
    $value = if ($Llm -eq "gpt") { "true" } else { "false" }
    $lines = [System.Collections.Generic.List[string]]::new()
    $found = $false
    foreach ($line in [IO.File]::ReadAllLines($EnvFile)) {
        if ($line -match '^\s*INCIDENT_PLATFORM_USE_REAL_LLM\s*=') {
            $lines.Add("INCIDENT_PLATFORM_USE_REAL_LLM=$value"); $found = $true
        } else { $lines.Add($line) }
    }
    if (-not $found) { $lines.Add("INCIDENT_PLATFORM_USE_REAL_LLM=$value") }
    [IO.File]::WriteAllLines($EnvFile, $lines, $utf8)
    Write-Host "Switch set: INCIDENT_PLATFORM_USE_REAL_LLM=$value  ($Llm)"
    if ($Llm -eq "gpt" -and -not ($lines -match '^\s*OPENAI_API_KEY\s*=\s*\S')) {
        Write-Warning "OPENAI_API_KEY is empty in .env, so calls will stay on the mock. Add your key: notepad `"$EnvFile`""
    }
}

if ($NoRestart) { Write-Host "Not restarting (-NoRestart). Restart later to apply."; return }

# A switch set in this terminal would override the file, so clear it for a predictable result.
if (Test-Path Env:INCIDENT_PLATFORM_USE_REAL_LLM) {
    Write-Warning "INCIDENT_PLATFORM_USE_REAL_LLM was set in this terminal and would override .env; clearing it."
    Remove-Item Env:INCIDENT_PLATFORM_USE_REAL_LLM
}

# --- 2. Stop any running dashboard ------------------------------------------------------
$running = Get-CimInstance Win32_Process -Filter "Name='python.exe'" |
    Where-Object { $_.CommandLine -match 'ui_server\.py' }
foreach ($p in $running) { Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue }
if ($running) { Write-Host "Stopped $(@($running).Count) running dashboard process(es)." }
for ($i = 0; $i -lt 20 -and (Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue); $i++) {
    Start-Sleep -Milliseconds 250
}
if (Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue) {
    throw "Port $Port is still in use by another program. Try: .\restart-dashboard.cmd -Port 8001"
}

# --- 3. Pick the Python: the venv has openai + spaCy; fall back to the system Python ---
$candidates = @((Join-Path $here ".venv-ner\Scripts\python.exe"),
                "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe")
$py = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $py) { $py = "python" }
Write-Host "Python: $py"

# --- 4. Start (in this window; the server prints which LLM mode it picked up) ----------
$env:INCIDENT_PLATFORM_PII_NER = $Pii
$serverArgs = @("-u", "ui_server.py", "--port", "$Port")
if ($NoBrowser) { $serverArgs += "--no-browser" }
& $py @serverArgs
