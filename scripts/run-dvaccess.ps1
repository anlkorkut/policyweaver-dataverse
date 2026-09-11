<#
.SYNOPSIS
    Run dvaccess from a VS Code (PowerShell) terminal.

.DESCRIPTION
    Creates the virtual environment on first use, resolves credentials, and runs one
    dvaccess stage or the read-only pipeline. extract, compile and plan never write
    to Dataverse, Entra or Fabric. Writing requires -Stage apply together with -Yes.

    Credentials, in order of preference:
      1. Service principal: auth.client_id in the config plus the
         DVACCESS_CLIENT_SECRET environment variable. Supply the secret with
         -KeyVaultName (fetched through az) or -PromptForSecret (typed, hidden).
         Either way it lives only in this PowerShell process and is cleared on exit.
      2. Azure CLI: auth.cli_subscription in the config selects the cached az
         account for the right tenant without changing your global az default.

.EXAMPLE
    .\scripts\run-dvaccess.ps1
    Runs extract, compile and plan. Read-only.
.EXAMPLE
    .\scripts\run-dvaccess.ps1 -Stage plan -DryRun
    Also validates the payload server-side with Fabric. Still no writes.
.EXAMPLE
    .\scripts\run-dvaccess.ps1 -Stage apply -Yes
    Writes the compiled roles to Fabric, then verifies.
.EXAMPLE
    .\scripts\run-dvaccess.ps1 -Stage explain -User someone@contoso.com
.EXAMPLE
    .\scripts\run-dvaccess.ps1 -KeyVaultName kv-dvaccess -SecretName dvaccess-client-secret
#>
[CmdletBinding()]
param(
    [ValidateSet('pipeline', 'extract', 'compile', 'plan', 'apply', 'verify', 'explain')]
    [string] $Stage = 'pipeline',
    [string] $Config = 'config/config.yaml',
    [string] $Run,
    [switch] $DryRun,
    [switch] $Yes,
    [string] $User,
    [string] $Table,
    [string] $KeyVaultName,
    [string] $SecretName = 'dvaccess-client-secret',
    [switch] $PromptForSecret,
    [switch] $DebugLogging
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

# --- virtual environment (called by path: no activation or scope side effects) ---
$venv = Join-Path $repoRoot '.venv-x64'
$python = Join-Path $venv 'Scripts\python.exe'
$dvaccess = Join-Path $venv 'Scripts\dvaccess.exe'
if (-not (Test-Path $python)) {
    Write-Host "Creating virtual environment at $venv ..." -ForegroundColor Cyan
    py -3.11 -m venv $venv
    if ($LASTEXITCODE -ne 0) { throw 'Could not create the virtual environment (is Python 3.11 installed?).' }
}
if (-not (Test-Path $dvaccess)) {
    Write-Host 'Installing dvaccess into the virtual environment ...' -ForegroundColor Cyan
    & $python -m pip install --quiet --upgrade pip
    & $python -m pip install --quiet -e '.[dev]'
    if ($LASTEXITCODE -ne 0) { throw 'pip install failed.' }
}

# --- configuration --------------------------------------------------------------
if (-not (Test-Path $Config)) {
    throw "Config not found: $Config. Copy config/config.example.yaml to config/config.yaml and fill in your ids."
}
$cliSubscription = (Select-String -Path $Config -Pattern '^\s*cli_subscription:\s*"?([0-9a-fA-F-]{36})' |
    Select-Object -First 1).Matches.Groups[1].Value

# --- credentials ----------------------------------------------------------------
$secretSetHere = $false
if ($KeyVaultName -and -not $env:DVACCESS_CLIENT_SECRET) {
    Write-Host "Reading secret '$SecretName' from Key Vault '$KeyVaultName' ..." -ForegroundColor Cyan
    $kvArgs = @('keyvault', 'secret', 'show', '--vault-name', $KeyVaultName, '--name', $SecretName,
        '--query', 'value', '-o', 'tsv')
    if ($cliSubscription) { $kvArgs += @('--subscription', $cliSubscription) }
    $env:DVACCESS_CLIENT_SECRET = & az @kvArgs
    if (-not $env:DVACCESS_CLIENT_SECRET) { throw "Could not read secret '$SecretName' from '$KeyVaultName'." }
    $secretSetHere = $true
}
elseif ($PromptForSecret -and -not $env:DVACCESS_CLIENT_SECRET) {
    $secure = Read-Host 'Client secret for the app registration (input hidden)' -AsSecureString
    $env:DVACCESS_CLIENT_SECRET = [System.Net.NetworkCredential]::new('', $secure).Password
    $secretSetHere = $true
}

if ($env:DVACCESS_CLIENT_SECRET) { $authMode = 'service principal' }
elseif ($cliSubscription) { $authMode = "Azure CLI account for subscription $cliSubscription" }
else { $authMode = 'default Azure CLI account' }
Write-Host "dvaccess | stage: $Stage | config: $Config | auth: $authMode" -ForegroundColor Green

# --- run ------------------------------------------------------------------------
$common = @('--config', $Config)
if ($DebugLogging) { $common += '-v' }
$runArgs = @()
if ($Run) { $runArgs = @('--run', $Run) }

function Invoke-Dvaccess([string[]] $Arguments) {
    & $dvaccess @common @Arguments
    if ($LASTEXITCODE -ne 0) { throw "dvaccess $($Arguments[0]) failed with exit code $LASTEXITCODE" }
}

try {
    switch ($Stage) {
        'pipeline' {
            Invoke-Dvaccess @('extract')
            Invoke-Dvaccess @('compile')
            $planArgs = @('plan')
            if ($DryRun) { $planArgs += '--dry-run' }
            Invoke-Dvaccess $planArgs
            Write-Host ''
            Write-Host 'Read-only pipeline complete. Review plan.json, then apply with:' -ForegroundColor Yellow
            Write-Host '  .\scripts\run-dvaccess.ps1 -Stage apply -Yes' -ForegroundColor Yellow
        }
        'extract' { Invoke-Dvaccess @('extract') }
        'compile' { Invoke-Dvaccess (@('compile') + $runArgs) }
        'plan' {
            $planArgs = @('plan') + $runArgs
            if ($DryRun) { $planArgs += '--dry-run' }
            Invoke-Dvaccess $planArgs
        }
        'apply' {
            if (-not $Yes) { throw 'apply writes roles to Fabric. Re-run with -Yes to confirm.' }
            Invoke-Dvaccess (@('apply', '--yes') + $runArgs)
        }
        'verify' { Invoke-Dvaccess (@('verify') + $runArgs) }
        'explain' {
            if (-not $User) { throw 'explain needs -User <UPN, full name, or systemuserid>.' }
            $explainArgs = @('explain', '--user', $User) + $runArgs
            if ($Table) { $explainArgs += @('--table', $Table) }
            Invoke-Dvaccess $explainArgs
        }
    }
    $latest = Get-ChildItem -Path runs -Directory -ErrorAction SilentlyContinue |
        Sort-Object Name | Select-Object -Last 1
    if ($latest) { Write-Host "Run artifacts: $($latest.FullName)" -ForegroundColor Green }
}
finally {
    if ($secretSetHere) { Remove-Item Env:DVACCESS_CLIENT_SECRET -ErrorAction SilentlyContinue }
}
