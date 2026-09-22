<#
.SYNOPSIS
Run an explicit Policy Weaver operation with live terminal output and saved logs.
.EXAMPLE
.\scripts\Run-PolicyWeaver.ps1 -Operation Prepare
.EXAMPLE
.\scripts\Run-PolicyWeaver.ps1 -Operation Status
.EXAMPLE
.\scripts\Run-PolicyWeaver.ps1 -Operation Withdraw -Config .\manual-demo.config.json
.NOTES
Prepare is the default. No automatic publication, role removal, or watchdog run.
Withdraw explicitly removes this deployment's owned roles. Retention mode is
selected in configuration before preparation, never by editing a prepared run.
Publish requires a fresh inspected boundary and a prepared generation. Existing
synthetic demo schemas/policies must be reconciled before publishing to that item.
#>
[CmdletBinding()]
param(
    [ValidateSet('Prepare', 'Doctor', 'Status', 'DryRun', 'Publish', 'BoundaryTemplate', 'Withdraw')]
    [string]$Operation = 'Prepare',
    [string]$Config,
    [long]$Generation,
    [string]$Boundary,
    [string]$PythonPath,
    [string]$LogDirectory,
    [switch]$Preview
)

$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
if (-not $Config) { $Config = Join-Path $repositoryRoot 'policyweaver.config.json' }
if (-not $PythonPath) {
    $candidatePaths = @(
        (Join-Path $repositoryRoot '.venv/Scripts/python.exe'),
        (Join-Path $repositoryRoot '.venv/bin/python'),
        (Join-Path $repositoryRoot '.venv-x64/Scripts/python.exe')
    )
    $PythonPath = $candidatePaths | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
}
if (-not $PythonPath) { throw 'Run python scripts/bootstrap_policyweaver.py first, or supply -PythonPath.' }
if (-not (Test-Path -LiteralPath $PythonPath -PathType Leaf)) {
    throw 'Python was not found. Supply -PythonPath for the virtual environment with Policy Weaver installed.'
}
$operationNames = @{
    Prepare = 'prepare'; Doctor = 'doctor'; Status = 'status'; DryRun = 'dry-run'
    Publish = 'publish'; BoundaryTemplate = 'boundary-template'; Withdraw = 'withdraw'
}
$terminalArguments = @('-u', (Join-Path $PSScriptRoot 'run_adapter_terminal.py'),
    '--operation', $operationNames[$Operation], '--config', $Config)
if ($PSBoundParameters.ContainsKey('Generation')) { $terminalArguments += @('--generation', "$Generation") }
if ($Boundary) { $terminalArguments += @('--boundary', $Boundary) }
if ($LogDirectory) { $terminalArguments += @('--log-directory', $LogDirectory) }
if ($Preview) { $terminalArguments += '--preview' }
& $PythonPath @terminalArguments
exit $LASTEXITCODE
