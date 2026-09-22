[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$SignKeyPath,
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '../../dist/read-context')
)

$ErrorActionPreference = 'Stop'
$resolvedKey = (Resolve-Path -LiteralPath $SignKeyPath).Path
if ([System.IO.Path]::GetExtension($resolvedKey) -ne '.snk') {
    throw 'SignKeyPath must identify a private strong-name .snk file.'
}
$testProject = Join-Path $PSScriptRoot 'tests/PolicyWeaver.ReadContext.Tests.csproj'
& dotnet restore $testProject --locked-mode "-p:SignKeyPath=$resolvedKey" --nologo
if ($LASTEXITCODE -ne 0) { throw 'Locked dependency restore failed.' }
& dotnet build $testProject --no-restore -c Release "-p:SignKeyPath=$resolvedKey" --nologo
if ($LASTEXITCODE -ne 0) { throw 'Plugin compilation failed.' }
& (Join-Path $PSScriptRoot 'tests/bin/Release/net462/PolicyWeaver.ReadContext.Tests.exe')
if ($LASTEXITCODE -ne 0) { throw 'Local plugin qualification failed.' }

$assemblyPath = Join-Path $PSScriptRoot 'bin/Release/net462/PolicyWeaver.ReadContext.dll'
$identity = [System.Reflection.AssemblyName]::GetAssemblyName($assemblyPath)
$token = -join ($identity.GetPublicKeyToken() | ForEach-Object { $_.ToString('x2') })
if ($token.Length -ne 16) { throw 'Plugin assembly must have a strong-name public key token.' }
$artifactDirectory = [System.IO.Path]::GetFullPath($OutputDirectory)
[System.IO.Directory]::CreateDirectory($artifactDirectory) | Out-Null
$artifactPath = Join-Path $artifactDirectory 'PolicyWeaver.ReadContext.dll'
Copy-Item -LiteralPath $assemblyPath -Destination $artifactPath -Force
$artifactHash = (Get-FileHash -LiteralPath $artifactPath -Algorithm SHA256).Hash.ToLowerInvariant()
$manifest = [ordered]@{
    schema_version = 1
    file = 'PolicyWeaver.ReadContext.dll'
    assembly_name = $identity.Name
    assembly_version = $identity.Version.ToString()
    assembly_culture = 'neutral'
    public_key_token = $token
    sha256 = $artifactHash
    type_name = 'PolicyWeaver.ReadContext.ReadContextPlugin'
    protocol_version = '1'
    custom_api_name = 'pw_ReadContext'
    target_framework = 'net462'
    sdk_package_version = '9.0.2.60'
    live_qualified = $false
}
$manifestJson = $manifest | ConvertTo-Json
[System.IO.File]::WriteAllText((Join-Path $artifactDirectory 'manifest.json'), $manifestJson + "`n", (New-Object System.Text.UTF8Encoding($false)))
Write-Output ('Artifact SHA256: ' + $artifactHash)
Write-Output ('Public key token: ' + $token)
Write-Output 'Local build and tests passed. Deployment and live identity qualification remain separate.'
