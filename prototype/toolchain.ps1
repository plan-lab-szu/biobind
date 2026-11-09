$ErrorActionPreference = 'Stop'

$prototypeRoot = $PSScriptRoot
$toolchainRoot = Join-Path $prototypeRoot '.toolchain'
$downloadRoot = Join-Path $toolchainRoot 'downloads'
$nodeVersion = '24.19.0'
$nodeArchiveName = "node-v$nodeVersion-win-x64.zip"
$nodeArchive = Join-Path $downloadRoot $nodeArchiveName
$nodeRoot = Join-Path $toolchainRoot "node-v$nodeVersion-win-x64"
$circomVersion = '2.2.3'
$circomRoot = Join-Path $toolchainRoot 'circom'
$circomExe = Join-Path $circomRoot 'circom.exe'

$expectedNodeSha256 = '57f71ab3652e797d84acddc79c81cc9ff1c6ddb2a1974cdb83f00fee9bff4c73'
$expectedCircomSha256 = 'e43f132ee6f0aa79b705beceb59c2a7e6a54d7bdeab917ca34e9fc1951d185e1'

New-Item -ItemType Directory -Force -Path $downloadRoot, $circomRoot | Out-Null

if (-not (Test-Path -LiteralPath $nodeArchive)) {
    $nodeUrl = "https://nodejs.org/dist/v$nodeVersion/$nodeArchiveName"
    Invoke-WebRequest -Uri $nodeUrl -OutFile $nodeArchive
}

$nodeDigest = (Get-FileHash -Algorithm SHA256 -LiteralPath $nodeArchive).Hash.ToLowerInvariant()
if ($nodeDigest -ne $expectedNodeSha256) {
    throw "Node.js archive digest mismatch: $nodeDigest"
}

if (-not (Test-Path -LiteralPath $nodeRoot)) {
    Expand-Archive -LiteralPath $nodeArchive -DestinationPath $toolchainRoot
}

if (-not (Test-Path -LiteralPath $circomExe)) {
    $circomUrl = "https://github.com/iden3/circom/releases/download/v$circomVersion/circom-windows-amd64.exe"
    Invoke-WebRequest -Uri $circomUrl -OutFile $circomExe
}

$circomDigest = (Get-FileHash -Algorithm SHA256 -LiteralPath $circomExe).Hash.ToLowerInvariant()
if ($circomDigest -ne $expectedCircomSha256) {
    throw "Circom executable digest mismatch: $circomDigest"
}

$nodeExe = Join-Path $nodeRoot 'node.exe'
$npmCli = Join-Path $nodeRoot 'node_modules\npm\bin\npm-cli.js'

if (-not (Test-Path -LiteralPath $nodeExe) -or -not (Test-Path -LiteralPath $npmCli)) {
    throw 'Pinned Node.js toolchain is incomplete.'
}

Push-Location $prototypeRoot
try {
    & $nodeExe $npmCli install --ignore-scripts --no-audit --no-fund
    if ($LASTEXITCODE -ne 0) {
        throw "npm install failed with exit code $LASTEXITCODE"
    }
}
finally {
    Pop-Location
}

& $nodeExe --version
& $circomExe --version
Write-Output "Toolchain ready at $toolchainRoot"

