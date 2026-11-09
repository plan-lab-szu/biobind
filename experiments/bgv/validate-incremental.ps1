param(
    [Parameter(Mandatory=$true)][string]$Exe,
    [Parameter(Mandatory=$true)][string]$ScratchRoot,
    [switch]$FullCapacity,
    [int]$Repetitions = 3
)
$ErrorActionPreference = 'Stop'
if ($Repetitions -lt 1) { throw 'Repetitions must be positive' }
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$resultRoot = Join-Path $PSScriptRoot "../results/bgv-incremental-$stamp"
foreach ($profile in @('FaceNet-3', 'MobileFaceNet-2')) {
    $limit = 64
    if ($FullCapacity) {
        if ($profile -eq 'FaceNet-3') { $limit = 24576 } else { $limit = 16384 }
    }
    for ($rep = 1; $rep -le $Repetitions; $rep++) {
        $name = "$profile-r$rep"
        & python (Join-Path $PSScriptRoot 'run.py') --exe $Exe --mode stress `
            --profile $profile --parameter-set incremental-candidate --max-enrollments $limit `
            --out (Join-Path $resultRoot $name) `
            --binary-dir (Join-Path $ScratchRoot "$stamp/$name")
        if ($LASTEXITCODE -ne 0) { throw "Validation failed for $name; raw evidence retained" }
    }
}
Write-Output "Completed requested scope. FullCapacity=$FullCapacity. Results: $resultRoot"
