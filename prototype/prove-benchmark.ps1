param(
    [ValidateRange(1, 20)]
    [int]$Repetitions = 5
)

$ErrorActionPreference = 'Stop'

$prototypeRoot = $PSScriptRoot
$nodeExe = Join-Path $prototypeRoot '.toolchain\node-v24.19.0-win-x64\node.exe'
$snarkjsCli = Join-Path $prototypeRoot 'node_modules\snarkjs\build\cli.cjs'
$operationScript = Join-Path $prototypeRoot 'scripts\benchmark-operation.mjs'
$buildRoot = Join-Path $prototypeRoot 'build'
$provingRoot = Join-Path $buildRoot 'proving'
$setupRoot = Join-Path $provingRoot 'local-benchmark-setup'
$ptauInitial = Join-Path $setupRoot 'pot15_0000.ptau'
$ptauContributed = Join-Path $setupRoot 'pot15_0001.ptau'
$ptauFinal = Join-Path $setupRoot 'pot15_final.ptau'

foreach ($requiredPath in @($nodeExe, $snarkjsCli, $operationScript)) {
    if (-not (Test-Path -LiteralPath $requiredPath)) {
        throw "Missing toolchain component: $requiredPath. Run ./toolchain.ps1 first."
    }
}

function New-RandomEntropy {
    $bytes = New-Object byte[] 64
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($bytes)
    }
    finally {
        $rng.Dispose()
    }
    return [System.BitConverter]::ToString($bytes).Replace('-', '').ToLowerInvariant()
}

function Get-Median([double[]]$Values) {
    $ordered = @($Values | Sort-Object)
    if ($ordered.Count % 2 -eq 1) {
        return $ordered[[math]::Floor($ordered.Count / 2)]
    }
    $upper = $ordered.Count / 2
    return ($ordered[$upper - 1] + $ordered[$upper]) / 2
}

function Invoke-ProfiledNode {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,
        [Parameter(Mandatory = $true)]
        [string]$LogStem
    )

    $stdoutPath = "$LogStem.stdout.log"
    $stderrPath = "$LogStem.stderr.log"
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $process = Start-Process -FilePath $nodeExe -ArgumentList $Arguments `
        -WorkingDirectory $prototypeRoot -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath
    $process.WaitForExit()
    $stopwatch.Stop()
    $process.Refresh()

    if ($process.ExitCode -ne 0) {
        $stderr = if (Test-Path -LiteralPath $stderrPath) {
            Get-Content -Raw -LiteralPath $stderrPath
        } else { '' }
        $stdout = if (Test-Path -LiteralPath $stdoutPath) {
            Get-Content -Raw -LiteralPath $stdoutPath
        } else { '' }
        throw "Command failed with exit code $($process.ExitCode).`n$stdout`n$stderr"
    }

    return [pscustomobject]@{
        elapsedMs = [math]::Round($stopwatch.Elapsed.TotalMilliseconds, 2)
        peakWorkingSetMiB = [math]::Round($process.PeakWorkingSet64 / 1MB, 2)
    }
}

function Invoke-NodeChecked {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,
        [Parameter(Mandatory = $true)]
        [string]$LogStem
    )
    $measurement = Invoke-ProfiledNode -Arguments $Arguments -LogStem $LogStem
    Write-Host ("Completed {0}: {1} ms, peak {2} MiB" -f `
        (Split-Path -Leaf $LogStem), $measurement.elapsedMs, $measurement.peakWorkingSetMiB)
    return $measurement
}

function Invoke-ProfiledOperation {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,
        [Parameter(Mandatory = $true)]
        [string]$LogStem,
        [Parameter(Mandatory = $true)]
        [string]$MetricsPath
    )

    $stdoutPath = "$LogStem.stdout.log"
    $stderrPath = "$LogStem.stderr.log"
    $process = Start-Process -FilePath $nodeExe `
        -ArgumentList (@('--expose-gc', $operationScript) + $Arguments + @($MetricsPath)) `
        -WorkingDirectory $prototypeRoot -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath

    [long]$peakWorkingSet = 0
    while (-not $process.HasExited) {
        try {
            $process.Refresh()
            $peakWorkingSet = [math]::Max($peakWorkingSet, $process.WorkingSet64)
        }
        catch {
            # The process can exit between HasExited and Refresh.
        }
        Start-Sleep -Milliseconds 10
    }
    $process.WaitForExit()

    if ($process.ExitCode -ne 0) {
        $stderr = if (Test-Path -LiteralPath $stderrPath) {
            Get-Content -Raw -LiteralPath $stderrPath
        } else { '' }
        $stdout = if (Test-Path -LiteralPath $stdoutPath) {
            Get-Content -Raw -LiteralPath $stdoutPath
        } else { '' }
        throw "Operation failed with exit code $($process.ExitCode).`n$stdout`n$stderr"
    }

    $core = Get-Content -Raw -LiteralPath $MetricsPath | ConvertFrom-Json
    $measurement = [pscustomobject]@{
        elapsedMs = [double]$core.elapsedMs
        peakWorkingSetMiB = [math]::Round($peakWorkingSet / 1MB, 2)
        baselineRssMiB = [double]$core.baselineRssMiB
        sampledPeakRssMiB = [double]$core.sampledPeakRssMiB
    }
    Write-Host ("Measured {0}: {1} ms, peak {2} MiB" -f `
        (Split-Path -Leaf $LogStem), $measurement.elapsedMs, $measurement.peakWorkingSetMiB)
    return $measurement
}

New-Item -ItemType Directory -Force -Path $provingRoot, $setupRoot | Out-Null

Write-Warning 'LOCAL SINGLE-MACHINE CEREMONY: BENCHMARK ONLY; NEVER USE THESE KEYS IN PRODUCTION.'

if (-not (Test-Path -LiteralPath $ptauFinal)) {
    Invoke-NodeChecked -Arguments @(
        $snarkjsCli, 'powersoftau', 'new', 'bn128', '15', $ptauInitial
    ) -LogStem (Join-Path $setupRoot 'phase1-new') | Out-Null

    $phase1Entropy = New-RandomEntropy
    Invoke-NodeChecked -Arguments @(
        $snarkjsCli, 'powersoftau', 'contribute', $ptauInitial, $ptauContributed,
        '--name=BioZERO-local-benchmark-phase1', "-e=$phase1Entropy"
    ) -LogStem (Join-Path $setupRoot 'phase1-contribute') | Out-Null
    $phase1Entropy = $null

    Invoke-NodeChecked -Arguments @(
        $snarkjsCli, 'powersoftau', 'prepare', 'phase2', $ptauContributed, $ptauFinal
    ) -LogStem (Join-Path $setupRoot 'phase1-prepare-phase2') | Out-Null

    Invoke-NodeChecked -Arguments @(
        $snarkjsCli, 'powersoftau', 'verify', $ptauFinal
    ) -LogStem (Join-Path $setupRoot 'phase1-verify') | Out-Null
}

$cases = @(
    @{ Name = 'auth_distance_128'; Constraints = 7660 },
    @{ Name = 'auth_distance_512'; Constraints = 27118 }
)
$allResults = @()

foreach ($case in $cases) {
    $name = $case.Name
    $circuitRoot = Join-Path $buildRoot $name
    $r1csPath = Join-Path $circuitRoot "$name.r1cs"
    $wasmPath = Join-Path $circuitRoot "${name}_js\$name.wasm"
    $inputPath = Join-Path $prototypeRoot "inputs\generated\$name.json"
    $caseRoot = Join-Path $provingRoot $name
    $zkeyInitial = Join-Path $caseRoot "${name}_0000.zkey"
    $zkeyFinal = Join-Path $caseRoot "${name}_benchmark_final.zkey"
    $verificationKey = Join-Path $caseRoot 'verification_key.json'

    foreach ($requiredPath in @($r1csPath, $wasmPath, $inputPath)) {
        if (-not (Test-Path -LiteralPath $requiredPath)) {
            throw "Missing circuit artifact: $requiredPath. Run ./benchmark.ps1 first."
        }
    }
    New-Item -ItemType Directory -Force -Path $caseRoot | Out-Null

    if (-not (Test-Path -LiteralPath $zkeyFinal)) {
        Invoke-NodeChecked -Arguments @(
            $snarkjsCli, 'groth16', 'setup', $r1csPath, $ptauFinal, $zkeyInitial
        ) -LogStem (Join-Path $caseRoot 'phase2-setup') | Out-Null

        $phase2Entropy = New-RandomEntropy
        Invoke-NodeChecked -Arguments @(
            $snarkjsCli, 'zkey', 'contribute', $zkeyInitial, $zkeyFinal,
            "--name=BioZERO-local-benchmark-$name", "-e=$phase2Entropy"
        ) -LogStem (Join-Path $caseRoot 'phase2-contribute') | Out-Null
        $phase2Entropy = $null

        Invoke-NodeChecked -Arguments @(
            $snarkjsCli, 'zkey', 'verify', $r1csPath, $ptauFinal, $zkeyFinal
        ) -LogStem (Join-Path $caseRoot 'phase2-verify') | Out-Null

        Invoke-NodeChecked -Arguments @(
            $snarkjsCli, 'zkey', 'export', 'verificationkey', $zkeyFinal,
            $verificationKey
        ) -LogStem (Join-Path $caseRoot 'export-vkey') | Out-Null
    }

    $witnessMeasurements = @()
    $proofMeasurements = @()
    $verificationMeasurements = @()

    for ($run = 1; $run -le $Repetitions; $run++) {
        $runStem = 'run-{0:D2}' -f $run
        $witnessPath = Join-Path $caseRoot "$runStem.wtns"
        $proofPath = Join-Path $caseRoot "$runStem-proof.json"
        $publicPath = Join-Path $caseRoot "$runStem-public.json"

        $witnessMetrics = Join-Path $caseRoot "$runStem-witness-metrics.json"
        $proofMetrics = Join-Path $caseRoot "$runStem-prove-metrics.json"
        $verificationMetrics = Join-Path $caseRoot "$runStem-verify-metrics.json"

        $witnessMeasurements += Invoke-ProfiledOperation -Arguments @(
            'witness', $inputPath, $wasmPath, $witnessPath
        ) -LogStem (Join-Path $caseRoot "$runStem-witness") `
          -MetricsPath $witnessMetrics

        $proofMeasurements += Invoke-ProfiledOperation -Arguments @(
            'prove', $zkeyFinal, $witnessPath,
            $proofPath, $publicPath
        ) -LogStem (Join-Path $caseRoot "$runStem-prove") `
          -MetricsPath $proofMetrics

        $verificationMeasurements += Invoke-ProfiledOperation -Arguments @(
            'verify', $verificationKey, $publicPath,
            $proofPath
        ) -LogStem (Join-Path $caseRoot "$runStem-verify") `
          -MetricsPath $verificationMetrics
    }

    $sampleProof = Join-Path $caseRoot 'run-01-proof.json'
    $samplePublic = Join-Path $caseRoot 'run-01-public.json'
    $allResults += [pscustomobject]@{
        circuit = $name
        constraints = $case.Constraints
        publicInputs = 5
        repetitions = $Repetitions
        witness = [pscustomobject]@{
            elapsedMs = @($witnessMeasurements.elapsedMs)
            medianElapsedMs = [math]::Round((Get-Median $witnessMeasurements.elapsedMs), 2)
            peakWorkingSetMiB = @($witnessMeasurements.peakWorkingSetMiB)
            medianPeakWorkingSetMiB = [math]::Round((Get-Median $witnessMeasurements.peakWorkingSetMiB), 2)
            baselineRssMiB = @($witnessMeasurements.baselineRssMiB)
        }
        proof = [pscustomobject]@{
            elapsedMs = @($proofMeasurements.elapsedMs)
            medianElapsedMs = [math]::Round((Get-Median $proofMeasurements.elapsedMs), 2)
            peakWorkingSetMiB = @($proofMeasurements.peakWorkingSetMiB)
            medianPeakWorkingSetMiB = [math]::Round((Get-Median $proofMeasurements.peakWorkingSetMiB), 2)
            baselineRssMiB = @($proofMeasurements.baselineRssMiB)
            canonicalUncompressedBytes = 256
            jsonBytes = (Get-Item -LiteralPath $sampleProof).Length
        }
        verification = [pscustomobject]@{
            elapsedMs = @($verificationMeasurements.elapsedMs)
            medianElapsedMs = [math]::Round((Get-Median $verificationMeasurements.elapsedMs), 2)
            peakWorkingSetMiB = @($verificationMeasurements.peakWorkingSetMiB)
            medianPeakWorkingSetMiB = [math]::Round((Get-Median $verificationMeasurements.peakWorkingSetMiB), 2)
            baselineRssMiB = @($verificationMeasurements.baselineRssMiB)
        }
        artifacts = [pscustomobject]@{
            provingKeyBytes = (Get-Item -LiteralPath $zkeyFinal).Length
            verificationKeyJsonBytes = (Get-Item -LiteralPath $verificationKey).Length
            publicSignalsJsonBytes = (Get-Item -LiteralPath $samplePublic).Length
        }
    }
}

$cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
$os = Get-CimInstance Win32_OperatingSystem
$record = [pscustomobject]@{
    generatedAt = (Get-Date).ToString('o')
    warning = 'Local single-machine phase-1 and phase-2 contributions; benchmark only; never use these keys in production.'
    setup = [pscustomobject]@{
        curve = 'bn128'
        power = 15
        maxConstraints = 32768
        transcriptVerified = $true
        productionCeremony = $false
    }
    host = [pscustomobject]@{
        os = $os.Caption
        cpu = $cpu.Name
        logicalProcessors = $cpu.NumberOfLogicalProcessors
        totalMemoryGiB = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
        node = (& $nodeExe --version)
        snarkjs = '0.7.6'
    }
    results = $allResults
}

$resultsPath = Join-Path $provingRoot 'results.json'
$record | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $resultsPath -Encoding utf8
Write-Output "Proving benchmark results written to $resultsPath"
