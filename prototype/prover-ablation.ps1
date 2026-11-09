param(
    [ValidateRange(1, 20)]
    [int]$ColdRepetitions = 5,
    [ValidateRange(2, 20)]
    [int]$WarmRepetitions = 6
)

$ErrorActionPreference = 'Stop'

$prototypeRoot = $PSScriptRoot
$nodeExe = Join-Path $prototypeRoot '.toolchain\node-v24.19.0-win-x64\node.exe'
$snarkjsCli = Join-Path $prototypeRoot 'node_modules\snarkjs\build\cli.cjs'
$operationScript = Join-Path $prototypeRoot 'scripts\prover-ablation-operation.mjs'
$provingResultsPath = Join-Path $prototypeRoot 'build\proving\results.json'
$outputRoot = Join-Path $prototypeRoot 'build\prover-ablation'

foreach ($requiredPath in @($nodeExe, $snarkjsCli, $operationScript, $provingResultsPath)) {
    if (-not (Test-Path -LiteralPath $requiredPath)) {
        throw "Missing required artifact: $requiredPath"
    }
}

function Get-Median([double[]]$Values) {
    $ordered = @($Values | Sort-Object)
    if ($ordered.Count % 2 -eq 1) {
        return $ordered[[math]::Floor($ordered.Count / 2)]
    }
    $upper = $ordered.Count / 2
    return ($ordered[$upper - 1] + $ordered[$upper]) / 2
}

function Invoke-ProfiledAblation {
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
        -ArgumentList (@('--expose-gc', $operationScript) + $Arguments) `
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
        Start-Sleep -Milliseconds 5
    }
    $process.WaitForExit()

    if ($process.ExitCode -ne 0) {
        $stderr = if (Test-Path -LiteralPath $stderrPath) {
            Get-Content -Raw -LiteralPath $stderrPath
        } else { '' }
        $stdout = if (Test-Path -LiteralPath $stdoutPath) {
            Get-Content -Raw -LiteralPath $stdoutPath
        } else { '' }
        throw "Ablation operation failed with exit code $($process.ExitCode).`n$stdout`n$stderr"
    }

    $metrics = Get-Content -Raw -LiteralPath $MetricsPath | ConvertFrom-Json
    $metrics | Add-Member -NotePropertyName externalPeakWorkingSetMiB `
        -NotePropertyValue ([math]::Round($peakWorkingSet / 1MB, 2))
    return $metrics
}

function Test-Proof {
    param(
        [Parameter(Mandatory = $true)][string]$VerificationKey,
        [Parameter(Mandatory = $true)][string]$PublicPath,
        [Parameter(Mandatory = $true)][string]$ProofPath,
        [Parameter(Mandatory = $true)][string]$LogStem
    )
    $stdoutPath = "$LogStem.stdout.log"
    $stderrPath = "$LogStem.stderr.log"
    $process = Start-Process -FilePath $nodeExe -ArgumentList @(
        $snarkjsCli, 'groth16', 'verify', $VerificationKey, $PublicPath, $ProofPath
    ) -WorkingDirectory $prototypeRoot -WindowStyle Hidden -PassThru -Wait `
      -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath
    if ($process.ExitCode -ne 0) {
        throw "Generated proof failed verification: $(Get-Content -Raw $stderrPath)"
    }
}

New-Item -ItemType Directory -Force -Path $outputRoot | Out-Null
$existing = Get-Content -Raw -LiteralPath $provingResultsPath | ConvertFrom-Json
$cases = @('auth_distance_128', 'auth_distance_512')
$allResults = @()

foreach ($name in $cases) {
    $caseRoot = Join-Path $prototypeRoot "build\proving\$name"
    $zkeyPath = Join-Path $caseRoot "${name}_benchmark_final.zkey"
    $witnessPath = Join-Path $caseRoot 'run-01.wtns'
    $verificationKey = Join-Path $caseRoot 'verification_key.json'
    $caseOutput = Join-Path $outputRoot $name
    New-Item -ItemType Directory -Force -Path $caseOutput | Out-Null

    foreach ($requiredPath in @($zkeyPath, $witnessPath, $verificationKey)) {
        if (-not (Test-Path -LiteralPath $requiredPath)) {
            throw "Missing proving artifact: $requiredPath"
        }
    }

    $coldSingleRuns = @()
    for ($run = 1; $run -le $ColdRepetitions; $run++) {
        $stem = Join-Path $caseOutput ('cold-single-{0:D2}' -f $run)
        $metricsPath = "$stem.metrics.json"
        $proofPath = "$stem.proof.json"
        $publicPath = "$stem.public.json"
        $measurement = Invoke-ProfiledAblation -Arguments @(
            'cold-single', $zkeyPath, $witnessPath, '1',
            $metricsPath, $proofPath, $publicPath
        ) -LogStem $stem -MetricsPath $metricsPath
        $coldSingleRuns += $measurement
        Write-Host ("{0} cold single {1}: {2} ms, peak {3} MiB" -f `
            $name, $run, $measurement.runs[0].elapsedMs,
            $measurement.externalPeakWorkingSetMiB)
    }
    Test-Proof -VerificationKey $verificationKey `
        -PublicPath (Join-Path $caseOutput ('cold-single-{0:D2}.public.json' -f $ColdRepetitions)) `
        -ProofPath (Join-Path $caseOutput ('cold-single-{0:D2}.proof.json' -f $ColdRepetitions)) `
        -LogStem (Join-Path $caseOutput 'verify-cold-single')

    $additionalWorkerRows = @()
    foreach ($workerCount in @(2, 4, 8)) {
        $workerRuns = @()
        for ($run = 1; $run -le $ColdRepetitions; $run++) {
            $stem = Join-Path $caseOutput ('cold-workers-{0}-{1:D2}' -f $workerCount, $run)
            $metricsPath = "$stem.metrics.json"
            $proofPath = "$stem.proof.json"
            $publicPath = "$stem.public.json"
            $measurement = Invoke-ProfiledAblation -Arguments @(
                "cold-workers-$workerCount", $zkeyPath, $witnessPath, '1',
                $metricsPath, $proofPath, $publicPath
            ) -LogStem $stem -MetricsPath $metricsPath
            if ($measurement.workerConcurrency -ne $workerCount) {
                throw "Requested $workerCount workers but ffjavascript created $($measurement.workerConcurrency)"
            }
            $workerRuns += $measurement
            Write-Host ("{0} cold workers={1} run {2}: {3} ms, peak {4} MiB" -f `
                $name, $workerCount, $run, $measurement.runs[0].elapsedMs,
                $measurement.externalPeakWorkingSetMiB)
        }
        Test-Proof -VerificationKey $verificationKey `
            -PublicPath (Join-Path $caseOutput ('cold-workers-{0}-{1:D2}.public.json' -f $workerCount, $ColdRepetitions)) `
            -ProofPath (Join-Path $caseOutput ('cold-workers-{0}-{1:D2}.proof.json' -f $workerCount, $ColdRepetitions)) `
            -LogStem (Join-Path $caseOutput "verify-cold-workers-$workerCount")
        [double[]]$workerElapsed = @($workerRuns | ForEach-Object { $_.runs[0].elapsedMs })
        [double[]]$workerPeak = @($workerRuns | ForEach-Object { $_.externalPeakWorkingSetMiB })
        $additionalWorkerRows += [pscustomobject]@{
            workerConcurrency = $workerCount
            repetitions = $ColdRepetitions
            elapsedMs = $workerElapsed
            medianElapsedMs = [math]::Round((Get-Median $workerElapsed), 2)
            peakWorkingSetMiB = $workerPeak
            medianPeakWorkingSetMiB = [math]::Round((Get-Median $workerPeak), 2)
            representativeProofVerified = $true
            workerLimitMethod = 'os.cpus() limited before importing snarkjs/ffjavascript in an isolated process'
        }
    }

    $warmStem = Join-Path $caseOutput 'warm-multi'
    $warmMetricsPath = "$warmStem.metrics.json"
    $warmProofPath = "$warmStem.proof.json"
    $warmPublicPath = "$warmStem.public.json"
    $warm = Invoke-ProfiledAblation -Arguments @(
        'warm-multi', $zkeyPath, $witnessPath, $WarmRepetitions,
        $warmMetricsPath, $warmProofPath, $warmPublicPath
    ) -LogStem $warmStem -MetricsPath $warmMetricsPath
    Test-Proof -VerificationKey $verificationKey -PublicPath $warmPublicPath `
        -ProofPath $warmProofPath -LogStem (Join-Path $caseOutput 'verify-warm-multi')

    $coldDefault = $existing.results | Where-Object { $_.circuit -eq $name }
    if (-not $coldDefault) {
        throw "Missing cold default result for $name"
    }

    [double[]]$singleElapsed = @($coldSingleRuns | ForEach-Object { $_.runs[0].elapsedMs })
    [double[]]$singlePeak = @($coldSingleRuns | ForEach-Object { $_.externalPeakWorkingSetMiB })
    [double[]]$warmSteadyElapsed = @($warm.runs | Select-Object -Skip 1 | ForEach-Object { $_.elapsedMs })
    [double[]]$warmSteadyPeak = @($warm.runs | Select-Object -Skip 1 | ForEach-Object { $_.sampledPeakRssMiB })

    $coldDefaultTime = [double]$coldDefault.proof.medianElapsedMs
    $coldDefaultPeak = [double]$coldDefault.proof.medianPeakWorkingSetMiB
    $coldSingleTime = Get-Median $singleElapsed
    $coldSinglePeak = Get-Median $singlePeak
    $warmSteadyTime = Get-Median $warmSteadyElapsed
    $warmSteadyPeakMedian = Get-Median $warmSteadyPeak
    $coldWorkerGrid = @(
        [pscustomobject]@{
            workerConcurrency = 1
            repetitions = $ColdRepetitions
            elapsedMs = $singleElapsed
            medianElapsedMs = [math]::Round($coldSingleTime, 2)
            peakWorkingSetMiB = $singlePeak
            medianPeakWorkingSetMiB = [math]::Round($coldSinglePeak, 2)
            representativeProofVerified = $true
            workerLimitMethod = 'snarkjs singleThread=true'
        }
    )
    $coldWorkerGrid += $additionalWorkerRows
    $coldWorkerGrid += [pscustomobject]@{
        workerConcurrency = [int]$existing.host.logicalProcessors
        repetitions = $coldDefault.proof.elapsedMs.Count
        elapsedMs = $coldDefault.proof.elapsedMs
        medianElapsedMs = $coldDefaultTime
        peakWorkingSetMiB = $coldDefault.proof.peakWorkingSetMiB
        medianPeakWorkingSetMiB = $coldDefaultPeak
        representativeProofVerified = $true
        workerLimitMethod = 'snarkjs/ffjavascript default'
    }

    $allResults += [pscustomobject]@{
        circuit = $name
        coldDefaultMulti = [pscustomobject]@{
            workerConcurrency = $existing.host.logicalProcessors
            repetitions = $coldDefault.proof.elapsedMs.Count
            medianElapsedMs = $coldDefaultTime
            medianPeakWorkingSetMiB = $coldDefaultPeak
            source = 'build/proving/results.json'
        }
        coldSingleThread = [pscustomobject]@{
            workerConcurrency = 1
            repetitions = $ColdRepetitions
            elapsedMs = $singleElapsed
            medianElapsedMs = [math]::Round($coldSingleTime, 2)
            peakWorkingSetMiB = $singlePeak
            medianPeakWorkingSetMiB = [math]::Round($coldSinglePeak, 2)
            proofVerified = $true
        }
        coldWorkerGrid = $coldWorkerGrid
        warmDefaultMulti = [pscustomobject]@{
            workerConcurrency = $warm.workerConcurrency
            repetitions = $WarmRepetitions
            firstElapsedMs = $warm.runs[0].elapsedMs
            steadyElapsedMs = $warmSteadyElapsed
            medianSteadyElapsedMs = [math]::Round($warmSteadyTime, 2)
            steadySampledPeakRssMiB = $warmSteadyPeak
            medianSteadySampledPeakRssMiB = [math]::Round($warmSteadyPeakMedian, 2)
            processPeakWorkingSetMiB = $warm.externalPeakWorkingSetMiB
            perRun = $warm.runs
            proofVerified = $true
        }
        comparisons = [pscustomobject]@{
            singleThreadMemoryReductionPercent = [math]::Round(
                100 * (1 - $coldSinglePeak / $coldDefaultPeak), 2)
            singleThreadTimeMultiplier = [math]::Round(
                $coldSingleTime / $coldDefaultTime, 2)
            warmSteadySpeedupOverColdDefault = [math]::Round(
                $coldDefaultTime / $warmSteadyTime, 2)
        }
    }
}

$rapidSnark = Get-Command rapidsnark -ErrorAction SilentlyContinue
$record = [pscustomobject]@{
    generatedAt = (Get-Date).ToString('o')
    scope = 'Groth16 prove-only ablation using an existing witness and proving key.'
    host = $existing.host
    modes = [pscustomobject]@{
        coldDefaultMulti = 'One proof per Node process; snarkjs default worker count.'
        coldSingleThread = 'One proof per Node process; snarkjs prover option singleThread=true.'
        warmDefaultMulti = 'Repeated proofs in one Node process; run 1 initializes the cached curve/workers and runs 2..N are steady-state.'
    }
    nativeBackend = [pscustomobject]@{
        rapidsnarkAvailable = [bool]$rapidSnark
        measured = [bool]$rapidSnark
        note = if ($rapidSnark) {
            'rapidsnark is available but requires a separate benchmark implementation.'
        } else {
            'No rapidsnark executable or local C/C++ build toolchain; WSL is present without an installed Linux distribution. No native number is estimated.'
        }
    }
    results = $allResults
}

$resultsPath = Join-Path $outputRoot 'results.json'
$record | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $resultsPath -Encoding utf8
Write-Output "Prover ablation results written to $resultsPath"
