$ErrorActionPreference = 'Stop'

$prototypeRoot = $PSScriptRoot
$nodeExe = Join-Path $prototypeRoot '.toolchain\node-v24.19.0-win-x64\node.exe'
$circomExe = Join-Path $prototypeRoot '.toolchain\circom\circom.exe'
$snarkjsCli = Join-Path $prototypeRoot 'node_modules\snarkjs\build\cli.cjs'
$buildRoot = Join-Path $prototypeRoot 'build'
$generatedInputRoot = Join-Path $prototypeRoot 'inputs\generated'

foreach ($requiredPath in @($nodeExe, $circomExe, $snarkjsCli)) {
    if (-not (Test-Path -LiteralPath $requiredPath)) {
        throw "Missing toolchain component: $requiredPath. Run ./toolchain.ps1 first."
    }
}

New-Item -ItemType Directory -Force -Path $buildRoot, $generatedInputRoot | Out-Null

Push-Location $prototypeRoot
try {
    & $nodeExe --test test/commitment.test.mjs
    if ($LASTEXITCODE -ne 0) { throw 'Commitment tests failed.' }

    & $nodeExe scripts/generate-inputs.mjs
    if ($LASTEXITCODE -ne 0) { throw 'Input generation failed.' }

    $benchmarkCases = @(
        @{ Name = 'distance_only_128'; Input = 'distance_only_128.json' },
        @{ Name = 'auth_distance_128_unpacked'; Input = 'auth_distance_128_unpacked.json' },
        @{ Name = 'auth_distance_128'; Input = 'auth_distance_128.json' },
        @{ Name = 'distance_only_512'; Input = 'distance_only_512.json' },
        @{ Name = 'auth_distance_512_unpacked'; Input = 'auth_distance_512_unpacked.json' },
        @{ Name = 'auth_distance_512'; Input = 'auth_distance_512.json' }
    )

    foreach ($benchmarkCase in $benchmarkCases) {
        $circuitName = $benchmarkCase.Name
        $circuitPath = Join-Path $prototypeRoot "circuits\$circuitName.circom"
        $circuitBuildRoot = Join-Path $buildRoot $circuitName
        New-Item -ItemType Directory -Force -Path $circuitBuildRoot | Out-Null

        & $circomExe $circuitPath --r1cs --wasm --sym --inspect --O2 `
            -l (Join-Path $prototypeRoot 'node_modules') -o $circuitBuildRoot
        if ($LASTEXITCODE -ne 0) { throw "Circom compilation failed for $circuitName." }

        $r1csPath = Join-Path $circuitBuildRoot "$circuitName.r1cs"
        $infoPath = Join-Path $circuitBuildRoot 'r1cs-info.txt'
        & $nodeExe $snarkjsCli r1cs info $r1csPath | Tee-Object -FilePath $infoPath
        if ($LASTEXITCODE -ne 0) { throw "R1CS inspection failed for $circuitName." }

        $wasmPath = Join-Path $circuitBuildRoot "${circuitName}_js\$circuitName.wasm"
        $inputPath = Join-Path $generatedInputRoot $benchmarkCase.Input
        $witnessPath = Join-Path $circuitBuildRoot "$circuitName.wtns"

        & $nodeExe $snarkjsCli wtns calculate $wasmPath $inputPath $witnessPath
        if ($LASTEXITCODE -ne 0) { throw "Witness generation failed for $circuitName." }

        & $nodeExe $snarkjsCli wtns check $r1csPath $witnessPath
        if ($LASTEXITCODE -ne 0) { throw "Witness check failed for $circuitName." }
    }

    $negativeCircuitRoot = Join-Path $buildRoot 'auth_distance_128'
    $negativeR1cs = Join-Path $negativeCircuitRoot 'auth_distance_128.r1cs'
    $negativeWasm = Join-Path $negativeCircuitRoot 'auth_distance_128_js\auth_distance_128.wasm'
    foreach ($negativeName in @('context_mismatch', 'threshold_fail', 'coordinate_out_of_range')) {
        $negativeInput = Join-Path $generatedInputRoot "$negativeName.json"
        $negativeWitness = Join-Path $negativeCircuitRoot "$negativeName.wtns"
        $negativeLog = Join-Path $negativeCircuitRoot "$negativeName.log"
        & $nodeExe $snarkjsCli wtns calculate $negativeWasm $negativeInput $negativeWitness `
            *> $negativeLog
        if ($LASTEXITCODE -eq 0) {
            throw "Invalid witness unexpectedly succeeded: $negativeName"
        }
        Write-Output "Expected rejection confirmed: $negativeName"
    }
}
finally {
    Pop-Location
}

Write-Output "Benchmark artifacts written to $buildRoot"
