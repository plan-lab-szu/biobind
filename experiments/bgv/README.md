# Real BGV enrollment and merge component experiment

**2026-10-30 r3 update:** parameter diagnosis and repair regression are now active. The v2 execution block below is historical: the substantively revised r3 diagnostic built and ran normally, without changing security settings. See `../../notes/bgv-repair-20261030-r3.md` for measured outcomes and remaining full-capacity validation.

This experiment is independent of the transparent-ciphertext JavaScript pipeline. It does not run BioZKFHE's block proofs (PVSC), threshold decryption, ES signatures, capture hardware, or a blockchain.

## Source and build identity

- BioZKFHE E3 parameter/layout source: commit `76ffb9f1885a2cbdef3f34c73971fc262db1bd60`, `source/biozkFHE/scmv_e3_benchmark.cpp`, copied byte-for-byte to `vendor/`.
- Official Microsoft SEAL **4.1.2**, tag commit `119dc32e135cb89c1062076a69310d4413ebc824`. The bundled author fork failed to build (unfinished encryption/decryption modifications); no archive files were patched.
- Zstandard **1.5.7**, commit `f8745da6ff1ad1e7bab384bd1f9d742439278e99`; zlib and MSGSL disabled. Default SEAL compression is Zstandard, also measured against `none`.
- Windows 11, Intel Core i9-9900T, w64devkit **2.11.0**, GCC **16.2.0**, Release/O3, default SEAL binomial noise, Blake2xb PRNG, OS randomness, `tc128` enforced. Timings are single-process component measurements.
- `SEAL_USE_ALIGNED_ALLOC=OFF` is required by this MinGW runtime. `seal-mingw-build.patch` changes archive packaging only: the driver links the separate Zstandard archive and Windows `bcrypt`. No cryptographic algorithm was patched.
- `source-measure-v1/` preserves the exact C++/CMake/driver bytes matched to the pre-run manifests for the executed first binary. The unmodified vendor source is shared at `vendor/`. Later `bgv-measure.cpp` adds a coefficient-modulus diagnostic override; this second binary was **blocked by Windows Code Integrity (4551/3077)** before execution. No adjusted-parameter result exists. System security settings were not changed.

The locally retained tools and full ciphertext buffers are in `%LOCALAPPDATA%/BioBindResearchTools`. Portable summaries, raw samples, parameters and hashes are under `../results/`. Do not confuse those ciphertext files with installed deployment keys: no secret or public encryption key is exported.

## Build

Use fixed versions above. On MinGW, apply the supplied packaging patch to a new official SEAL checkout, then:

```powershell
cmake -S $SealSource -B $SealBuild -G Ninja -DCMAKE_BUILD_TYPE=Release -DSEAL_USE_MSGSL=OFF -DSEAL_USE_ZLIB=OFF -DSEAL_USE_ZSTD=ON "-DFETCHCONTENT_SOURCE_DIR_ZSTD=$ZstdSource" -DSEAL_USE_ALIGNED_ALLOC=OFF '-DCMAKE_POLICY_VERSION_MINIMUM=3.5'
cmake --build $SealBuild -j 8
cmake -S experiments/bgv -B $DriverBuild -G Ninja -DCMAKE_BUILD_TYPE=Release "-DSEAL_DIR=$SealBuild/cmake" "-DBIOBIND_ZSTD_LIBRARY=$SealBuild/lib/libzstd.a"
cmake --build $DriverBuild -j 4
```

On other platforms use SEAL's normal supported build and omit the MinGW packaging patch/bcrypt-specific option. To reproduce the exact executed v1 driver, put `source-measure-v1/bgv-measure.cpp` and its CMakeLists in a temporary build source directory alongside a copy of `vendor/`. New outputs must use unused paths.

```powershell
python experiments/bgv/run.py --exe $DriverExe --out $NewResultDir --binary-dir $NewLargeBufferDir
python experiments/bgv/run.py --exe $DriverExe --mode stress --profile FaceNet-3 --out $NewStressResult --binary-dir $NewStressScratch
```

`--source-dir` selects the matching C++ snapshot when using the v1 executable. Do not use the new `--coeff-bits` option with a v1 executable. Failed runs and new parameter profiles must be kept separate from the original E3 measurements.

## Measurement design

Five original E3 profiles, degree 8192; FaceNet L=128/Gamma=128/n=1,2,3; MobileFaceNet L=512/Gamma=512/n=1,2. These are **not** the LFW authentication profile L=512/Gamma=2047. Each parameter file contains the actual prime values, key/data parameter IDs, SEAL version and security level. SEAL removes the special last modulus from the data level, leaving three RNS limbs in all five profiles.

For each profile, generate a random-normalized synthetic query and a complete tail gallery with the final slot empty. Encrypt the tail once. One warmup and five measured rounds each freshly encrypt the query and the last-slot enrollment (public-key encryption, fresh OS entropy). Separate timers cover matrix construction, encoding, encryption, serialization, loading two inputs, L additions, saving the result, and encrypted query evaluation. Check all 8192 batch slots, including every packed layer, against plaintext scores. A second context independently loads both frames and recomputes the merge; its serialized result must be byte-identical. It is a second computation in the same process, not a cross-machine determinism test.

Hashing is real Keccak-256 via Python PyCryptodome, one warmup plus five measurements for each representative tail/enrollment/merged frame; disk reads are excluded. The sum of the three separately reported medians is a component-cost summary, not an end-to-end transaction latency. Key generation, capture, networking, signatures, chain processing and extraction are excluded.

Frame v1: 8 ASCII bytes `BGBGV001`; little-endian uint64 d,n,L,T; then L rows, each with a uint64 byte length and the actual output of `Ciphertext::save`. Thus framing overhead is `40+8L` bytes. All measured ciphertexts are size 2, first data level, NTT form, correction factor 1. A deployment also needs authenticated parameter/public-key identities, allowed representations and version rules; this frame is an experiment specification, not a newly deployed source-contract ABI. Sizes are measured bytes, not `save_size` bounds.

## Cumulative correctness stress

Start with an actual encrypted single enrollment. For each new registration, freshly encrypt all L sparse rows and add them to the existing block. Evaluate the full encrypted query (L ciphertext products and L-1 sums) at counts 1,2,4,... and layer/capacity boundaries. Check all slots/layers and record minimum row noise and query noise. Stop at the first observed decoding failure. Axis vectors at boundaries respect the admissible normalized-domain bound. No fresh encryption of an already full gallery is substituted for accumulated ciphertexts.

This is a finite diagnostic under one fixed synthetic plaintext seed and fresh cryptographic randomness. A failing checkpoint is a counterexample to blanket correctness of that tested configuration; it does not locate the earliest possible failure. A zero noise-budget report alone is not treated as failure: the experiment compares actual decrypted results, and some zero-budget runs still decode correctly. Passing a small count would not establish all `nd-1` merges or a cryptographic failure bound.


## r3 diagnosis and candidate repair

`--parameter-set incremental-candidate` selects key-modulus limb sizes
`60,50,50,50` (210 bits total, 160 data bits), at degree 8192 with mandatory
SEAL `tc128` validation. Plaintext modulus, layout, normalized inputs and
query computation are unchanged. This is a regression candidate; the flag
does not certify full-capacity correctness or deployment suitability.

At each stress checkpoint, r3 decrypts **every accumulated row** and checks
it against plaintext packing. It also freshly encrypts the exact same
gallery and evaluates it with the same encrypted query as a diagnostic
control. The fresh control is never used to refresh or replace the
accumulated block. These checks distinguish row accumulation from failure
in the final encrypted query. Additional encryption changes the crypto
randomness consumption; compare observed behavior rather than requiring
identical failure counts across versions.

A decoding error now yields exit status 2 after flushing raw evidence.
`run.py` preserves that evidence and reports nonzero status, including for
legacy drivers that returned zero despite incorrect decoding. Four runner
regression tests are in `test-runner.py`. A finite successful run records
`completedCapacity: false` unless it actually reaches `n*8192` registrations.

`validate-incremental.ps1 -Exe <r3 executable> -ScratchRoot <new local directory>`
runs three fresh-key repetitions per candidate profile at 64 registrations.
Add `-FullCapacity` for 24,576 and 16,384 registrations respectively; expect
hours of computation. Run with new result directories. Passing short tests
must not be reported as having completed this full-capacity validation.

The original E3 measurement table remains for the original parameters;
its timing/compression numbers must not be relabeled as repaired-parameter
performance measurements. Preserve `source-pre-r3/` and old manifests.
