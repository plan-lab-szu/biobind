# Unified 512-dimensional candidate, 2026-10-31

The candidate matches the manuscript's **512 dimensions / Gamma 2047**.
It uses N=8192, two packed layers, capacity 16384, T=8473312,
48-bit batching plaintext modulus and coefficient bits 60,50,50,50.
See `profile.json` for high-precision C1 bounds. These static checks do not
establish accumulated-noise correctness. Exact primes and parameter IDs
must come from a successful SEAL execution; none are invented here.

Build succeeded using the existing SEAL 4.1.2 toolchain. Windows Code
Integrity blocked the executable before the first smoke test. See
`windows-execution-block.json`. **No unified-profile runtime result exists.**
Do not change security settings or relabel old Gamma128/512 runs as this profile.

Source is self-contained with the unchanged author benchmark under vendor/.
The driver checks dimension, coordinate and squared-norm bounds on unified
query/enrollment vectors. Stress encryption uses four OpenMP workers with
separate encoder/encryptor objects and memory pools; measurement mode is
serial so its component timers do not sum parallel worker time. The parallel
driver has compiled but has not yet been validated at runtime.

In an environment permitted to run locally built research programs, configure
with CMake, a C++17 compiler, OpenMP and official SEAL 4.1.2 (with Zstandard).
On Linux a normal SEAL installation requires no MinGW packaging patch:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DSEAL_DIR=/path/to/seal/lib/cmake/SEAL-4.1
cmake --build build -j4
python -m pip install pycryptodome
python run-full.py --exe build/bgv-measure --out /new/results --scratch /new/local-ciphertexts
```

`run-full.py` performs 128-registration smoke, one warmup plus five serial
measurement rounds, then three full-capacity histories with independent
keys and plaintext seeds 20261031/32/33. It verifies checkpoints 8192,8193,
16384 and all intermediate powers of two. All 16384 registrations in every
full run must actually be encrypted and accumulated; no fresh block replaces
the accumulation. The fresh-block comparison is only a diagnostic control.
It retains raw logs on failure and never marks partial runs as full passes.

Measurements remain synthetic. Matching dimensionality and quantization
does not establish integration with LFW features, PVSC, threshold decryption,
the bridge or the on-chain gateway. These are separate acceptance obligations.
