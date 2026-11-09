# Unified512 runtime repair, 2026-10-31

This is a new source/run lineage. Do not overwrite or resume the older
`unified-20261031` / `bgv-unified-20261031-resumed` artifacts.

The previous MinGW C++17 `std::shared_mutex` path leaked Windows handles.
One run stalled in the OpenMP startup barrier after process handle exhaustion.
All completed decoding checkpoints remained correct; capacity was not validated.
See `../../../notes/runtime-repair-20261031.md` and the diagnostic directory.

Build official SEAL 4.1.2 with **`-DSEAL_USE_CXX17=OFF`**, Zstd enabled and
zlib/MSGSL disabled as in the saved configure log. This selects SEAL's existing
atomic ReaderWriterLocker. Compile this driver as C++17 with OpenMP and point
`SEAL_DIR` at that new SEAL build. Set `BIOBIND_ZSTD_LIBRARY` to its
`lib/libzstd.a` when using the existing MinGW packaging. The driver rejects
MinGW configurations that still define `SEAL_USE_SHARED_MUTEX`.

`runtime-build.json` identifies the actual executable, static libraries,
generated config, numerical/RNG source and driver files by SHA-256. The original
benchmark in vendor/ and numerical profile are unchanged. Independent OS-seeded
keys and encryption randomness are retained; only plaintext test data use fixed
seeds.

The controller still executes smoke128, serial component measurement and three
independent 16384-registration histories. The full accumulated ciphertext is
never replaced by the freshly encrypted diagnostic control. Checkpoints include
8192, 8193 and 16384, with every decoded row/query/packed value checked.

Progress is emitted every 64 registrations with handle telemetry. It is not a
correctness checkpoint. A handle count >=10000 causes failure; 900 seconds
without new progress causes the runner to terminate the child and preserve raw
files. Read open log contents rather than relying on directory timestamps.

The new measurements remain synthetic component experiments, not an integrated
LFW/PVSC/threshold-decryption/on-chain pipeline or an independent correctness proof.
