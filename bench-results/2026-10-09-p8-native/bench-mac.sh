#!/usr/bin/env bash
# Apple M4 Max: no AVX-512, so packing matrices use i32/i64 and the scan uses
# portable kernels. Smaller matrix: 10 samples at 8 workers.
set -euo pipefail
e=${1:?release examples directory}
out=${2:?output directory}
export RAYON_NUM_THREADS=8
run() { local name=$1; shift; /usr/bin/time -l "$@" > "$out/$name.jsonl" 2> "$out/$name.time"; }
run mac-b49 "$e/native_e2e" 28672 32768 16 2 10 4 0 29 0 --threads 8
run mac-p2  "$e/native_e2e" 28672 65536 8 2 10 4 0 22 28 --response-bits 10 --storage u8 --threads 8
run mac-p2w "$e/native_e2e" 28672 65536 8 2 10 4 0 22 28 --response-bits 10 --storage u16 --threads 8
run mac-p1  "$e/native_e2e" 28672 65536 8 1 10 4 0 22 28 --gadget-bits 27 --response-bits 10 --storage u8 --threads 8
