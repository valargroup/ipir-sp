#!/usr/bin/env bash
# Final certificates at the chosen widths (each width set has its own setup ID),
# plus a p = 2^16 regression report and 65,536-row large-table checks.
set -euo pipefail
examples=${1:?release examples directory}
out=${2:?output directory}
mkdir -p "$out"
export RAYON_NUM_THREADS=${RAYON_NUM_THREADS:-8}
time_cmd() { if [ "$(uname)" = Darwin ]; then /usr/bin/time -l "$@"; else /usr/bin/time -v "$@"; fi; }
run() {  # name rows cols gadget ell query response mask
  local name=$1 rows=$2 cols=$3 gadget=$4 ell=$5 query=$6 response=$7 mask=$8
  time_cmd "$examples/native_noise" "$rows" "$cols" 54 "$mask" --two-mask --query-bits "$query" \
    --p-bits 8 --ell "$ell" --gadget-bits "$gadget" --response-bits "$response" --storage u8 \
    > "$out/noise-$name.json" 2> "$out/noise-$name.time"
  python3 reinspiring/tools/security/certify_native.py --require-bits 0 "$out/noise-$name.json" \
    > "$out/certificate-$name.json"
}
run p8-g19-q28-r10-m22 28672 65536 19 2 28 10 22   # P2
run p8-g27-q28-r10-m22 28672 65536 27 1 28 10 22   # P1
run p8-g19-q27-r10-m22 28672 65536 19 2 27 10 22   # smallest two-digit upload
run p8-g19-q28-r9-m22 28672 65536 19 2 28 9 22     # smallest two-digit total
run p8-g19-q28-r10-m22-rows65536 65536 32768 19 2 28 10 22
run p8-g27-q28-r10-m22-rows65536 65536 32768 27 1 28 10 22
# p = 2^16 regression: must equal the recorded 2026-10-09 report apart from new keys.
time_cmd "$examples/native_noise" 28672 32768 54 29 --two-mask \
  > "$out/noise-p16-regression-two-mask29-n49.json" 2> "$out/noise-p16-regression.time"
