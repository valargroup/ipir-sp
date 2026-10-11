#!/usr/bin/env bash
# Screen stage: one full-size p = 2^8 noise report per gadget, with dithered
# query weights and every public-mask screen (lossless 54-bit publication),
# then counterfactual width frontiers. Widths change setup IDs, so chosen
# widths are regenerated and certified in the final stage.
set -euo pipefail
examples=${1:?release examples directory}
out=${2:?output directory}
mkdir -p "$out"
export RAYON_NUM_THREADS=${RAYON_NUM_THREADS:-8}
time_cmd() { if [ "$(uname)" = Darwin ]; then /usr/bin/time -l "$@"; else /usr/bin/time -v "$@"; fi; }
for cfg in "2 19" "1 27"; do
  set -- $cfg; ell=$1; gadget=$2
  time_cmd "$examples/native_noise" 28672 65536 54 54 --two-mask --query-bits 28 \
    --p-bits 8 --ell "$ell" --gadget-bits "$gadget" --response-bits 10 --storage u8 \
    > "$out/screen-noise-p8-g$gadget.json" 2> "$out/screen-noise-p8-g$gadget.time"
  python3 reinspiring/tools/security/certify_native.py --screens --require-bits 0 \
    "$out/screen-noise-p8-g$gadget.json" > "$out/screen-cert-p8-g$gadget.json"
done
