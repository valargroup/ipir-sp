#!/usr/bin/env bash
set -euo pipefail
while [[ ! -f /root/results/final27/complete ]]; do
 kill -0 35879 2>/dev/null || { echo 'final27 stopped without completion'; exit 1; }
 sleep 5
done
for mode in 2 3 4; do
 RAYON_NUM_THREADS=8 /root/final27-packing 16 2 30 8 "$mode" > /root/results/final27/diagnostic-mode$mode.jsonl
done
printf 'complete\n' > /root/results/final27/diagnostics-complete
