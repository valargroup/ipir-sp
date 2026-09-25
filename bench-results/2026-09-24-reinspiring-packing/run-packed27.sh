#!/usr/bin/env bash
set -euo pipefail
source /root/.cargo/env
while [[ ! -f /root/results/final/complete ]]; do
 kill -0 21866 2>/dev/null || { echo 'final job stopped without completion'; exit 1; }
 sleep 10
done
cd /root/optimized
export RUSTFLAGS='-C target-cpu=native'
git apply /root/packed27.patch
cargo test --release -p reinspiring > /root/results/packed27-tests.log 2>&1
cargo build --release -p ipir-sp --features native-reinspiring --example packing_stages > /root/results/packed27-build.log 2>&1
cp target/release/examples/packing_stages /root/packed27-packing
sha256sum /root/packed27-packing /root/packed27.patch > /root/results/packed27-sha256.txt
for rep in 1 2 3; do
 variants='final packed27'
 if [[ $rep == 2 ]]; then variants='packed27 final'; fi
 for ell in 2 3; do
  for variant in $variants; do
   RAYON_NUM_THREADS=8 /usr/bin/time -v /root/$variant-packing 16 "$ell" 30 8 1 > /root/results/packed27-trial-$variant-e$ell-r$rep.jsonl 2> /root/results/packed27-trial-$variant-e$ell-r$rep.time
  done
 done
done
for variant in final packed27; do
 RAYON_NUM_THREADS=8 /root/$variant-packing 1 2 30 1 1 > /root/results/packed27-single-$variant.jsonl
done
printf 'complete\n' > /root/results/packed27-complete
