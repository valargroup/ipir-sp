#!/usr/bin/env bash
set -euo pipefail
source /root/.cargo/env
export RUSTFLAGS='-C target-cpu=native'
test -f /root/results/final27/diagnostics-complete
cd /root/optimized
git apply /root/tiles8.patch
cargo test --release -p reinspiring --lib > /root/results/tiles-tests.log 2>&1
cargo build --release -p ipir-sp --features native-reinspiring --example packing_stages > /root/results/tiles8-build.log 2>&1
cp target/release/examples/packing_stages /root/tiles8-packing
sed -i 's/const PACKED_TILE_ROWS: usize = 8;/const PACKED_TILE_ROWS: usize = 16;/' reinspiring/src/native_matrix.rs
cargo build --release -p ipir-sp --features native-reinspiring --example packing_stages > /root/results/tiles16-build.log 2>&1
cp target/release/examples/packing_stages /root/tiles16-packing
for rep in 1 2 3; do
 variants='final27 tiles8 tiles16'
 if [[ $rep == 2 ]]; then variants='tiles16 tiles8 final27'; fi
 for variant in $variants; do
  RAYON_NUM_THREADS=8 /root/$variant-packing 16 2 30 8 1 > /root/results/tiles-trial-$variant-r$rep.jsonl
 done
done
for variant in final27 tiles8 tiles16; do
 RAYON_NUM_THREADS=8 /root/$variant-packing 16 3 30 8 1 > /root/results/tiles-ell3-$variant.jsonl
 RAYON_NUM_THREADS=8 /root/$variant-packing 1 2 30 1 1 > /root/results/tiles-single-$variant.jsonl
done
printf 'complete\n' > /root/results/tiles-complete
