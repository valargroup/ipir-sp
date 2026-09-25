#!/usr/bin/env bash
set -euo pipefail
source /root/.cargo/env
export RUSTFLAGS='-C target-cpu=native'
mkdir -p /root/results/final8
cd /root/optimized
cargo test -p reinspiring --release --lib > /root/results/final8/tests.log 2>&1
cargo clippy -p reinspiring -p ipir-sp --all-targets --all-features -- -D warnings > /root/results/final8/clippy.log 2>&1
cargo test -p ipir-sp --release --all-features --test native_flow > /root/results/final8/native-flow.log 2>&1
cargo build --release -p ipir-sp --features native-reinspiring --example packing_stages --example native_e2e --example packing_compare > /root/results/final8/build.log 2>&1
cp target/release/examples/packing_stages /root/final8-packing
cp target/release/examples/native_e2e /root/final8-e2e
cp target/release/examples/packing_compare /root/final8-compare
sha256sum /root/final8-{packing,e2e,compare} > /root/results/final8/binary-sha256.txt
for rep in 1 2 3; do
 RAYON_NUM_THREADS=8 BENCH_THREADS=8 /usr/bin/time -v /root/final8-e2e 28672 32768 14 2 3 8 > /root/results/final8/e2e-r$rep.jsonl 2> /root/results/final8/e2e-r$rep.time
 RAYON_NUM_THREADS=8 /usr/bin/time -v /root/final8-compare > /root/results/final8/compare-r$rep.jsonl 2> /root/results/final8/compare-r$rep.time
done
printf 'complete\n' > /root/results/final8/complete
