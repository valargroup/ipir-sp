#!/usr/bin/env bash
# Run after run-final.sh and run-packed27.sh. Source abb6a96 = 8866066+packed27.patch.
set -euo pipefail
source /root/.cargo/env
export RUSTFLAGS='-C target-cpu=native'
test -f /root/results/packed27-complete
mkdir -p /root/results/final27
cd /root/optimized
git diff | sha256sum > /root/results/final27/source-diff-sha256.txt
cargo fmt -p inspiring -p reinspiring -p ipir-sp -p simplepir-kernel -- --check > /root/results/final27/fmt.log 2>&1
RUSTDOCFLAGS='-D warnings' cargo doc -p inspiring -p reinspiring -p ipir-sp -p simplepir-kernel --no-deps --all-features > /root/results/final27/doc.log 2>&1
cargo clippy -p inspiring -p reinspiring -p ipir-sp -p simplepir-kernel --all-targets --all-features -- -D warnings > /root/results/final27/clippy.log 2>&1
cargo test -p inspiring -p reinspiring -p ipir-sp -p simplepir-kernel --all-features --no-fail-fast > /root/results/final27/tests.log 2>&1
cargo test -p reinspiring --release --test native_flow native_paper_degree_roundtrip -- --ignored > /root/results/final27/degree2048.log 2>&1
cargo test -p ipir-sp --release --all-features --test native_flow > /root/results/final27/ipir-native.log 2>&1
cargo build --release -p ipir-sp --features native-reinspiring --example packing_stages --example native_e2e --example packing_compare > /root/results/final27/build.log 2>&1
cp target/release/examples/packing_stages /root/final27-packing
cp target/release/examples/native_e2e /root/final27-e2e
cp target/release/examples/packing_compare /root/final27-compare
sha256sum /root/final27-packing /root/final27-e2e /root/final27-compare > /root/results/final27/binary-sha256.txt
function packing() {
 local variant=$1 blocks=$2 ell=$3 workers=$4 concurrency=$5 rep=$6
 local mode=0
 if [[ $variant == final27 ]]; then mode=1; fi
 local out=/root/results/final27/packing-$variant-b$blocks-e$ell-t$workers-c$concurrency-r$rep
 RAYON_NUM_THREADS=$workers /usr/bin/time -v /root/$variant-packing "$blocks" "$ell" 30 "$concurrency" "$mode" > "$out.jsonl" 2> "$out.time"
}
# Primary final comparison is directly paired against the original baseline.
for rep in 1 2 3; do
 for variant in baseline final27; do packing "$variant" 16 2 8 8 "$rep"; done
 for ell in 2 3; do packing final27 1 "$ell" 8 1 "$rep"; done
 packing final27 16 2 8 1 "$rep"
done
for ell in 2 3; do
 packing final27 16 "$ell" 1 1 1
 packing final27 1 "$ell" 1 1 1
done
# Full snapshot checks select first/middle/last rows and compare exact phase errors.
for rep in 1 2 3; do
 for variant in baseline final27; do
  RAYON_NUM_THREADS=8 BENCH_THREADS=8 /usr/bin/time -v /root/$variant-e2e 28672 32768 14 2 3 8 > /root/results/final27/e2e-$variant-r$rep.jsonl 2> /root/results/final27/e2e-$variant-r$rep.time
 done
 for workers in 1 8; do
  RAYON_NUM_THREADS=$workers /usr/bin/time -v /root/final27-compare > /root/results/final27/compare-t$workers-r$rep.jsonl 2> /root/results/final27/compare-t$workers-r$rep.time
 done
done
RAYON_NUM_THREADS=8 BENCH_THREADS=8 /usr/bin/time -v /root/final27-e2e 28672 32768 14 2 3 1 > /root/results/final27/e2e-final27-serial.jsonl 2> /root/results/final27/e2e-final27-serial.time
printf 'complete\n' > /root/results/final27/complete
