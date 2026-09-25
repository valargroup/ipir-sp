#!/usr/bin/env bash
# Dedicated Intel host, existing /root/baseline and /root/optimized checkouts.
# final.patch is git diff b308543 8866066; baseline harness is archived alongside.
set -euo pipefail
source /root/.cargo/env
export RUSTFLAGS='-C target-cpu=native'
mkdir -p /root/results/final
cd /root/optimized
test -f /root/results/widthprobe-complete
git apply -R /root/widthprobe.patch
git apply /root/final.patch
cargo fmt -p inspiring -p reinspiring -p ipir-sp -p simplepir-kernel -- --check > /root/results/final/fmt.log 2>&1
RUSTDOCFLAGS='-D warnings' cargo doc -p inspiring -p reinspiring -p ipir-sp -p simplepir-kernel --no-deps --all-features > /root/results/final/doc.log 2>&1
cargo clippy -p inspiring -p reinspiring -p ipir-sp -p simplepir-kernel --all-targets --all-features -- -D warnings > /root/results/final/clippy.log 2>&1
cargo check -p inspiring -p reinspiring -p ipir-sp -p simplepir-kernel --all-targets --all-features > /root/results/final/check.log 2>&1
cargo test -p inspiring -p reinspiring -p ipir-sp -p simplepir-kernel --all-features --no-fail-fast > /root/results/final/tests.log 2>&1
cargo test -p reinspiring --release --test native_flow native_paper_degree_roundtrip -- --ignored > /root/results/final/degree2048.log 2>&1
cargo test -p reinspiring --release > /root/results/final/release-tests.log 2>&1
cargo bench -p inspiring --bench pack --no-run > /root/results/final/bench-inspiring.log 2>&1
cargo bench -p ipir-sp --bench end_to_end --features experimental-params --no-run > /root/results/final/bench-ipir.log 2>&1
cargo build --release -p ipir-sp --features native-reinspiring --example packing_stages --example native_e2e --example packing_compare > /root/results/final/build-optimized.log 2>&1
cp target/release/examples/packing_stages /root/final-packing
cp target/release/examples/native_e2e /root/final-e2e
cp target/release/examples/packing_compare /root/final-compare
cd /root/baseline
cargo build --release -p ipir-sp --features native-reinspiring --example packing_stages --example native_e2e > /root/results/final/build-baseline.log 2>&1
cp target/release/examples/packing_stages /root/baseline-packing
cp target/release/examples/native_e2e /root/baseline-e2e
sha256sum /root/final-packing /root/final-e2e /root/final-compare /root/baseline-packing /root/baseline-e2e /root/final.patch > /root/results/final/binary-sha256.txt
lscpu > /root/results/final/lscpu.txt
rustc -Vv > /root/results/final/rustc.txt
function packing() {
 local variant=$1 blocks=$2 ell=$3 workers=$4 concurrency=$5 rep=$6
 local mode=0
 if [[ $variant == final ]]; then mode=1; fi
 local out=/root/results/final/packing-$variant-b$blocks-e$ell-t$workers-c$concurrency-r$rep
 RAYON_NUM_THREADS=$workers /usr/bin/time -v /root/$variant-packing "$blocks" "$ell" 30 "$concurrency" "$mode" > "$out.jsonl" 2> "$out.time"
}
for rep in 1 2 3; do
 for ell in 2 3; do
  for variant in baseline final; do
   packing "$variant" 16 "$ell" 8 8 "$rep"
   packing "$variant" 1 "$ell" 8 1 "$rep"
  done
 done
 # Quantify batching separately from arithmetic improvements for primary profile.
 for variant in baseline final; do packing "$variant" 16 2 8 1 "$rep"; done
done
for ell in 2 3; do
 for variant in baseline final; do
  packing "$variant" 16 "$ell" 1 1 1
  packing "$variant" 1 "$ell" 1 1 1
 done
done
for rep in 1 2 3; do
 for variant in baseline final; do
  RAYON_NUM_THREADS=8 BENCH_THREADS=8 /usr/bin/time -v /root/$variant-e2e 28672 32768 14 2 3 8 > /root/results/final/e2e-$variant-r$rep.jsonl 2> /root/results/final/e2e-$variant-r$rep.time
 done
 for workers in 1 8; do
  RAYON_NUM_THREADS=$workers /usr/bin/time -v /root/final-compare > /root/results/final/compare-t$workers-r$rep.jsonl 2> /root/results/final/compare-t$workers-r$rep.time
 done
done
RAYON_NUM_THREADS=8 BENCH_THREADS=8 /usr/bin/time -v /root/final-e2e 28672 32768 14 2 3 1 > /root/results/final/e2e-final-serial.jsonl 2> /root/results/final/e2e-final-serial.time
printf 'complete\n' > /root/results/final/complete
