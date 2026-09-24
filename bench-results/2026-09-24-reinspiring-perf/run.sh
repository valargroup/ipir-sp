#!/usr/bin/env bash
# Dedicated idle x86 host, Rust 1.89, AVX-512/VNNI; separate source/build dirs.
set -euo pipefail
main_dir=${1:?checkout of main 611a292 required}
refresh_dir=${2:?checkout of optimized implementation required}
out=${3:?absolute output directory required}
mkdir -p "$out"
cp "$refresh_dir/ipir-sp/examples/inspiring_e2e.rs" "$main_dir/ipir-sp/examples/"
export RUSTFLAGS='-C target-cpu=native'
# Do not share target directories across checkouts: Cargo can reuse stale examples.
(cd "$main_dir" && CARGO_TARGET_DIR=target-native cargo build --locked --release -p ipir-sp --example inspiring_e2e)
(cd "$refresh_dir" && CARGO_TARGET_DIR=target-native cargo build --locked --release -p ipir-sp --examples --features native-reinspiring)
for workers in 1 8; do
  RAYON_NUM_THREADS=$workers /usr/bin/time -v "$refresh_dir/target-native/release/examples/packing_compare" \
    > "$out/pack-t$workers.jsonl" 2> "$out/pack-t$workers.time"
done
BENCH_THREADS=1,2,4,8 RAYON_NUM_THREADS=8 /usr/bin/time -v \
  "$main_dir/target-native/release/examples/inspiring_e2e" 28672 32768 p14 30 \
  > "$out/main-p14.jsonl" 2> "$out/main-p14.time"
BENCH_THREADS=1,2,4,8 RAYON_NUM_THREADS=8 /usr/bin/time -v \
  "$refresh_dir/target-native/release/examples/native_e2e" 28672 32768 14 2 30 \
  > "$out/native-p14.jsonl" 2> "$out/native-p14.time"
for profile in p16q46 p16q48 p16q49; do
  BENCH_THREADS=8 RAYON_NUM_THREADS=8 /usr/bin/time -v \
    "$main_dir/target-native/release/examples/inspiring_e2e" 28672 32768 "$profile" 30 \
    > "$out/main-$profile.jsonl" 2> "$out/main-$profile.time"
done
for limbs in 2 3; do
  BENCH_THREADS=8 RAYON_NUM_THREADS=8 /usr/bin/time -v \
    "$refresh_dir/target-native/release/examples/native_e2e" 28672 32768 16 "$limbs" 30 \
    > "$out/native-p16-l$limbs.jsonl" 2> "$out/native-p16-l$limbs.time"
done
RAYON_NUM_THREADS=8 "$refresh_dir/target-native/release/examples/native_dot" > "$out/dot.jsonl"
