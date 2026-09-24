#!/usr/bin/env bash
# Run on an idle host after installing Rust 1.89.0 and Python 3.
# Supply separate directories for pinned main and the refreshed implementation.
set -euo pipefail
main_dir=${1:?pinned main checkout required}
refresh_dir=${2:?refreshed checkout required}
output_dir=${3:?output directory required}
mkdir -p "$output_dir"
cp "$refresh_dir/ipir-sp/examples/inspiring_e2e.rs" "$main_dir/ipir-sp/examples/"
(cd "$main_dir" && cargo build --locked --release -p ipir-sp --example inspiring_e2e)
(cd "$refresh_dir" && cargo build --locked --release -p ipir-sp --examples --features native-reinspiring)
for workers in 1 2 4 8; do
  RAYON_NUM_THREADS=$workers /usr/bin/time -v "$refresh_dir/target/release/examples/packing_compare" \
    > "$output_dir/pack-t$workers.jsonl" 2> "$output_dir/pack-t$workers.time"
done
BENCH_THREADS=1,2,4,8 RAYON_NUM_THREADS=8 /usr/bin/time -v \
  "$main_dir/target/release/examples/inspiring_e2e" 28672 32768 p14 30 \
  > "$output_dir/main-p14-scaling.jsonl" 2> "$output_dir/main-p14-scaling.time"
BENCH_THREADS=1,2,4,8 RAYON_NUM_THREADS=8 /usr/bin/time -v \
  "$refresh_dir/target/release/examples/native_e2e" 28672 32768 14 2 30 \
  > "$output_dir/native-p14-scaling.jsonl" 2> "$output_dir/native-p14-scaling.time"
for profile in p16q46 p16q48 p16q49; do
  BENCH_THREADS=8 RAYON_NUM_THREADS=8 /usr/bin/time -v \
    "$main_dir/target/release/examples/inspiring_e2e" 28672 32768 "$profile" 30 \
    > "$output_dir/main-$profile-t8.jsonl" 2> "$output_dir/main-$profile-t8.time"
done
for limbs in 2 3; do
  BENCH_THREADS=8 RAYON_NUM_THREADS=8 /usr/bin/time -v \
    "$refresh_dir/target/release/examples/native_e2e" 28672 32768 16 "$limbs" 30 \
    > "$output_dir/native-p16-l$limbs-t8.jsonl" 2> "$output_dir/native-p16-l$limbs-t8.time"
done
