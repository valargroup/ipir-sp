#!/usr/bin/env bash
# Run from any directory with two separate checkouts, baseline at 689bceb.
# Usage: run.sh BASELINE_CHECKOUT OPTIMIZED_CHECKOUT OUTPUT_DIRECTORY
set -euo pipefail
baseline=$(cd "${1:?baseline checkout required}" && pwd)
optimized=$(cd "${2:?optimized checkout required}" && pwd)
mkdir -p "${3:?output directory required}"
out=$(cd "$3" && pwd)
if [[ "$baseline" == "$optimized" ]]; then
  echo 'Baseline and optimized checkouts must be different.' >&2
  exit 1
fi
export RAYON_NUM_THREADS=${RAYON_NUM_THREADS:-8}
export BENCH_THREADS=$RAYON_NUM_THREADS
# Match flags across both builds. Set RUSTFLAGS='-C target-cpu=native' for the
# Intel comparison; the initial Apple M4 Max measurements used default flags.
for variant in baseline optimized; do
  if [[ "$variant" == baseline ]]; then checkout=$baseline; else checkout=$optimized; fi
  (
    cd "$checkout"
    git rev-parse HEAD
    git diff --stat
    rustc -Vv
    printf 'RUSTFLAGS=%s\nRAYON_NUM_THREADS=%s\n' "${RUSTFLAGS:-}" "$RAYON_NUM_THREADS"
  ) > "$out/$variant-metadata.txt"
  # Explicit, distinct target directories avoid a stale example binary being
  # reused across checkouts with identical package versions.
  cargo build --manifest-path "$checkout/Cargo.toml" \
    --target-dir "$checkout/target/preprocessing-benchmark" --release \
    -p ipir-sp --features native-reinspiring --example native_e2e \
    > "$out/$variant-build.txt" 2>&1
done
for repeat in 1 2 3; do
  for variant in baseline optimized; do
    if [[ "$variant" == baseline ]]; then checkout=$baseline; else checkout=$optimized; fi
    binary="$checkout/target/preprocessing-benchmark/release/examples/native_e2e"
    if [[ $(uname -s) == Darwin ]]; then time_args=(-l); else time_args=(-v); fi
    /usr/bin/time "${time_args[@]}" "$binary" 28672 32768 14 2 3 \
      > "$out/$variant-$repeat.jsonl" 2> "$out/$variant-$repeat.time"
  done
done
python3 - "$out" <<'PY'
import json, pathlib, statistics, sys
root = pathlib.Path(sys.argv[1])
results = {}
observations = {}
for variant in ['baseline', 'optimized']:
    runs = [[json.loads(line) for line in path.read_text().splitlines()]
            for path in sorted(root.glob(f'{variant}-*.jsonl'))]
    assert len(runs) == 3
    observations[variant] = runs
    for run in runs:
        assert all(row['correct'] for row in run if row['kind'] == 'sample')
    results[variant] = [run[0]['offline_s'] for run in runs]
    results[variant + '_median_s'] = statistics.median(results[variant])
for before, after in zip(observations['baseline'], observations['optimized']):
    assert len(before) == len(after) == 4
    for field in ['rows', 'cols', 'pbits', 'ell', 'threads', 'coeff_bytes', 'published_bytes']:
        assert before[0][field] == after[0][field], field
    for left, right in zip(before[1:], after[1:]):
        for field in ['phase_error', 'upload_bytes', 'download_bytes']:
            assert left[field] == right[field], field
results['speedup'] = results['baseline_median_s'] / results['optimized_median_s']
(root / 'summary.json').write_text(json.dumps(results, indent=2) + '\n')
print(json.dumps(results, indent=2))
assert results['speedup'] >= 3, 'Preprocessing target was not reached'
PY
