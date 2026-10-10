#!/usr/bin/env bash
# Timing and memory matrix on a dedicated idle x86 host (AVX-512 VNNI/VBMI).
# Builds: RUSTFLAGS='-C target-cpu=native', separate CARGO_TARGET_DIR per checkout.
#   head: the branch under test; base: origin/main 91e1965 (u16 no-regression A/B).
# Usage: bench.sh HEAD_EXAMPLES BASE_EXAMPLES OUT
set -euo pipefail
# shellcheck disable=SC1091
[ -f "$HOME/.cargo/env" ] && source "$HOME/.cargo/env"
head=${1:?head release examples directory}
base=${2:?base release examples directory}
out=${3:?output directory}
mkdir -p "$out"
export RAYON_NUM_THREADS=8
# Run from the head checkout so rustc resolves its pinned toolchain.
cd "$head/../../.."

host_json() {
  python3 - "$out/host.json" <<'PY'
import json, platform, subprocess, sys
flags = open('/proc/cpuinfo').read()
cpu = next(l.split(':', 1)[1].strip() for l in open('/proc/cpuinfo') if l.startswith('model name'))
mem = next(int(l.split()[1]) * 1024 for l in open('/proc/meminfo') if l.startswith('MemTotal'))
json.dump({
    'cpu': cpu, 'vcpus': int(subprocess.check_output(['nproc'])), 'memory_bytes': mem,
    'flags': {f: (f in flags) for f in ('avx512f', 'avx512dq', 'avx512bw', 'avx512_vnni', 'avx512vbmi', 'avx512ifma')},
    'kernel': platform.release(), 'rustc': subprocess.check_output(['rustc', '-V'], text=True).strip(),
    'rayon_workers': 8, 'loadavg_start': open('/proc/loadavg').read().split()[:3],
}, open(sys.argv[1], 'w'), indent=2)
PY
}
run() {  # name binary args...
  local name=$1; shift
  echo "$(date -u +%FT%TZ) start $name load $(cut -d' ' -f1-3 /proc/loadavg)" >> "$out/log.txt"
  /usr/bin/time -v "$@" > "$out/$name.jsonl" 2> "$out/$name.time"
  echo "$(date -u +%FT%TZ) end   $name load $(cut -d' ' -f1-3 /proc/loadavg)" >> "$out/log.txt"
}

host_json
P16="28672 32768 16 2"
P8_2="28672 65536 8 2"
P8_1="28672 65536 8 1"
# Pass 1: all configurations, 20 samples at 1/2/4/8 workers, offline concurrency 4.
run b49  "$head/native_e2e" $P16 20 4 0 29 0  --threads 1,2,4,8
run b43  "$head/native_e2e" $P16 20 4 0 29 43 --threads 1,2,4,8
run b44  "$head/native_e2e" $P16 20 4 0 29 44 --threads 8
run p2   "$head/native_e2e" $P8_2 20 4 0 22 28 --response-bits 10 --storage u8  --threads 1,2,4,8
run p2w  "$head/native_e2e" $P8_2 20 4 0 22 28 --response-bits 10 --storage u16 --threads 1,2,4,8
run p1   "$head/native_e2e" $P8_1 20 4 0 22 28 --gadget-bits 27 --response-bits 10 --storage u8 --threads 1,2,4,8
# Pass 2, reverse order: 8 workers, offline concurrency 1 (build peak RSS), drift check.
run p1-c1  "$head/native_e2e" $P8_1 20 1 0 22 28 --gadget-bits 27 --response-bits 10 --storage u8 --threads 8 --no-cold-decode
run p2w-c1 "$head/native_e2e" $P8_2 20 1 0 22 28 --response-bits 10 --storage u16 --threads 8 --no-cold-decode
run p2-c1  "$head/native_e2e" $P8_2 20 1 0 22 28 --response-bits 10 --storage u8  --threads 8 --no-cold-decode
run b43-c1 "$head/native_e2e" $P16 20 1 0 29 43 --threads 8 --no-cold-decode
run b49-c1 "$head/native_e2e" $P16 20 1 0 29 0  --threads 8 --no-cold-decode
# Base vs head on unchanged u16 profiles (main's example reads BENCH_THREADS).
BENCH_THREADS=8 run base-b49 "$base/native_e2e" $P16 20 4 0 29 0
BENCH_THREADS=8 run base-b43 "$base/native_e2e" $P16 20 4 0 29 43
# Isolated scan kernels: same 1.75 GiB / 1.75 GiB of logical bits per configuration.
run dot-p16-q49    "$head/native_dot" --pbits 16 --query-bits 49
run dot-p16-q43    "$head/native_dot" --pbits 16 --query-bits 43
run dot-p8-u16-q28 "$head/native_dot" --cols 65536 --pbits 8 --query-bits 28
run dot-p8-u8-q28  "$head/native_dot" --cols 65536 --pbits 8 --query-bits 28 --storage u8
run dot-p8-u8-q49  "$head/native_dot" --cols 65536 --pbits 8 --query-bits 49 --storage u8
python3 - "$out/host.json" <<'PY'
import json, sys
h = json.load(open(sys.argv[1])); h['loadavg_end'] = open('/proc/loadavg').read().split()[:3]
json.dump(h, open(sys.argv[1], 'w'), indent=2)
PY
(cd "$out" && sha256sum *.jsonl *.time host.json log.txt > SHA256SUMS)
echo done > "$out/DONE"
