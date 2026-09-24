#!/usr/bin/env python3
"""Prepend the final tiling result to the complete four-row reference report."""
import json, statistics, subprocess, sys
from pathlib import Path
root=Path(__file__).resolve().parent
subprocess.run([sys.executable,str(root/'write-report.py')],check=True)
prior=(root/'README.md').read_text().replace('# Native packing optimization results','# Four-row reference measurements',1)
s=json.loads((root/'summary-final8.json').read_text()); t=s['trials_ms']; e=s['e2e_medians']; c=s['compare_medians_ms']
a=statistics.median(t[f'tiles-trial-final27-r{i}'] for i in [1,2,3]); b=statistics.median(t[f'tiles-trial-tiles8-r{i}'] for i in [1,2,3])
text=f'''# Native packing optimization results

Final implementation: `{s['source']}`, based on main `1d8aea3`.
The complete four-row reference measurements below remain available so that
results from different cohorts are not silently pooled. This final supplement
selects eight-row tiles and supersedes their online timings on AVX-512/VBMI.
The preprocessing arithmetic, coefficient format, parameters and wire format
are unchanged by the final tiling refinement.

## Final eight-row refinement

Three paired trials per layout, thirty fresh-key queries per trial, sixteen
blocks, degree 2048, two limbs, eight workers; reversed layout order in the
second repetition. Every fixture and ciphertext digest matches across layouts,
and also matches the four-row reference cohort.

| Run | Four rows | Eight rows | Sixteen rows |
|---|---:|---:|---:|
'''
for i in [1,2,3]:
 text+=f"| {i} | {t[f'tiles-trial-final27-r{i}']:.3f} ms | {t[f'tiles-trial-tiles8-r{i}']:.3f} ms | {t[f'tiles-trial-tiles16-r{i}']:.3f} ms |\n"
text+=f'''
The median improves **{a:.3f} → {b:.3f} ms ({(1-b/a)*100:.1f}% lower)**.
Eight rows improved every paired trial; sixteen rows was less consistent.
Single exploratory checks also improved the three-limb fixture
(13.373 → 12.971 ms) and one-block two-limb fixture (0.925 → 0.901 ms).
These secondary checks have one repetition and are not precision estimates.

Final expanded Intel SIMD tests, Clippy, integrated native flow and three
full-wire benchmark runs pass. The full-database shape remains **28,672 × 32,768
u16 elements, 1.75 GiB**. Final medians:

| Measurement | Final eight-row implementation |
|---|---:|
| Complete preprocessing, eight blocks in flight | {e['setup_s']:.3f} s |
| Packing stage | {e['packing_ms']:.3f} ms |
| Database scan | {e['matvec_ms']:.3f} ms |
| Complete server response, sequential stages | {e['server_ms']:.3f} ms |
| Retained native two-limb coefficients, sixteen blocks | 433.25 MiB |

These are a final validation cohort, not freshly interleaved baseline pairs;
see the four-row section for directly paired preprocessing evidence. First,
middle and last rows recover exactly, with matching baseline phase errors and
wire sizes. Faster final scan timings are run variation, not a scan code change.

The final same-host, single-block hot-path comparison (three runs, thirty
samples each, eight workers) measures actual InspiRING at **{c['inspiring_odd']:.3f} ms**,
native two-limb ReinspiRING at **{c['native_l2_pack']:.3f} ms**
(**{c['inspiring_odd']/c['native_l2_pack']:.2f}× faster**) and native three-limb at
**{c['native_l3_pack']:.3f} ms**. The identical-parameter odd-q ReinspiRING adapter
remains slower at **{c['reinspiring_odd']:.3f} ms**. Native uses a different modulus
and decomposition; these are implementation measurements, not a security-equivalence
claim or a reproduction of the complete ReinsPIRe protocol's headline gain.

## Packing material, measured directly

| Coefficient payload | Per degree-2048 output | Sixteen outputs |
|---|---:|---:|
| Actual InspiRING preprocessed output | 95.96875 MiB | 1535.5 MiB |
| Native ReinspiRING, two limbs | 27.07813 MiB | 433.25 MiB |
| Native ReinspiRING, three limbs | 42.10938 MiB | 673.75 MiB |

InspiRING also has **95.953125 MiB of shared top-key image coefficients**, counted
once rather than per output. Counts come from allocated coefficient vector lengths
in `packing_compare`, not peak RSS. The sixteen-output InspiRING figure is the
linear sum of sixteen per-output buffers, not a new full-server allocation sample.
Context tables, object headers, allocator overhead, temporary scratch, database and
other server state are excluded. Native compression uses exact actual coefficient
bounds, not lossy truncation. Parallel setup can raise peak process memory even
while retained material falls.

## Remaining optimization opportunities

The tested low-level candidates are exhausted for this pass, not proven globally
optimal. On the four-row source, matrix work took 7.069 ms versus 6.238 ms for a
read/XOR sweep of its compressed payload. This is an optimistic traffic reference,
not a strict bandwidth lower bound or a prediction for another machine.

Further experiments have different tradeoffs: batching multiple queries could
reuse matrix reads and raise throughput but may add queueing latency; deployment
hardware, thread affinity and NUMA placement need measurements on that hardware;
persisting compiled material could avoid rebuilding unchanged snapshots but needs
versioning and snapshot binding. These are unimplemented candidates, not claimed
wins. The split API already permits packing contributions to overlap the scan,
but transport, authentication, request/block binding and two-machine timings remain
integration work. Do not add scan and packing times when estimating an ideal
parallel critical path; do include final addition and network overhead.

## Final evidence

`summary-final8.json`, `analyze-tiles.py`, `tiles-experiment.sh` and
`run-tiles-final.sh` record the refinement. `harness/tiles-final.patch` is the
kernel/test diff from `abb6a96`; the separate material-count patch affects only
reported buffer counts. All 451 remote source files match commit `6c1aabc`.
`REMOTE-SHA256SUMS` covers 403 collected host artifacts; names under `final/`,
`final27/` and `final8/` map to `raw-final/`, `raw-final27/` and `raw-final8/`.
All other names map to `raw-experiments/`. Frozen binaries were also downloaded
and verified locally; their hashes are archived, not their large executable files.
`completion.json` records source CI links and verified temporary-host cleanup.
Independent review approved the final implementation; the native cryptographic
profile remains experimental with the production gates in SECURITY.md.

---

'''
(root/'README.md').write_text(text+prior)
