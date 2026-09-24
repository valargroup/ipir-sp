#!/usr/bin/env python3
"""Render the report only from completed, verified benchmark summaries."""
import json
import re
import statistics
from pathlib import Path
root=Path(__file__).resolve().parent
s=json.loads((root/'summary-final27.json').read_text())
old=json.loads((root/'summary.json').read_text())
def value(name,field,source=s):return source['packing'][name][field]['median']
def rss(path):return int(re.search(r'Maximum resident set size \(kbytes\): (\d+)',path.read_text())[1])*1024
b='baseline-b16-e2-t8-c8';n='final27-b16-e2-t8-c8'
bs=value(b,'setup_s');ns=value(n,'setup_s');bo=value(b,'online_ms');no=value(n,'online_ms')
serialb=value('baseline-b16-e2-t8-c1','setup_s',old);serialn=value('final27-b16-e2-t8-c1','setup_s')
eb=s['e2e']['baseline'];en=s['e2e']['final27']
ev=lambda v,k:v[k]['median']
serialpath=root/'raw-final27/e2e-final27-serial.jsonl'
serial=[json.loads(l) for l in serialpath.read_text().splitlines()]
assert len(serial)==4 and all(r['correct'] for r in serial[1:])
a=s['actual_inspiring'];comp=lambda threads,name:a[str(threads)][name]['median']
coeff=value(n,'coefficient_bytes')/2**20
text=f'''# Native packing optimization results

Published implementation: `abb6a96804dbef6f5b14cb4e23f97e6645df5938`, including
main `1d8aea3`. Baseline: `cf6a83c`, with diagnostic-only commit `b308543` and
the archived benchmark harness. Scope is ReinspiRING packing plus its IPIR-SP
integration. This does not implement the complete ReinsPIRe protocol.

## Primary packing result

Sixteen degree-2048 blocks (32,768 output coefficients), q=2^54, p=2^14,
base=2^19, two limbs, Gaussian profile; eight Rayon workers. Packing-only setup
starts from sixteen distinct random public mask matrices. It excludes database
hint construction and is not a benchmark of a database of a specified row count.
Each online sample has freshly generated uploaded keys. Medians below are
medians of three run medians, each with five warmups and thirty measured queries.

| Measurement | Before | Final | Improvement |
|---|---:|---:|---:|
| Packing setup, one block in flight | {serialb:.3f} s | {serialn:.3f} s | {serialb/serialn:.2f}× |
| Packing setup, eight blocks in flight | {bs:.3f} s | {ns:.3f} s | {bs/ns:.2f}× |
| Online packing, eight-block setup fixture | {bo:.3f} ms | {no:.3f} ms | {bo/no:.2f}× |
| Retained packing coefficients | {value(b,'coefficient_bytes')/2**20:.2f} MiB | {coeff:.2f} MiB | {100*(1-value(n,'coefficient_bytes')/value(b,'coefficient_bytes')):.2f}% smaller |
| Peak packing-only process RSS, eight blocks in flight | {value(b,'peak_rss_bytes')/2**30:.3f} GiB | {value(n,'peak_rss_bytes')/2**30:.3f} GiB | Includes fixtures and scratch |

Moving from the previous serial-block configuration to the explicit eight-block
configuration gives {serialb/ns:.2f}× lower packing setup time. The same-concurrency
row separates arithmetic improvements from scheduling. The default server
constructor still processes blocks sequentially; concurrent setup is opt-in.
The harness holds all input masks through setup, so process RSS includes that
caller-owned storage. Retained coefficient counts exclude NTT context tables,
allocator overhead, object headers, and the database.

The primary eight-block comparison is three directly interleaved baseline/final
pairs. Serial-block baseline values come from the preceding matched-fixture run
on the same dedicated host; they are not a second set of immediate final pairs.
Raw per-run values and variation are in `summary-final27.json` and `summary.json`.

## Complete database check

The original workload is **28,672 rows × 32,768 columns of u16**, exactly
1,879,048,192 bytes (**1.75 GiB**), with sixteen output packing blocks. Complete
setup includes hint construction, packing compilation, and database layout.
Three new baseline/final pairs each verify first, middle, and last rows through
the complete wire format (three warmups plus three measured queries).

| Complete IPIR-SP measurement | Before | Final |
|---|---:|---:|
| Preprocessing, previous serial / explicit eight-block final | {ev(eb,'setup_s'):.3f} s | {ev(en,'setup_s'):.3f} s |
| Packing stage | {ev(eb,'packing_ms'):.3f} ms | {ev(en,'packing_ms'):.3f} ms |
| Database scan | {ev(eb,'matvec_ms'):.3f} ms | {ev(en,'matvec_ms'):.3f} ms |
| Complete server response | {ev(eb,'server_ms'):.3f} ms | {ev(en,'server_ms'):.3f} ms |
| Peak process RSS | {ev(eb,'peak_rss_bytes')/2**30:.3f} GiB | {ev(en,'peak_rss_bytes')/2**30:.3f} GiB |

Complete preprocessing improves {ev(eb,'setup_s')/ev(en,'setup_s'):.2f}× relative to the
previous optimized revision. Against the older 117.724-second preprocessing
measurement in the [preceding report](../2026-09-24-reinspiring-preprocessing/README.md),
the final value is approximately {117.724/ev(en,'setup_s'):.2f}× faster; that older result
was collected on a different instance of the same hardware class, not in these
fresh pairs. The historically measured main InspiRING full setup was 9.523 s;
that full-database baseline has not been rerun in this packing-focused pass.

A separate check of the final **default serial constructor** took
{serial[0]['offline_s']:.3f} s with {rss(serialpath.with_suffix('.time'))/2**30:.3f} GiB peak RSS
(one run). Concurrent preprocessing therefore remains an explicit throughput /
peak-memory tradeoff, even though retained packing material is smaller.
All matched full-wire phase errors and upload/download sizes are unchanged.

## Separate packing and scan machines

`prepare_keys` prepares uploaded ciphertext bodies once per request;
`prepare_pack` computes H'y and the leftover without a scan result; consuming
`PendingNativePack::finish` adds the matching scan body. For the primary fixture:

| Packing component | Median time |
|---|---:|
| Request key preparation | {value(n,'key_ms'):.3f} ms |
| Independent packing contribution | {value(n,'contribution_ms'):.3f} ms |
| Final addition of scan bodies | {value(n,'finish_ms'):.3f} ms |

Component medians need not add exactly to the total median. With independent
machines, the computational critical path can approach
`max(scan, key preparation + packing contribution) + final addition`, rather
than the sum of scan and packing. This is an architectural implication, **not a
measured two-host latency**. Network, serialization, queueing, and authenticated
request/block dispatch are not implemented or measured by this split API.
The raw scan output for this shape is 256 KiB. A faster scan backend could make
packing the critical stage instead; no GPU/packing-machine comparison is claimed.

## Actual InspiRING and the papers

The same-host `packing_compare` benchmark uses one degree-2048 output, five
warmups and thirty samples per run, repeated three times. It repeats fixed keys
and inputs for hot-path attribution; it is separate from the fresh-key,
many-block benchmark above. Native entries here use the standalone `pack` API.

| Actual implementation | One worker | Eight workers |
|---|---:|---:|
| InspiRING, odd q≈2^56, three limbs | {comp(1,'inspiring_odd'):.3f} ms | {comp(8,'inspiring_odd'):.3f} ms |
| Odd-q ReinspiRING adapter, identical ciphertext parameters | {comp(1,'reinspiring_odd'):.3f} ms | {comp(8,'reinspiring_odd'):.3f} ms |
| Native ReinspiRING, q=2^54, two limbs | {comp(1,'native_l2_pack'):.3f} ms | {comp(8,'native_l2_pack'):.3f} ms |
| Native ReinspiRING, q=2^54, three limbs | {comp(1,'native_l3_pack'):.3f} ms | {comp(8,'native_l3_pack'):.3f} ms |

Native two-limb packing is {comp(1,'inspiring_odd')/comp(1,'native_l2_pack'):.2f}× faster
with one worker and {comp(8,'inspiring_odd')/comp(8,'native_l2_pack'):.2f}× faster with eight
than the actual InspiRING implementation in this hot-path benchmark. The odd-q
adapter remains slower. The native comparison changes modulus and decomposition
profile, so it is not an identical-security-parameter speedup claim.

[ReinsPIRe Table 5](https://eprint.iacr.org/2026/1934) reports single-threaded
packing setup / matrix / leftover times of 3.9 s / 13.6 ms / 1.2 ms for two limbs
and 6.0 s / 20.6 ms / 1.8 ms for three. Our final one-worker setup measurements
from the matching attribution harness are
{a['1']['setup_s']['native_l2']['median']:.3f} s and {a['1']['setup_s']['native_l3']['median']:.3f} s;
matrix times are {comp(1,'native_l2_matrix'):.3f} / {comp(1,'native_l3_matrix'):.3f} ms,
and standalone leftover times {comp(1,'native_l2_leftover'):.3f} / {comp(1,'native_l3_leftover'):.3f} ms.
These use a newer Xeon, Rust/Spiral, different caching, and different implementation
choices. Paper numbers are measurements, not a theoretical universal speedup.

[InsPIRe Table 5](https://eprint.iacr.org/2025/1352) reports 40 ms online and 36 s
offline for 4,096 LWEs producing two degree-2,048 outputs in its q≈2^56, p=2^15 profile (our actual-implementation fixture uses p=2^14).
A per-output normalization is 20 ms online / 18 s offline, not a fresh measured
baseline. Both papers report single-threaded Xeon results. The full ReinsPIRe
headline throughput gain concerns its complete protocol, not this IPIR-SP
composition.

The algorithmic cost remains O(ell*d² log d) compilation and O(ell*d²) online
matrix work, plus lifted polynomial products. Optimizations reduce constants,
allocations, transforms, and coefficient traffic. For two limbs, the dense
matrix payload is `2*d*d*27/8 = 27 MiB` per block on this host; the remaining
packing coefficient bytes are the final mask, cached leftover transforms, and
eight padding bytes. Three-limb matrices in the measured fixtures require 28 bits.

## Retained and rejected work

Retained: owned power-of-two FFT compilation, tiled transpose and direct compact
block concatenation; bounded block scheduling; safe i64-to-i128 aggregation;
public trace residue/CRT simplification; request-wide transforms and bounded
full-sum leftover reconstruction; four-row SIMD; exact adaptive 27/28-bit storage;
and the scan-independent packing API. All wider-range and unsupported-CPU
fallbacks remain exact.

The final 27-bit refinement was a separately reviewed three-pair experiment:
two-limb online medians were 8.736 ms with 28 bits and 8.478 ms with adaptive
storage, at about 2% more packing setup time. It saves a further 16 MiB over
sixteen blocks. Its three-limb fixtures retain 28-bit storage.

Rejected: reusable trace scratch changed setup only about 0.2%; 24/26-bit storage
could not represent the observed coefficients; the previously tested split-word
multiply did not beat the native SIMD kernel. Shared uploaded transforms alone
were modest until combined with the full-sum leftover path and matrix kernel.
A read/XOR diagnostic of the original 32-bit payload took about 7.35 ms versus
7.95 ms for the four-row matrix multiplication; this motivated compression.
It is an optimistic traffic reference, not a strict hardware lower bound.

At this four-row checkpoint, no further demonstrated CPU-packing win remained
from the candidates tested so far; the final eight-row supplement records the
subsequent successful refinement. This is not a proof of optimality: different hardware,
request batching, or protocol changes are separate experiments. Reusing the few
setup-mask transforms across blocks cannot remove the thousands of sequential
trace products per block; this pass retains the simpler per-block contexts.

## Validation and reproduction

Final code passed Intel formatting, docs, Clippy, all-feature tests, explicit
release degree-2048 checks, release SIMD tests, and integrated full-wire checks.
The initial implementation also passed bench compilation and independent Python
integer-oracle tests. Mac checks cover portable fallbacks. CUDA hardware tests
inherited from main are explicitly ignored on this CPU host.

`analyze.py` and `analyze-final27.py` reject missing groups, incomplete runs,
failed process statuses, input-hash mismatches, ciphertext-hash mismatches, or
changed matched full-wire phase errors. All four fixture shapes and all thirty
per-shape ciphertext sample hashes match across versions and schedules.
`REVIEW.md` records the required second implementation review and the FFT helper
regression it found and closed. This does not approve the experimental native
cryptographic profile; the existing production activation gates in
[SECURITY.md](../../reinspiring/SECURITY.md) remain unchanged.

Hardware: DigitalOcean dedicated Intel eight vCPU / 32 GiB, ams3, Xeon Gold
6548N, Rust1.89, release `RUSTFLAGS='-C target-cpu=native'`. Build/test processes
and timed workloads ran serially. `metadata.json`, frozen binary hashes,
source verification, raw logs, and the three run scripts establish provenance.
The final host tree was checked against all 451 files in source commit `abb6a96`.

Recreate baseline `b308543` and optimized `8866066`, copy the archived baseline
harness into its example path, and run the commands in `run-final.sh` using
separate target directories. Apply `harness/packed27-candidate.patch` (the retained
`abb6a96` code diff), then run `run-packed27.sh` and `run-final27.sh`. Host paths
and the prerequisite-wait PID in those scripts describe the recorded session;
adapt them for a new host. Run both analysis scripts after collecting all data.
Cleanup and SHA-256 verification are recorded alongside the report.
'''
(root/'README.md').write_text(text)
