# Packing optimization work in progress

User objective: continue optimizing until practical ideas are exhausted; focus
on packing, with packing and database matvec planned on separate machines.
Goal remains active. Do not mistake provisional improvements for completion.

Baseline: cf6a83c (previous 3.21x preprocessing improvement). Diagnostic-only
commit b308543 adds NativeBuildTiming/build_timed and packing_stages example.
Current uncommitted changes: native power-of-two FFT compiler + tiled transpose
and owned input; concurrency-capable benchmark; prepared request key transforms
and PendingNativePack prepare/finish API; equivalence/negative tests.

Temporary approved DO host (KEEP until final collection):
- ID 603320067, roman-reinspiring-packing-20260924, 178.62.223.36
- ams3, g-8vcpu-32gb-intel, Ubuntu24, 120GB disk, Valargroup misc project
- SSH root with Roman local id_ed25519; no private key/env copied.
- /root/baseline and /root/optimized from b308543 source bundle.
- /root/results retains experiments. Rust1.89 target-cpu=native.
- bootstrap PID8628 finished. compiler experiment PID15446 finished.
- online experiment PID16955 finished (confirm marker before further workloads).
- Sources are b308543 plus /root/compiler.patch or /root/online.patch.
  Baseline additionally has updated concurrency-capable benchmark only.
- Source transfer: /tmp/reinspiring-packing-opt locally; preserve patches/results.

Measured exploratory Intel (one run, 16 distinct matrices, ell2, 8 workers):
- Initial packing setup: about 22 s (sum individual stages, old harness).
- Optimized compiler, new batch harness: c1 15.040s; c2 8.517s;
  c4 6.165s; c8 5.749s. Need paired final runs with SAME harness.
- Shared online key transforms, 30 samples:
  legacy 16-block median12.337ms; cached11.792ms (key .323ms,
  contribution11.363ms, finish .103ms). Single-block legacy1.195ms vs
  cached1.326ms: retain legacy pack API for single-block use.
- Mac compiler concurrency setup c1 7.701s,c2 4.047,c4 2.645,c8 2.566.
  Mac measurements vary; use dedicated Intel for decisions.
- Native flow tests (7 passed/1 ignored) and all-target/all-feature clippy passed
  with current cached key API. Exact ciphertext equality + malformed body and
  setup rejection are covered. Degree2048/full integration still must run.

Next candidates, not exhausted:
1. Aggregate the two leftover limb products before inverse transforms ONLY if
   public full-sum CRT bound fits two primes; otherwise retain per-limb fallback.
   Current sum_cached still reconstructs each limb, same as legacy path.
2. Measure many-block matrix-only/leftover-only and bandwidth lower bound to
   identify remaining online limit. Consider four-row fused SIMD kernel; prior
   split-32-bit multiplication experiment was rejected in earlier perf report.
3. Fuse H-stack and compact NativeMatrix conversion to avoid intermediate u64
   matrix copy (~64MiB/block at ell2). Peak memory matters for c4/c8 setup.
4. Parallelize exact integer aggregation FFT, improve its transpose locality;
   optionally use i64 stages only while len*(q-1)<=i64::MAX then widen to i128.
   NEVER reduce modulo q before D.1 division; preserve exact floor rounding.
5. Reuse trace buffers/contexts/automorphism tables across blocks; measure impact.
6. Integrate accepted shared-key path into NativeServer respond, and expose a
   bounded packing-batch builder or documented scheduling API for separate host.
   PendingNativePack already allows all expensive terms before scan output;
   dispatcher must retain existing request binding. No network protocol added.

Must finish: evaluate promising candidates; retain/reject with measured evidence;
full correctness + release/debug/clippy/docs checks; matched many-block and
single-block runs for 2/3 limbs; report isolated packing setup/online/final join,
peak memory and retained storage; update PR17 origin/main (already authorized);
follow CI (historically queued self-hosted jobs; run equivalent checks directly);
copy+SHA256 verify artifacts; delete ONLY host603320067 and verify absence.

Further progress (uncommitted):
- sum_cached now combines leftover products iff prepare_public's whole-sum
  signed CRT bound fits two primes; otherwise keeps per-product reconstruction.
  Native key preparation chooses sufficient primes from profile-wide digit bound
  (safe across all blocks), lowering request prep ~.323 to .221ms on Intel.
  New dense-boundary test forces the aggregate capacity boundary.
- Intel aggregate trial: b16 legacy12.552 vs prepared11.851ms;
  b1 legacy1.154 vs prepared1.072ms; ell3 prepared17.834ms. All correct.
  Thus 16-block online is mainly H'y; no large leftover-total gain claimed.
- NativeMatrix::from_blocks directly compacts H-stack and validates all blocks;
  caller in NativePreprocessed now uses it. Needs dedicated multiblock conversion
  tests before final, although oracle and existing matrix tests pass.
- Added read/XOR diagnostic and benchmark modes2=matrix,3=leftover,4=read.
- Trial four-row AVX512 dot shares y loads across four rows, dispatches scalar/
  AVX2 fallback otherwise; current worktree selects it. Local kernel tail/sign
  tests and Clippy passed, but actual AVX512 must pass remote tests.
- /root/aggregate-experiment.sh finished. Next /root/rows4-experiment.sh runs
  diagnostic version (from_blocks, no four-row kernel) then four-row variant.
  /tmp/reinspiring-packing-opt/diag.patch and rows4.patch are full diffs from
  b308543. Remote optimized reset uses reverse prior patch then apply next.
  This script does NOT modify baseline. Preserve /root/diag-packing binary.

## Progress after packing optimization continuation

Retained code committed ee3cfa2, then merged latest origin/main 1d8aea3
(CUDA matvec PR22) in **88660669f548ed33988220cdb13f5d9469dd33c8**.
Only conflict was CI package lists; retained union of reinspiring and
simplepir-kernel checks. Baseline remains b308543 (diagnostic-only atop cf6a83c).
PR remote remains cf6a83c, now confirmed ALL existing checks succeeded.
Main workspace /Users/roman/projects/ipir-sp untouched.

Accepted additional experiments:
- Packed28 exact coefficient storage on AVX512 f/dq/bw/vbmi, four padding bytes,
  automatic32/64 fallback otherwise; paired medians (30 samples per run):
  mixed32 9.120/9.605/9.383ms vs packed28 8.654/8.619/8.617ms.
  Each ell2block storage 33,636,352 ->29,442,052 bytes.
  Actual Intel SIMD boundary tests and full exact-output/decrypt checks passed.
- Mixed i64/i128 aggregation setup c8 ~5.12s. Final width always widened before
  public worst-case bound crosses i64; direct independent integer tests passed.
- public_dot small-bound residue conversion, canonical add/sub reduction,
  specialized exact two-prime CRT: setup5.207/5.187/5.191 ->4.542/4.530/4.537s.
- NativeServer respond integrates prepared key sharing. New bounded build APIs
  preserve default serial behavior and expose opt-in batch concurrency.
  New tests compare complete published masks and wire responses across batches.
- Packed28 and from_blocks have boundary, malformed-shape, fallback tests.
- Benchmark now hashes all fixture inputs and exact ciphertext rows outside
  timers. Baseline-compatible harness archived under harness/.

Rejected/deferred experiments:
- Reusable PublicDotEvaluator scratch (plus to_ntt_no_reduce) only ~0.2% change
  (4.518 vs4.526s); REMOVED (not in final code).
- Width probe: all16 ell2block maxabs34.7M..40.5M exceeds signed26bit limit;
  all16 ell3blocks69.7M..70.7M need28bits. No24/26bit implementation retained.
  Probe logging REMOVED (not in final code).

Independent review required by runbook reviewer rule: agent packing_review
reviewed retained arithmetic/bounds/unsafe-load/API changes. Found public FFT
helper unsigned subtraction overflow for n8,d2,q16; fixed rotation normalization
and added known-answer debug regression. Reviewer independently reran and
approved after fix. No further blockers. This is implementation review, not
cryptographic production-profile approval.

Tests so far: full reinspiring debug passed, IPIR native flow3tests passed,
scoped reinspiring/ipir allfeature Clippy passed. Broad workspace Clippy has
pre-existing nullifier-pir Backend large_enum_variant warning; not modified.
Final CI-equivalent checks now run after latest-main merge on Intel.

LIVE FINAL RUN:
- /root/run-final.sh (local report run-final.sh)
- PID **21866** on host603320067, 178.62.223.36; confirmedlive at00:27.
- /root/results/final-driver.log, logs/results /root/results/final/
- Script reverses widthprobe.patch, applies final.patch (b308543..8866066).
- Runs fmt/doc/Clippy/check/allfeature tests, explicit degree2048 release,
  release reinspiring suite, benchmark compilation, then freezes binaries.
- Paired3repeat packing b16/b1, ell2/3,8workers; serial-vs-batch ell2;
  secondary1worker fixtures; complete 1.75GiB fullwire baseline/final3pairs;
  actual InspiRING/odd rewrite/native packing_compare1/8workers3repeats.
- Script final marker /root/results/final/complete; do not treat elapsed timeout
  as terminal. Poll PID/logs first. May need fix build/test failure before runs.
- Existing previous processes packed2818800,trace19374,scratch20488,
  widthprobe21318 are finished. All raw results still onhost.

Unfinished: final job validation, fixture/ciphertext hash pair verification,
final report+raw SHA verification, remaining required test/doc fixes if any,
publish origin HEAD:cursor/reinspiring-packing-c201 and updatePR17 main/draft,
follow CI (now runner queue cleared), deleteONLYdroplet603320067 and confirm.
Goal stays ACTIVE. Do not claim completion or stop at provisional measurements.

Latest checkpoint:
- Published reviewed implementation+mainmerge **8866066** to origin PR17
  cursor/reinspiring-packing-c201; keepdraft/main. New CI running: pushrun
  36013082365 portable SUCCESS, tests IN_PROGRESS; duplicate PRrun36013091626
  queued. Do not mistake priorcf6a green checks for new head checks.
- Final Intel fmt/docs/Clippy/check, complete allfeature tests incl newlymerged
  simplepir-kernel, explicit release degree2048 (14.30s), release reinspiring,
  both benchmark compile checks ALL PASSED. Frozen binary build completed.
- Intel lscpu confirms avx512f,dq,bw,vbmi; Packed28 storage used in fixtures.
- Mac final scopedallfeature Clippy/docs and both native_flow suites PASSED.
- First1and16block before/after pairs exact fixtureSHA and all30ciphertextSHA
  MATCH. Final analyze.py will verify ALL shapes/workers/repeats and fullwire
  phase errors once complete. Script syntax validated only, not yet fullrun.
- Remotefinal PID21866 confirmedlive at08:25 with30packingfiles collected.
  Still running1worker and thenfullwire/actualInspiring runs; no concurrent
  remote builds or extra benchmarks. Do not restart.
- Three completed8worker ell2 groups (seconds): baselinec1
  [21.560892489,21.531537339,21.515678585], finalc1
  [9.98079485,9.999106116,10.310851226], baselinec8
  [8.320097507,8.303232135,8.314955008], finalc8
  [4.538130322,4.550214809,4.534336971]. Finalc8 online medians
  [8.498208,8.503469,8.587277]ms vsbaselinec8
  [12.315272,12.388428,12.689825]ms.
- Documentation updates README/SECURITY/SPEC are UNCOMMITTED; benchmark report
  directory untracked. ReportREADME is placeholder explicitlyinprogress.
  REVIEW.md archives independent review; analyze.py validates exact groups.
  raw-experiments copied (~816KiB), raw-final currently ONLY completedlogs+
  environmentmetadata. Mustcollect fullraw and verifyagainstremoteSHA before
  destroying host. Hoststilllive; finalruncompletion notyetobserved.
- Note freshmain brings CUDA checks; GPUtests intentionallyignored onCPUhost.
- Need finishfinalreport includingactualInspiring and singlethreadpapercontext,
  retainedvspeakmemory, batchingtradeoff, splitworkerlatency limits and rejected
  candidates. Do not claim fullprotocol2x orcryptographicapproval. Native
  productiongates documented in SECURITY remainunchanged.

## Final completion update (supersedes earlier pending state)

- Published arithmetic through 6c1aabc: adaptive exact27/28-bit coefficients,
  eight-row SIMD with four-row fallback, shared per-request key transforms,
  split pending-pack API and bounded setup concurrency. Main1d8aea3 incorporated.
- All final27 and final8 cohorts complete. Three row-layout pairs select eight
  rows (8.640 -> 8.074ms median); exact outputs match for all450 trial queries.
- Final8 full database:18.101ssetup,7.933mspacking,34.767msscan,44.773msserver.
  ActualInspiring2.369ms vsnative2limb0.923ms forhot singleblock8workers.
- Required independent reviewer approves retained implementation. Intel expanded
  SIMD tests, Clippy and integration pass; fullwire first/middle/last rows pass.
- All403remoteartifacts SHA256verified, plus11frozenbinariesand sourcepatch.
  All451sourcefiles match6c1aabc. Rawdata and reproducibleanalyses archived.
- Droplet603320067 deleted; successfulDOlist confirmsabsence.
- completion.json records source-CI evidence; final report publication CI is
  followed separately to avoid self-referential artifact commits.
