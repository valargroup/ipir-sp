# Can recent PIR work cut IPIR+SP upload by 2× or more?

Date: 2026-10-08. Scope: per-query upload (query + key material) at the deployed
nullifier shape, under the four hard constraints in the research brief.

Number labels:

- **[measured]**: ours, from this report's prototype runs or an earlier
  `bench-results/` report (cited).
- **[paper]**: as reported by the paper.
- **[estimate]**: my calculation, with the inputs stated.

## Answer

**No published 2024–2026 scheme gets a 2× upload cut at our shape without
breaking a hard constraint.** Every scheme with a much smaller upload keeps
megabytes to gigabytes of per-client keys on the server, so the client becomes
stateful and its queries linkable. The rest either fall below 128-bit security
or grow the download well past 25% (candidate table below).

**Changing our own parameters clears 2×, with no new hardness assumption.**
Three stacked changes do it:

1. **Small entries.** Store each database entry as 4 bits instead of 14–16, and
   make rows 4× wider so a row still holds a whole bucket.
2. **Radix samples.** Put two rows into one query sample, at two scales.
3. **One-digit packing key.** Cut K_g to a single approximate gadget digit, which
   the larger noise margin of small entries pays for.

Measured at full size on the native two-mask path, with 20-bit published masks:

| | Today (production) | 4-bit entries | + radix samples | + 1-digit K_g |
|---|---:|---:|---:|---:|
| Upload per query | 236,544 B | **98,340 B (2.41×)** | 75,300 B (3.14×) [estimate] | **61,476 B (3.85×)** |
| Download per query | 81,920 B | 81,988 B | 81,988 B | 81,988 B |
| Total per query | 318,464 B | 180,328 B (1.77×) | 157,288 B (2.02×) | 143,464 B (2.22×) |
| Public masks per snapshot (one-time) | 229,376 B | 655,396 B | 655,396 B | 655,396 B |
| Certified decryption failure (target 2^-128) | — | ≤ 2^-536 | — | ≤ 2^-604 |
| Server, M4 Max, 8 workers | — | 93.2 ms | — | 47.9 ms |
| Server, Xeon 8358 [estimate] | 122 ms [measured] | ~210 ms | — | ~115 ms |
| Lattice security, MATZOV / core-SVP | 2^131.2 / 2^103.4 | 2^136.8 / 2^109.5 | same | same |

Notes:

- The "+ radix samples" column keeps the 2-digit K_g. Its upload comes from
  the measured byte layout; it was not run end to end.
- "+ 1-digit K_g" means radix samples and the one-digit key together.
- Measured rows come from `prototype/`.
- The Xeon times are scaled from measured per-host ratios (see recommendation 1).
- Security was re-estimated with lattice-estimator `53da598` on the exact
  instances, which the changes leave as they are (`security/estimates-ours.jsonl`).

What this costs:

- **One-time snapshot download.** The public masks grow from about 230 KB to
  655 KB. A wallet that makes one query per snapshot moves more bytes in total.
  Break-even against production is about 2.4 queries per snapshot for the full
  stack and 3.1 for 4-bit entries alone.
- **Packing work.** There are 4× as many packing blocks: 64 instead of 16.
- **Server memory.** Retained packing data grows from 0.54 GB to 2.15 GB.
- **Experimental status.** All of this sits on the experimental native profile.
  It still needs the KDM review that `reinspiring/SECURITY.md` requires.

## The baseline

| Item | Bytes | Source |
|---|---:|---|
| First-dimension query: 28,672 rows × 42 bits | 150,528 | repo README [measured] |
| Packing keys K_g, K_h: 2 × 3 digits × 2048 × 56 bits | 86,016 | repo README [measured] |
| **Upload** | **236,544** | |
| Download: 16 blocks × 2048 × 20 bits | 81,920 | repo README [measured] |
| Published c1 masks, once per snapshot: 32,768 × 56 bits | 229,376 | `2026-09-04-key-reuse` [measured] |
| Native two-mask (#24), upload / download / masks | 203,300 / 90,180 / 237,604 | `2026-09-25-no-extra-download` [measured] |

A 2× cut means upload ≤ 118,272 B with download ≤ 102,400 B. The query is 64% of
the upload, and deleting every key byte would give only 1.57×. So the query
itself has to shrink.

## Why the query resists compression

The query gives the server one encrypted number per database row. The server
multiplies each row by its number and adds the rows up. Three facts set the
query's size.

1. **The random part (mask) of the query must be public and fixed.** That is
   what lets the server precompute DB^T·A once per snapshot, and lets InspiRING
   move its mask work offline. So only the 28,672 bodies are sent.

2. **Server-side expansion does not help.**
   - Automorphisms, key switching and multiplication by plaintext are all linear
     in the plaintext. A linear map cannot turn 2,048 uploaded slots into a
     28,672-long one-hot vector (a rank argument).
   - A multiplicative step (RGSW, tensoring) can, but it makes the mask depend on
     the query. The server would then multiply the database by that mask online,
     and InspiRING's offline work would no longer apply.
   - With unstructured LWE masks, that online product costs about d = 2048 times
     today's scan.
   - With ring-structured masks (Spiral, Respire, OnionPIR) it costs about two
     NTT-domain products per database coefficient: 114–393 MB/s per core
     [paper], against 2.4–13.6 GB/s for SimplePIR-style scans [paper, YPIR
     Table 5]. Those schemes also need megabytes of per-client keys.
   - InsPIRe's polynomial evaluation is the one published way around this. It
     applies an RGSW after the scan to t-times-fewer rows. The price is t× the
     packing work and a query-dependent response mask, which loses the
     published-mask trick and roughly doubles the download.

3. **Each body needs enough bits.**
   - Rounding a body to b_q bits adds an error of about q/2^{b_q}.
   - The scan multiplies that error by database entries up to p and sums it over
     R rows. The total must stay under the decryption threshold q/(2p).
   - So b_q ≈ 2·log2 p + ½·log2 R + margin. `ipir-sp/src/modulus_switch.rs:35`
     uses this rule (42 bits at p=2^14). The native certificate charges the same
     term as a worst-case L1 bound (49 bits at p=2^16).

That leaves three levers: fewer rows, fewer bits per row, and fewer key bytes.

- **Fewer rows** means wider records, which costs download unless the response
  gets denser.
- **Fewer bits per row** comes mostly from a smaller p. That changes b_q by a
  factor rather than a few bits (49 → 23 bits at p = 2^16 → 2^4).
- **The response stays the same size.** A smaller p does not grow the response,
  because the response rate improves: 4/5 bits per coefficient at p=2^4, against
  14/20 today.
- **Why papers kept p large.** Each smaller p multiplies the number of LWE
  outputs to pack. ReinspiRING's cheap per-block packing (0.2–0.8 ms on 8
  cores) is what makes that affordable.

## Candidate table

The shape for all estimates is the deployed one: 1.6 GB, one 57 KB record per
query, 8-core AVX-512.

- "Per-client keys" means reusable keys the server stores for each client, so
  the client is stateful and its queries are linkable.
- "[ours]" in the security column means re-run with lattice-estimator `53da598`.
  It reports MATZOV / ADPS16 core-SVP, taking the best of primal uSVP, primal BDD
  and dual hybrid (`security/`).

| # | Candidate (source) | Core idea | Upload | Keys (in upload) | Download | Total | Online server | Security / assumptions | Client state | Complexity | Fit |
|---|---|---|---:|---:|---:|---:|---|---|---|---|---|
| 0 | **Today**: IPIR+SP production | YPIR+SP scan + InspiRING | 236,544 [measured] | 86,016 | 81,920 | 318,464 | 122 ms, 8358 [measured] | 2^131.2 / 2^103.4 [ours]; KDM-RLWE (scaled automorphisms) | none | — | — |
| 1 | **4-bit entries, native two-mask** (this report; packing from ReinsPIRe ePrint 2026/1934) | small p, 4× wider rows, 23-bit query, 5-bit response | **98,340** [measured] | 27,648 | 81,988 | 180,328 | 93 ms M4 [measured]; ~210 ms 8358 [estimate] | 2^136.8 / 2^109.5 [ours]; same native assumption | none (655 KB public masks per snapshot) | M | partial |
| 2 | **#1 + radix samples** (this report; derived during the survey) | two 4-bit rows per sample at scales q/16 and q/4096 | 75,300 [estimate] | 27,648 | 81,988 | 157,288 | ~115 ms 8358 [estimate] | as #1 | none | M | partial |
| 3 | **#2 + 1-digit K_g** (approximate gadget: ReinsPIRe App. E.1, InsPIRe App. G.1) | small p frees noise budget for ℓ=1 | **61,476** [measured] | 13,824 | 81,988 | 143,464 | 47.9 ms M4 [measured]; ~115 ms 8358 [estimate] | as #1; fewer key samples | none | S on top of #2 | partial |
| 3b | #3 + dithered query rounding (this report) | client rounds with private coins, so a Hoeffding bound replaces the L1 bound | ~57 KB [estimate] | 13,824 | 81,988 | ~139 KB | as #3 | as #1 (post-processing) | none | S | partial |
| 4 | Production one key, 2 approximate digits (InsPIRe ePrint 2025/1352 §3.3, App. G.1) | fewer key bytes only | 179,200 [estimate] | 28,672 | 81,920 | 261,120 | ~120 ms | as #0 | none | S | drop-in |
| 5 | #1 + #4 on production InspiRING (odd q) | reshape without the native backend | ~99,400 [estimate] | 28,672 | 81,920 | ~181,300 | ~360 ms 8358 [estimate] | 2^131.2 / 2^103.4 [ours] | none | M | partial |
| 6 | InsPIRe polynomial evaluation, t=4–16 (ePrint 2025/1352, S&P 2026) | DB column holds t entries; one RGSW selects | 121–149 KB with 2-digit gadget [estimate from paper sizes] | ~57 KB + RGSW | ~192 KB (×2.4; mask becomes query-dependent) [estimate] | 270–340 KB | ~270 ms (t=4) to ~1.1 s (t=16) [estimate] | 128-bit [paper]; KDM + RGSW | none | L | partial |
| 7 | ReinsPIRe as published (ePrint 2026/1934) | native q, compiled packing | 234–546 KB at 1 GB [paper, Table 6] | 52 KB | 12 KB at 1 GB, small records [paper] | — | 5.9 GB/s/core [paper] | code: q=2^52 ternary → 2^134.1 / 2^105.7 [ours] | none | — | already implemented here |
| 8 | Spiral / SpiralPack (ePrint 2022/368, S&P 2022) | query expansion + RGSW folding | 14 KB [paper] | + 17–47 MB per client | 188–242 KB [paper] | — | 4.6–4.9 s 1T [paper] | 128-bit [paper]; KDM | **per-client keys** | L | rewrite |
| 9 | Respire (ePrint 2024/1165, CCS 2024) | ring-switched compressed queries | 7.7 KB at 1 GB, 256 B records [paper] | + 3.9 MB per client | 2 KB [paper] | — | 3.48 s 1T [paper] | 128-bit [paper]; KDM, 2Q samples | **per-client keys** | L | rewrite |
| 10 | OnionPIRv2 (ePrint 2025/1142) | BFV + RGSW external products | 64 KB [paper] | + 2.9 MB | 57 KB at 22.5 KB records | — | ~1.3 s 1T [paper] | **~113-bit** [paper] | per-client keys | L | rewrite |
| 11 | VIA / VIA-C (ePrint 2025/2074, S&P 2026) | MLWE rank halving, ring switching | 473 KB / 0.57 KB [paper, 1-byte records] | + 14.8 MB (VIA-C) | 15.5 KB | — | 0.44 s [paper] | **110-bit** [paper]; a third-party re-estimate of the implementation gives 72–88 bits | VIA-C per-client | L | rewrite |
| 12 | KsPIR (CCS 2024) | key-switching expansion | 932 KB stateless, 140 KB stateful [paper, 8 KB records] | 2.3 MB stateless | 26 KB | — | 487 ms 1T | 128-bit [paper]; sparse ternary secret | stateful variant | L | rewrite |
| 13 | HintlessPIR (ePrint 2023/1733, CRYPTO 2024) | homomorphic hint compression | 1.5 MB at 8.6 GB [paper] | 360 KB | 3.0 MB | — | 1.35 s 1T | 128-bit [paper] | none | L | rewrite |
| 14 | SandwichPIR (ePrint 2026/1816) | InsPIRe packing on GPU tensor cores, p=2^8 | ~176 KB on CPU [estimate] | 32 KB | ×1.6–2.4 [estimate] | — | 3.4 ms, GPU only [paper] | q=2^32, σ=0.5 → 2^192.7 / 2^168.0 [ours] | none | L | rewrite |
| 15 | NTPIR (ePrint 2026/1910, CCS 2026) | RLWE → NTRU response | — | 512–656 KB per query [paper] | 1 ring element | — | 1.8× faster than InsPIRe⁽²⁾ [paper] | NTRU at q=2^45 (possibly overstretched); circular | none | L | rewrite |
| 16 | DNSPIR (ePrint 2026/1872) | single σ₅ Galois key, modulus-switched key | 52 KB at 2.7 GB, 2.5 KB records [paper artifact] | 26 KB | 22 KB | — | 1.3 s on 8 threads [paper] | **sparse h=128 → 2^127.7 / 2^99.4 [ours]** | none | L | idea only |
| 17 | SkrrtPIR (ePrint 2026/2385, Oct 2026) | single Galois key, cyclic unpacking, batch PIR | no numbers yet | — | — | — | — | not stated | none | ? | watch |
| 18 | Session/epoch key reuse (our #13/#16 prototype; Spiral/Respire model) | send keys once per batch | 161–172 KB warm [measured] | amortized | 81,920 | 243–254 KB warm; worse cold | unchanged | KDM with more samples; **no protection against a malicious server** (SimplePIR App. B) | batch secret | S (exists) | already tried |

How to read the rows:

- **#1–#3 and #5** change our own parameters; nothing like them was found in the
  literature.
- **#4** is known but not yet in production.
- **#6, #14, #15, #16 and #17** are partial ideas.
- **#8–#13** break statelessness, security or the download limit.

## Top 3 recommendations

The three recommendations stack. Each one is a separate decision.

### 1. 4-bit entries on the native two-mask path (the enabler)

**What changes.**

- The plaintext modulus goes from p = 2^16 to 2^4, and each 32-byte nullifier
  becomes 64 entries of 4 bits.
- A row holds 2,048 nullifiers: 131,072 entries, or 64 RLWE output blocks.
- 49,925,853 nullifiers then need 24,378 rows, padded to 24,576 (12 RLWE query
  polynomials).
- Query bodies are sent at 23 bits and response bodies at 5 bits.
- Keys are the shipped two-mask K_g: 2 digits, base 2^19.

**Byte math** [measured, `prototype/e2e-p4.jsonl`, `prototype/e2e-p4-l2-m20.jsonl`]:

- Upload = 36 header + 27,648 key + 24,576 × 23 bits (70,656) = **98,340 B**.
  That is 2.41× below production (236,544) and 2.07× below native today
  (203,300).
- Download = 68 header + 131,072 × 5 bits (81,920) = **81,988 B**. That is +0.08%
  against production and −9% against native.
- Published masks, once per snapshot, at 2 masks × 131,072 coefficients:

  | Mask precision | Bytes | Correctness |
  |---|---:|---|
  | 27 bits (today's API floor) | 884,772 | certified ≤ 2^-209,629 (`cert-p4.json`) |
  | 20 bits | **655,396** | certified ≤ 2^-536 (`cert-p4-l2-m20.json`) |
  | 19 bits | 622,628 | screen only, ≤ 2^-138 |
  | 18 bits | — | fails the screen (2^-32) |

**Why the download doesn't grow.** The response rate improves from
14/20 = 0.70 (16/22 = 0.73 for native) to 4/5 = 0.80. With p this small, the
noise is tiny next to q/(2p), so one spare bit per coefficient covers the
rounding.

**Noise budget** [measured, `prototype/cert-p4.json`].

- The decryption radius is q/(2p) = 2^49 (today it is 2^37).
- Deterministic charges total 2^48.78:
  - response rounding: q/2^6 = 2^48
  - query rounding: worst-case column L1 × q/2^24 ≈ 2^47.5
  - D.1 division: 2^28
- That leaves 2^46.2 for the random terms. Their standard deviation is
  about 2^32.6, so there are about 14 spare bits.
- Recommendations 2 and 3 spend those spare bits.

**Security.** Unchanged at 2^136.8 MATZOV / 2^109.5 core-SVP [ours].

- The lattice instances are the same: n=2048, q=2^54, σ=6.4, Gaussian secret.
  p does not enter the estimate.
- The 23-bit query is a deterministic rounding of an LWE sample. Anything that
  distinguishes it also distinguishes the full-precision sample, the same
  argument as `modulus_switch.rs:58`.

**Server cost.**

Quiet M4 Max runs against a matched baseline [measured,
`prototype/e2e-p4-l2-m20.jsonl` and `prototype/e2e-baseline-p16.jsonl`]. The
baseline is today's native p16 two-mask with 29-bit masks. 8 workers, medians.

| | Baseline | 4-bit entries |
|---|---:|---:|
| Server | 26.4 ms | 93.2 ms |
| Scan | 22.3 ms | 78.9 ms |
| Packing | 3.26 ms | 13.6 ms |
| Client generation | 20.1 ms | 25.1 ms |
| Client decode | 0.20 ms | 0.77 ms |
| Offline setup | 13.6 s | 45.8 s |
| Retained packing data | 0.54 GB | 2.15 GB |

The scan costs 3.54× for 3.43× the entries; packing costs 4.2× for 4× the blocks.

Projection to the Xeon 8358 [estimate]. Host ratios come from
`2026-09-24-reinspiring-perf`: the 8358 is 1.13× slower than the 6548N on the
scan and 1.35× slower on packing.

- Scan: 34.3 ms × 3.54 × 1.13 ≈ 137 ms.
- Packing: 12.25 ms × 4.16 × 1.35 ≈ 69 ms.
- Total: about 210 ms, against a 500 ms budget.
- The prototype reuses today's u16 scan kernel. A 4-bit layout keeps the
  database at the same 1.6 GB of bits and needs 3 query digits instead of 7.

**Code changes:**

- `ipir-sp/src/native.rs`:
  - Make the query and response widths profile parameters, derived from
    (p, rows) through the certificate. Today they are fixed at `49` and
    `log p + 6`.
  - Raise the rows × cols ≤ 2^30 guard (here it is 3.2·10^9).
  - Lower the two-mask published-mask floor.
- `reinspiring/src/noise.rs`: export mask screens below 27 bits.
- `reinspiring/tools/security/certify_native.py`: generalize p and the
  query/response widths (8 lines in `prototype/prototype.diff`).
- nullifier-pir and wallet-pir encoders: 4-bit digits, 2,048 nullifiers per row.

**Risks:**

- **Cold clients.** A client downloads 655 KB of masks per snapshot instead of
  about 230 KB. Against production that breaks even at 3.1 queries per snapshot.
- **Server resources.** Offline setup takes 3.4× longer on the M4 Max
  [measured]. On the 8358 that is an estimated 2–3 minutes per snapshot,
  scaling the 6548N's 36.7 s native setup. Radix samples cut the ratio to 2.3×.
  Retained memory grows by 1.6 GB.
- **Native review.** The native KDM review gate still applies.
- **Fixture-only certificate.** As with every certificate in the repo, it covers
  only the synthetic fixture.

### 2. Radix samples: two 4-bit rows per query sample

**What changes.**

- Group rows in pairs. The server stores the merged entry c = D0 + 256·D1
  (12 bits, still u16).
- The client puts its one-hot selector at scale q/16 when it wants row D0,
  and at q/4096 when it wants row D1.
- Multiplying the selected sample by c gives:
  - **D0 selected:** D0·q/16, plus D1·16q ≡ 0 mod q, so the other row vanishes.
  - **D1 selected:** D1·q/16, plus D0·q/4096. The second term is a
    lower-digit residue of at most 15·q/4096 = Δ/17.
- The hint DB^T·A, InspiRING/ReinspiRING packing and the response format are
  unchanged.

The idea came out of the query-compression survey as an unverified derivation.
I checked it algebraically and validated it end to end below.

**Byte math** [measured for 1-digit K_g, `prototype/radix-l1-m20.jsonl`]:

- 12,288 merged rows × 31 bits = 47,616 B, which is 15.5 bits per logical row
  (23 before).
- Upload with 1-digit K_g = 36 + 13,824 + 47,616 = **61,476 B (3.85×)**.
- Upload with 2-digit K_g = 36 + 27,648 + 47,616 = 75,300 B (3.14×) [estimate].
- Download is unchanged at 81,988 B.

**Noise** [measured, `prototype/cert-radix-l1-m20.txt`]:

- Deterministic terms total 2^48.69:
  - response rounding: 2^48
  - query rounding: 12,288 rows × 12-bit entries × q/2^32 ≈ 2^46.6
  - lower-digit residue: 15·2^42 ≈ 2^45.9
- The certificate is ≤ 2^-604 at 20-bit masks with 1-digit K_g. It was computed
  by `prototype/certify_radix.py` on a conservative fixture: uniform 12-bit
  entries, which over-bound the merged entries.
- All 13 measured queries decode both row positions correctly. The worst phase
  error is 2^48.04, against a radius of 2^49.

**Server** [measured, M4 Max, 8 workers]:

- Server 47.9 ms: scan 38.6 ms (half the entries of recommendation 1) and
  packing 8.65 ms.
- Offline setup 31.5 s.
- Xeon 8358 [estimate]: scan 34.3 ms × 1.73 × 1.13 ≈ 67 ms, plus packing
  ≈ 44 ms, for about **115 ms**. That is roughly today's production time.

**Code changes:**

- `encrypt_selection`: set the selection scale from the target's position in its
  pair. The prototype does this with `PROTO_SEL_SHIFT`; production code would
  derive it.
- A profile split between "storage p" (2^12, used for entry and hint bounds) and
  "decode p" (2^4).
- Merged encoding in the encoders.
- Digit extraction in the decoder: round((v − 8)/256) mod 16.
- A residue term in the certificate.

**Risks:**

- This is a new, unpublished construction and needs review. The algebra is
  short, but nobody else has checked it.
- The lower-digit residue depends on the database. It is bounded
  deterministically, not argued to be random.
- Three rows per sample would save about 9 KB more. But merged entries would
  reach about 20 bits (u32 storage, a 4.3 GB database), so I stopped at two.

### 3. One-digit K_g (and dithered query rounding)

**What changes.** K_g becomes a single approximate digit, base 2^27, with
27 low bits discarded.

- `NativeParams::new` rejects this today: it caps the base at 24 bits and the
  discarded bits at 24. The prototype relaxes the caps to 28 and 32.
- It is ReinsPIRe's and InsPIRe's approximate gadget taken down to ℓ = 1.
- At p = 2^16 it could not be certified; the upload-search report's best screen
  was 2^-18. At p = 2^4 the decryption radius is 4,096× larger.

**Byte math** [measured]:

- Key upload drops 27,648 → 13,824 B (−13,824 B).
- With 4-bit entries alone: 84,516 B (2.80×), `prototype/e2e-p4-l1.jsonl`.
- With radix samples too: 61,476 B (3.85×), as above.

**Noise** [measured]:

- Certified ≤ 2^-421 at 20-bit masks with 4-bit entries
  (`prototype/cert-p4-l1-m20.json`), and ≤ 2^-604 with radix samples.
- Phase error rises by about 2^41.4 over the 2-digit run, consistent with the
  model's σ ≈ 2^40.3.
- Packing gets faster: 8.9 ms against 13.6 ms on the M4 Max.

**Dithered query rounding** [estimate, not built]:

- The client rounds each body up or down with probability set by the
  fractional part, using its own coins. The per-row rounding errors then become
  independent, bounded and zero-mean.
- The certificate can then use a Hoeffding bound, roughly √(Σ DB²)·step, in
  place of the worst-case L1·step/2. That is about 20× smaller at R ≈ 24K, or
  about 3 query bits.
- This costs no security: the rounding uses randomness independent of the
  secret, so it is post-processing.
- It needs a new certificate family. Without radix samples, 23 → 20 bits saves
  9,216 B; with radix samples it saves a similar 3–4 bits per sample.

**Risks:**

- One-digit keys have not been reviewed.
- The residue term from discarded bits is 2^11× larger than with 2 digits. The
  certificate handles it with public weights, and margins stay above 2^-400.

### Not ranked: production InspiRING without the native backend

To stay on the odd-q backend, apply recommendation 1's layout there and port
InsPIRe's one-key partial packing (§3.3, the same idea as #24's two-mask) with
2 approximate digits at 56 bits (28,672 B) [estimate].

- **Upload:** about 99.4 KB (2.38×). With today's 86 KB of keys it would be
  156,672 B, only 1.51×, so the key change is required.
- **Server:** packing is about 2.85 ms per block on the 8358 (after #15), so
  ~182 ms for 64 blocks. The scan is about 178 ms. Total about 360 ms.
- **Status:** this is new cryptographic code on the production path, and it
  needs the certificate machinery that production lacks today.

## Rejected ideas

| Idea | Breaks | One-line reason |
|---|---|---|
| Spiral, SpiralPack, Respire, OnionPIRv2, KsPIR (stateful), VIA-C, Pirouette, Npir, NTRUPIR, VIPIR ExpPack, ZipPIR | Statelessness/privacy (2) | Small uploads come from MB–GB of per-client keys stored on the server. Queries become linkable, and a malicious server recovers a reused secret in ~log q crafted responses (SimplePIR, ePrint 2022/949, App. B). |
| Session/epoch key reuse for IPIR+SP (our #13/#16) | Privacy (2) against an active server | The proofs cover passive servers only. Even free keys would save ≤ 36%, and the cold total is worse (`2026-09-04-key-reuse`). |
| Long-lived packing secret + fresh query secret | Goal | Still needs about one key-switching matrix per query (same bytes as K_g), with no forward secrecy against an active server. |
| InsPIRe polynomial evaluation, t ≥ 4 | Download (≤ +25%); server time at t ≥ 16 | The response mask becomes query-dependent, so download grows about 2.4×; packing scales with t. |
| OnionPIR/OnionPIRv2, VIA | Security (1) | 111–113 and 110 bits [paper]. VIA's implementation was re-estimated at 72–88 bits in a public review thread. |
| DNSPIR parameters | Security (1); time (3) | The sparse h=128 secret estimates at 2^127.7 MATZOV [ours]; 1.3 s on 8 threads. |
| HintlessPIR | Download | 3 MB response at our record size [paper]. |
| SandwichPIR on CPU | Download | 8-bit plaintexts with its packing push download ×1.6–2.4 [estimate]; its speed needs a GPU. |
| NTPIR, other NTRU keys | Goal; extra assumption | NTRU keys cannot be seeded (512–656 KB per query), and NTRU at q=2^45 may be overstretched. |
| FrodoPIR, ChalametPIR, SimplePIR/DoublePIR hints, Piano, Plinko, RMS24 | Hints (4) | MB-scale client hints or client preprocessing. |
| DEPIR implementations (Lin–Mook–Wichs; Okada et al. FC 2024; ePrint 2026/243) | Server feasibility | TB-scale preprocessed storage, or seconds to minutes per batch. |
| Module-LWE keys, ring switching to d=1024, hybrid special-modulus key switching | Security (1) or goal | No saving at equal security, or the key modulus qP breaks the d=2048 cap. |
| Server-side query expansion with public masks (automorphisms, key switching) | Goal | Linear in the plaintext, so it cannot turn 2,048 slots into a 28,672-long one-hot. |
| RGSW/tensor index decomposition (row = i1 × i2) in the first dimension | Time (3) | Query-dependent masks on the database cost at least (R1+R2)·C·d MACs, about 24× today's scan at the best split. |
| LWR or trapdoor-compressed query bodies | Goal / privacy | LWR saves nothing (same rounding error). A public-A trapdoor known to clients lets anyone invert every query. |
| Shaving query bits at p = 2^14–2^16 | Goal | At most 3–4 bits per row (≤ 10%) under the deterministic certificate. |
| A ternary secret to buy noise margin | Security margin | Native ternary is 2^128.8 MATZOV: under 1 bit of margin (`reinspiring/SECURITY.md`). |
| Query expansion à la SealPIR/MulPIR | IP | Beyond the reasons above, Google's US11310045B2 covers RLWE ciphertext compression and expansion (heads-up, not legal advice). |

## Open questions and the smallest experiment for each

1. **Real Xeon timing.** Run the prototype on the dedicated Intel droplet used in
   `2026-09-24-reinspiring-perf`, built with `RUSTFLAGS='-C target-cpu=native'`.
   Run both
   `PROTO_QUERY_BITS=23 PROTO_RESPONSE_BITS=5 native_e2e 24576 131072 4 2 30 1 0 20`
   and `PROTO_QUERY_BITS=31 PROTO_RESPONSE_BITS=5 native_radix 12288 131072 1 27 33 20`.
   This settles the ~210 ms and ~115 ms estimates.
2. **Radix samples with 2-digit K_g.** One `native_radix` run with `2 19`. This
   confirms the 75,300 B row, which was not run end to end.
3. **19-bit masks.** They pass the screen at 2^-138. Regenerate the setup at
   19 bits and certify it, which saves 33 KB per snapshot. Below 19 bits, one
   more response bit (+16 KB per query) buys about 3 mask bits.
4. **Dithered rounding certificate.** Add a bounded-independent family to
   `certify_native.py` and rerun `native_noise` with 3 fewer query bits.
5. **The real snapshot.** Run `native_noise` on snapshot 3317500 encoded at
   4 bits (and merged for radix). Every certificate in the repo is fixture-only.
6. **A neighbouring p (2^3 or 2^5).** The model (`model/exact_shapes.py`)
   prefers 2^4 for the trade-off between upload and published masks; changing
   one argument checks a neighbour.
7. **A 4-bit scan kernel.** A microbenchmark in `simplepir-kernel` measures
   recommendation 1 without radix samples; radix samples already halve the
   entries.
8. **SkrrtPIR (ePrint 2026/2385).** It claims single-Galois-key unpacking with no
   stored client keys. The full text was not available on 2026-10-08.
9. **Application scope (outside PIR).** Do wallets need the whole 32-byte
   nullifiers, or would shorter fingerprints do for the membership check? A 4×
   smaller database would cut both directions by about 2× at the balanced
   shape.

## Evidence and reproduction

**Prototype** (`prototype/`):

- `prototype.diff` holds research-only changes against `d599987`, made in a
  throwaway worktree and **not for merging**:
  - env overrides for the query/response widths, p, gadget base and limb count
  - relaxed shape and gadget guards
  - mask screens down to 18 bits
  - a generalized certificate checker
  - the `native_radix` example
- `run_*.sh` hold the exact commands. Their outputs are `noise-*.json`,
  `cert-*.json`/`.txt` and `e2e-*.jsonl`/`radix-*.jsonl`.
- Host: Apple M4 Max, 128 GB, Rust 1.89, 8 Rayon workers.
- Fixture: synthetic database seed 0x2417, setup `[7;32]`, snapshot `[19;32]`.

**Model** (`model/`):

- `smallp_model.py` and `exact_shapes.py` model bytes and noise.
- They are calibrated to the repo's 29-bit two-mask certificate. They reproduce
  the accepted 49/29-bit profile and the rejected 28-bit masks.
- They predicted 23-bit queries, 5-bit responses and a 19-bit mask floor before
  the measurements confirmed them.

**Security** (`security/`):

- lattice-estimator `53da598` on SageMath 10.9.
- `estimates-ours.jsonl` reproduces the repo's 2^131.2 and 2^136.8 exactly.
- `estimates-literature.jsonl` covers the flagged paper parameters.

**Literature:** four survey passes on 2026-10-08.

- ePrint PDFs sat behind a bot check. Full texts came from mirrors, author
  pages, USENIX/PoPETs and arXiv.
- Read as abstracts only: ReinsPIRe (code read instead), NTPIR, Atom, YsPIR and
  SkrrtPIR.
- The InsPIRe copy read predates its August 2026 revision.
