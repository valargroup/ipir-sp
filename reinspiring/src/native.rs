//! Native-modulus ReinspiRING (Algorithms 1–2, Appendices C and D.1–D.2).
//!
//! This is an experimental cryptographic profile: Gaussian and ternary secret
//! configurations are distinct. Neither inherits the security claims of the
//! odd-modulus InspiRING profile. Ciphertext convention is b + a*s = Delta*m+e.
use crate::{
    compile::{collapse_kg_exponents, compile_fast, tau_coeffs},
    error::ReinspiringError,
    lift_ntt::{centered, LiftContext, PreparedLiftOperand, PreparedLiftRight},
    matrix::PackingMatrix,
    native_matrix::NativeMatrix,
};
use rand_chacha::{
    rand_core::{RngCore, SeedableRng},
    ChaCha20Rng,
};
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use spiral_rs::discrete_gaussian::DiscreteGaussian;
use std::time::{Duration, Instant};

/// Separate sampler identifiers; these are cryptographic profile properties.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecretDistribution {
    /// Same discrete Gaussian standard deviation (6.4) as current IPIR-SP.
    Gaussian,
    /// Uniform ternary secret for the paper's Lemma 10 research configuration.
    TernaryResearch,
}

/// Validated immutable native profile. All native profiles remain experimental.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeParams {
    d: usize,
    q: u64,
    p: u64,
    bits: u32,
    ell: usize,
    dropped: u32,
    sampler: SecretDistribution,
}
impl NativeParams {
    /// Validate bounded allocations, decomposition, and lift capacity.
    pub fn new(
        d: usize,
        q_bits: u32,
        p_bits: u32,
        bits: u32,
        ell: usize,
        sampler: SecretDistribution,
    ) -> Result<Self, ReinspiringError> {
        if !(2..=2048).contains(&d)
            || !d.is_power_of_two()
            || !(16..=56).contains(&q_bits)
            || p_bits == 0
            || p_bits >= q_bits
            || bits == 0
            || bits > 24
            || ell == 0
            || ell > 8
        {
            return Err(ReinspiringError::InvalidParams(
                "invalid native profile".into(),
            ));
        }
        let q = 1u64 << q_bits;
        let p = 1u64 << p_bits;
        let dropped = q_bits.saturating_sub(bits * ell as u32);
        if dropped > 24 {
            return Err(ReinspiringError::InvalidParams(
                "too many discarded gadget bits".into(),
            ));
        }
        LiftContext::new(d, q)?;
        Ok(Self {
            d,
            q,
            p,
            bits,
            ell,
            dropped,
            sampler,
        })
    }
    /// Degree-2048, q=2^54, z=2^19, p=2^14 packing research configuration.
    pub fn paper(ell: usize, sampler: SecretDistribution) -> Result<Self, ReinspiringError> {
        Self::new(2048, 54, 14, 19, ell, sampler)
    }
    /// Ring degree.
    pub fn d(&self) -> usize {
        self.d
    }
    /// Ciphertext modulus.
    pub fn q(&self) -> u64 {
        self.q
    }
    /// Plaintext modulus.
    pub fn p(&self) -> u64 {
        self.p
    }
    /// Gadget limb count.
    pub fn ell(&self) -> usize {
        self.ell
    }
    /// Number of low bits rounded away before signed decomposition.
    pub fn dropped_bits(&self) -> u32 {
        self.dropped
    }
    /// Secret sampler.
    pub fn sampler(&self) -> SecretDistribution {
        self.sampler
    }
    /// Stable profile encoding, included in setup and transport bindings.
    pub fn encoding(&self) -> Vec<u8> {
        let mut v = b"reinspiring-native-experimental-v1".to_vec();
        for x in [
            self.d as u64,
            self.q,
            self.p,
            self.bits as u64,
            self.ell as u64,
            self.dropped as u64,
            self.sampler as u64,
        ] {
            v.extend(x.to_le_bytes());
        }
        v
    }
    /// Deterministic D.1 bound conditional on ||s||_infinity <= secret_bound.
    /// Uniform ternary gives d^2. Gaussian production analysis must supply a
    /// justified tail bound (the current sampler has finite support <=65).
    pub fn division_error_bound(&self, secret_bound: u64) -> u128 {
        self.d as u128 * self.d as u128 * secret_bound as u128
    }
    /// Conservative total decomposition-rounding bound, excluding KS noise.
    pub fn decomposition_error_bound(&self, secret_bound: u64) -> u128 {
        if self.dropped == 0 {
            0
        } else {
            (self.d - 1) as u128
                * self.d as u128
                * (1u128 << (self.dropped - 1))
                * secret_bound as u128
        }
    }
    fn factor(&self, j: usize) -> u64 {
        let shift = self.dropped + self.bits * j as u32;
        if shift >= self.q.trailing_zeros() {
            0
        } else {
            1 << shift
        }
    }
}

/// Public packing masks, domain-separated from query and client randomness.
/// Seed-based construction prevents callers from injecting weak masks.
pub struct NativeSetup {
    params: NativeParams,
    id: [u8; 32],
    w: Vec<Vec<u64>>,
    v: Vec<Vec<u64>>,
}
impl NativeSetup {
    /// Expand canonical uniform masks using pinned ChaCha20 and low-bit sampling.
    pub fn new(params: NativeParams, seed: [u8; 32]) -> Self {
        let mut h = Sha256::new();
        h.update(params.encoding());
        h.update(b"/packing-masks/");
        h.update(seed);
        let id: [u8; 32] = h.finalize().into();
        let mut rng = ChaCha20Rng::from_seed(id);
        let mut draw = || {
            (0..params.ell)
                .map(|_| {
                    (0..params.d)
                        .map(|_| rng.next_u64() & (params.q - 1))
                        .collect()
                })
                .collect()
        };
        let w = draw();
        let v = draw();
        Self { params, id, w, v }
    }
    /// Profile used by this setup.
    pub fn params(&self) -> &NativeParams {
        &self.params
    }
    /// Public setup identifier.
    pub fn id(&self) -> [u8; 32] {
        self.id
    }
}

/// Secret coefficients have no Debug/Clone or serialization implementation.
pub struct NativeSecret {
    params: NativeParams,
    coeffs: Vec<u64>,
}
impl Drop for NativeSecret {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.coeffs.zeroize();
    }
}
impl NativeSecret {
    /// Sample a fresh secret from a cryptographic RNG; caller must seed it securely.
    pub fn sample(params: &NativeParams, rng: &mut ChaCha20Rng) -> Self {
        let dg = DiscreteGaussian::init(6.4 * std::f64::consts::TAU.sqrt());
        let coeffs = (0..params.d)
            .map(|_| match params.sampler {
                SecretDistribution::Gaussian => dg.sample(params.q, rng),
                SecretDistribution::TernaryResearch => loop {
                    let v = rng.next_u32();
                    if v < u32::MAX {
                        break match v % 3 {
                            0 => params.q - 1,
                            1 => 0,
                            _ => 1,
                        };
                    }
                },
            })
            .collect();
        Self {
            params: params.clone(),
            coeffs,
        }
    }
    /// LWE body encrypting m under a public mask. Noise is freshly sampled.
    pub fn encrypt_lwe(
        &self,
        a: &[u64],
        m: u64,
        rng: &mut ChaCha20Rng,
    ) -> Result<u64, ReinspiringError> {
        validate_poly(a, &self.params)?;
        if m >= self.params.p {
            return Err(invalid("plaintext out of range"));
        }
        let q = self.params.q;
        let dot = a
            .iter()
            .zip(&self.coeffs)
            .fold(0u64, |s, (&a, &b)| s.wrapping_add(a.wrapping_mul(b)))
            & (q - 1);
        let e = DiscreteGaussian::init(6.4 * std::f64::consts::TAU.sqrt()).sample(q, rng);
        Ok((m
            .wrapping_mul(q / self.params.p)
            .wrapping_add(e)
            .wrapping_sub(dot))
            & (q - 1))
    }
    /// Encrypt a one-hot selection over polynomial-block public query masks.
    pub fn encrypt_selection(
        &self,
        polys: &[Vec<u64>],
        target: usize,
        rng: &mut ChaCha20Rng,
    ) -> Result<Vec<u64>, ReinspiringError> {
        let p = &self.params;
        if polys.is_empty() || target >= polys.len().saturating_mul(p.d) {
            return Err(invalid("selection out of range"));
        }
        let lift = LiftContext::new(p.d, p.q)?;
        let dg = DiscreteGaussian::init(6.4 * std::f64::consts::TAU.sqrt());
        let mut out = Vec::with_capacity(polys.len() * p.d);
        for (block, poly) in polys.iter().enumerate() {
            validate_poly(poly, p)?;
            let inverse = tau_coeffs(poly, 2 * p.d as u64 - 1, p.q);
            let inner = lift.multiply(&inverse, &self.coeffs)?;
            for (i, x) in inner.into_iter().enumerate() {
                let selection = (p.q / p.p) & 0u64.wrapping_sub((block * p.d + i == target) as u64);
                out.push(selection.wrapping_add(dg.sample(p.q, rng)).wrapping_sub(x) & (p.q - 1));
            }
        }
        Ok(out)
    }
    /// Decode all packed coefficients; errors are measured separately with phase_error.
    pub fn decrypt(&self, ct: &NativeCiphertext) -> Result<Vec<u64>, ReinspiringError> {
        let phase = self.phase(ct)?;
        let delta = self.params.q / self.params.p;
        Ok(phase
            .into_iter()
            .map(|x| ((x + delta / 2) / delta) & (self.params.p - 1))
            .collect())
    }
    fn phase(&self, ct: &NativeCiphertext) -> Result<Vec<u64>, ReinspiringError> {
        if ct.params != self.params {
            return Err(invalid("ciphertext profile mismatch"));
        }
        let prod = LiftContext::new(self.params.d, self.params.q)?.multiply(&ct.a, &self.coeffs)?;
        Ok(prod
            .iter()
            .zip(&ct.b)
            .map(|(&a, &b)| (a + b) & (self.params.q - 1))
            .collect())
    }
    /// Maximum centered error relative to the expected encoded message.
    pub fn phase_error(
        &self,
        ct: &NativeCiphertext,
        expected: &[u64],
    ) -> Result<u64, ReinspiringError> {
        if expected.len() != self.params.d || expected.iter().any(|&m| m >= self.params.p) {
            return Err(invalid("invalid expected plaintext"));
        }
        Ok(self
            .phase(ct)?
            .iter()
            .zip(expected)
            .map(|(&x, &m)| {
                centered(
                    x.wrapping_sub(m * (self.params.q / self.params.p)) & (self.params.q - 1),
                    self.params.q,
                )
                .unsigned_abs() as u64
            })
            .max()
            .unwrap_or(0))
    }
}

/// Uploaded key bodies bound to a public mask setup; no client secret is retained.
pub struct NativeKeys {
    id: [u8; 32],
    kg: Vec<Vec<u64>>,
    kh: Vec<Vec<u64>>,
}
impl NativeKeys {
    /// Generate fresh noisy encryptions for the two automorphism keys.
    pub fn generate(
        setup: &NativeSetup,
        secret: &NativeSecret,
        rng: &mut ChaCha20Rng,
    ) -> Result<Self, ReinspiringError> {
        let p = &setup.params;
        if secret.params != *p {
            return Err(invalid("key profile mismatch"));
        }
        let lift = LiftContext::new(p.d, p.q)?;
        let dg = DiscreteGaussian::init(6.4 * std::f64::consts::TAU.sqrt());
        let mut bodies = |mask: &[Vec<u64>], g: u64| -> Result<Vec<Vec<u64>>, ReinspiringError> {
            let from = tau_coeffs(&secret.coeffs, g, p.q);
            mask.iter()
                .enumerate()
                .map(|(j, w)| {
                    let ws = lift.multiply(w, &secret.coeffs)?;
                    Ok((0..p.d)
                        .map(|i| {
                            from[i]
                                .wrapping_mul(p.factor(j))
                                .wrapping_add(dg.sample(p.q, rng))
                                .wrapping_sub(ws[i])
                                & (p.q - 1)
                        })
                        .collect())
                })
                .collect()
        };
        Ok(Self {
            id: setup.id,
            kg: bodies(&setup.w, 5 % (2 * p.d as u64))?,
            kh: bodies(&setup.v, 2 * p.d as u64 - 1)?,
        })
    }
    /// Canonical body words, in kg then kh limb order.
    pub fn words(&self) -> Vec<u64> {
        self.kg.iter().chain(&self.kh).flatten().copied().collect()
    }
    /// Parse a bounded canonical key payload under an explicit setup.
    pub fn from_words(setup: &NativeSetup, words: &[u64]) -> Result<Self, ReinspiringError> {
        let p = &setup.params;
        if words.len() != 2 * p.ell * p.d || words.iter().any(|&x| x >= p.q) {
            return Err(invalid("malformed native keys"));
        }
        let chunks: Vec<_> = words.chunks_exact(p.d).map(|x| x.to_vec()).collect();
        Ok(Self {
            id: setup.id,
            kg: chunks[..p.ell].to_vec(),
            kh: chunks[p.ell..].to_vec(),
        })
    }
}

/// Native coefficient-domain RLWE ciphertext, distinct from Spiral's NTT type.
pub struct NativeCiphertext {
    params: NativeParams,
    a: Vec<u64>,
    b: Vec<u64>,
}
impl NativeCiphertext {
    /// Canonical mask and body rows.
    pub fn rows(&self) -> (&[u64], &[u64]) {
        (&self.a, &self.b)
    }
    /// Construct from canonical bounded rows under an explicit profile.
    pub fn from_rows(
        params: &NativeParams,
        a: Vec<u64>,
        b: Vec<u64>,
    ) -> Result<Self, ReinspiringError> {
        validate_poly(&a, params)?;
        validate_poly(&b, params)?;
        Ok(Self {
            params: params.clone(),
            a,
            b,
        })
    }
}

/// Immutable public preprocessing. Online data cannot alter its mask trace.
pub struct NativePreprocessed {
    pub(crate) params: NativeParams,
    pub(crate) id: [u8; 32],
    pub(crate) a: Vec<u64>,
    pub(crate) h: NativeMatrix,
    pub(crate) leftover: PreparedLiftOperand,
    pub(crate) lift: LiftContext,
}

/// Offline stage durations, excluding caller-side database-hint construction.
#[derive(Clone, Copy, Debug)]
pub struct NativeBuildTiming {
    /// Auxiliary context construction and exact integer mask aggregation.
    pub aggregation: Duration,
    /// Public key-switch trace, including digit decomposition and final mask.
    pub trace: Duration,
    /// Matrix compilation, compact storage conversion and leftover preparation.
    pub compilation: Duration,
    /// Complete build, including input validation.
    pub total: Duration,
}

/// Request-local packing key preparation, shared across blocks from one setup.
/// Owns only uploaded ciphertext bodies, never a client secret. A dispatcher
/// must associate this object with the same request as its database scan.
pub struct PreparedNativeKeys {
    id: [u8; 32],
    y: Vec<u64>,
    kh: PreparedLiftRight,
}

/// Packing work that can finish before the database scan. The borrowed block
/// binds the result to its own published mask. Finishing consumes the object;
/// request routing/binding remains the responsibility of the caller.
pub struct PendingNativePack<'a> {
    pre: &'a NativePreprocessed,
    body: Vec<u64>,
}
impl PendingNativePack<'_> {
    /// Add the matching scan result and return the final ciphertext.
    pub fn finish(mut self, b: &[u64]) -> Result<NativeCiphertext, ReinspiringError> {
        validate_poly(b, &self.pre.params)?;
        for (dst, &x) in self.body.iter_mut().zip(b) {
            *dst = (*dst + x) & (self.pre.params.q - 1);
        }
        NativeCiphertext::from_rows(&self.pre.params, self.pre.a.clone(), self.body)
    }
}
impl NativePreprocessed {
    /// Prepare uploaded key bodies once for all blocks from this setup.
    pub fn prepare_keys(&self, keys: &NativeKeys) -> Result<PreparedNativeKeys, ReinspiringError> {
        if keys.id != self.id {
            return Err(invalid("packing setup mismatch"));
        }
        Ok(PreparedNativeKeys {
            id: keys.id,
            y: keys.kg.iter().flatten().copied().collect(),
            kh: self.lift.prepare_bounded_right(
                &keys.kh,
                (1u64 << (self.params.bits - 1)).min(self.params.q / 2),
            )?,
        })
    }

    /// Compute H'y and the leftover term without waiting for the scan result.
    pub fn prepare_pack(
        &self,
        keys: &PreparedNativeKeys,
    ) -> Result<PendingNativePack<'_>, ReinspiringError> {
        if keys.id != self.id {
            return Err(invalid("prepared packing setup mismatch"));
        }
        let mut body = self.h.multiply(&keys.y)?;
        let leftover = self.lift.sum_cached(&self.leftover, &keys.kh)?;
        for (dst, x) in body.iter_mut().zip(leftover) {
            *dst = (*dst + x) & (self.params.q - 1);
        }
        Ok(PendingNativePack { pre: self, body })
    }
    /// Compile a d-by-d LWE mask matrix using D.2 aggregation and D.1 rounding.
    pub fn build(setup: &NativeSetup, masks: &[Vec<u64>]) -> Result<Self, ReinspiringError> {
        Self::build_timed(setup, masks).map(|(pre, _)| pre)
    }
    /// Build ordered independent packing blocks with bounded scratch concurrency.
    /// The caller retains the input masks; at most `concurrent_blocks` builds
    /// run at once, each using the current Rayon pool. Zero is invalid.
    pub fn build_batch(
        setup: &NativeSetup,
        masks: &[Vec<Vec<u64>>],
        concurrent_blocks: usize,
    ) -> Result<Vec<Self>, ReinspiringError> {
        if concurrent_blocks == 0 {
            return Err(invalid("zero preprocessing concurrency"));
        }
        let mut result = Vec::with_capacity(masks.len());
        for batch in masks.chunks(concurrent_blocks) {
            let compiled: Result<Vec<_>, _> =
                batch.par_iter().map(|m| Self::build(setup, m)).collect();
            result.extend(compiled?);
        }
        Ok(result)
    }
    /// Compile with offline stage attribution; identical arithmetic to `build`.
    pub fn build_timed(
        setup: &NativeSetup,
        masks: &[Vec<u64>],
    ) -> Result<(Self, NativeBuildTiming), ReinspiringError> {
        let total_start = Instant::now();
        let p = &setup.params;
        let d = p.d;
        let q = p.q;
        if masks.len() != d {
            return Err(invalid("expected d mask rows"));
        }
        for row in masks {
            validate_poly(row, p)?;
        }
        let aggregation_start = Instant::now();
        let lift = LiftContext::new(d, q)?;
        let mut agg = aggregate_masks(masks, q)?;
        let aggregation = aggregation_start.elapsed();
        let trace_start = Instant::now();
        // Reorder odd exponents into left powers of 5, then their negatives.
        let mut slots = Vec::with_capacity(d);
        let mut g = 1usize;
        for _ in 0..d / 2 {
            slots.push(std::mem::take(&mut agg[(g - 1) / 2]));
            g = g * 5 % (2 * d);
        }
        g = 1;
        for _ in 0..d / 2 {
            let e = (2 * d - g) % (2 * d);
            slots.push(std::mem::take(&mut agg[(e - 1) / 2]));
            g = g * 5 % (2 * d);
        }
        let exponents = collapse_kg_exponents(d);
        let public_w = lift.prepare_public_dot(&setup.w, (1u64 << (p.bits - 1)).min(q / 2))?;
        let public_v = lift.prepare_public_dot(&setup.v, (1u64 << (p.bits - 1)).min(q / 2))?;
        let trace_half = |half: &mut [Vec<u64>],
                          exps: &[u64]|
         -> Result<Vec<Vec<Vec<u64>>>, ReinspiringError> {
            let mut digits = Vec::with_capacity(half.len() - 1);
            for (step, idx) in (1..half.len()).rev().enumerate() {
                let ds = decompose(&half[idx], p)?;
                // ds * tau(w) = tau(tau^-1(ds) * w). Only the public
                // digits change per step; w's auxiliary transforms are reused.
                let inverse =
                    spiral_rs::number_theory::invert_uint_mod(exps[step], (2 * d) as u64).unwrap();
                let unrotated: Vec<_> = ds.iter().map(|x| tau_coeffs(x, inverse, q)).collect();
                let update = tau_coeffs(&lift.public_dot(&public_w, &unrotated)?, exps[step], q);
                for (a, x) in half[idx - 1].iter_mut().zip(update) {
                    *a = (*a + x) & (q - 1);
                }
                digits.push(ds);
            }
            Ok(digits)
        };
        // The two collapse chains are independent until the final K_h step.
        let (left, right) = slots.split_at_mut(d / 2);
        let (left_digits, right_digits) = rayon::join(
            || trace_half(left, &exponents[..d / 2 - 1]),
            || trace_half(right, &exponents[d / 2 - 1..]),
        );
        let mut digits = left_digits?;
        digits.extend(right_digits?);
        let last = decompose(&slots[d / 2], p)?;
        let update = lift.public_dot(&public_v, &last)?;
        let a = slots[0]
            .iter()
            .zip(update)
            .map(|(&a, x)| (a + x) & (q - 1))
            .collect();
        let trace = trace_start.elapsed();
        let compilation_start = Instant::now();
        let blocks: Result<Vec<_>, _> = (0..p.ell)
            .into_par_iter()
            .map(|j| {
                let ts: Vec<_> = digits.iter().map(|x| x[j].clone()).collect();
                if d == 2 {
                    Ok(PackingMatrix::zero(d, d, q))
                } else {
                    compile_fast(&ts, &exponents, q)
                }
            })
            .collect();
        let h = NativeMatrix::from_blocks(blocks?)?;
        let pre = Self {
            params: p.clone(),
            id: setup.id,
            a,
            h,
            leftover: lift.prepare_public(&last)?,
            lift,
        };
        Ok((
            pre,
            NativeBuildTiming {
                aggregation,
                trace,
                compilation: compilation_start.elapsed(),
                total: total_start.elapsed(),
            },
        ))
    }
    /// Pack d bodies with validated uploaded keys. All arithmetic is deterministic.
    pub fn pack(&self, b: &[u64], keys: &NativeKeys) -> Result<NativeCiphertext, ReinspiringError> {
        validate_poly(b, &self.params)?;
        if keys.id != self.id {
            return Err(invalid("packing setup mismatch"));
        }
        let y: Vec<_> = keys.kg.iter().flatten().copied().collect();
        let mut out = self.h.multiply(&y)?;
        let leftover = self.lift.sum_prepared(&self.leftover, &keys.kh)?;
        for i in 0..self.params.d {
            out[i] = (out[i] + leftover[i] + b[i]) & (self.params.q - 1);
        }
        NativeCiphertext::from_rows(&self.params, self.a.clone(), out)
    }
    /// Read/XOR diagnostic for coefficient memory traffic; not a cryptographic checksum.
    pub fn matrix_read_checksum(&self) -> u64 {
        self.h.read_checksum()
    }
    /// Matrix-only operation for benchmark attribution.
    pub fn matrix_product(&self, keys: &NativeKeys) -> Result<Vec<u64>, ReinspiringError> {
        if keys.id != self.id {
            return Err(invalid("packing setup mismatch"));
        }
        self.h
            .multiply(&keys.kg.iter().flatten().copied().collect::<Vec<_>>())
    }
    /// Leftover-only operation for benchmark attribution.
    pub fn leftover_product(&self, keys: &NativeKeys) -> Result<Vec<u64>, ReinspiringError> {
        if keys.id != self.id {
            return Err(invalid("packing setup mismatch"));
        }
        self.lift.sum_prepared(&self.leftover, &keys.kh)
    }
    /// Retained coefficient storage, excluding auxiliary NTT tables and headers.
    pub fn coefficient_bytes(&self) -> usize {
        self.h.storage_bytes() + self.leftover.storage_bytes() + self.params.d * 8
    }
    /// Published c1 row; independent of the client's secret and uploaded bodies.
    pub fn mask(&self) -> &[u64] {
        &self.a
    }
}

/// Signed approximate gadget digits, least significant retained limb first.
/// Nearest rounding discards `dropped_bits`; ties round upward. Reconstruction
/// uses weights 2^(dropped_bits+j*bits), not the full-decomposition weights.
pub fn decompose(a: &[u64], p: &NativeParams) -> Result<Vec<Vec<u64>>, ReinspiringError> {
    validate_poly(a, p)?;
    let mut out = vec![vec![0; p.d]; p.ell];
    let z = 1i128 << p.bits;
    for (i, &a) in a.iter().enumerate() {
        let mut x = if p.dropped == 0 {
            a as i128
        } else {
            (a as i128 + (1i128 << (p.dropped - 1))) >> p.dropped
        };
        for limb in &mut out {
            let digit = (x + z / 2).rem_euclid(z) - z / 2;
            limb[i] = digit.rem_euclid(p.q as i128) as u64;
            x = (x - digit) / z;
        }
    }
    Ok(out)
}

// D.2 transposed ring FFT over *integers*. Intermediate coefficients need more
// than u64: d*q is 2^65 at the paper parameters. Integer lifts preserve the
// exact D.1 floor division; reducing mod q before dividing would be incorrect.
fn aggregate_masks(masks: &[Vec<u64>], q: u64) -> Result<Vec<Vec<u64>>, ReinspiringError> {
    let d = masks.len();
    // Each destination gets exactly one input here. Row-wise filling avoids
    // scattering writes across the entire integer matrix.
    let mut polys = vec![vec![0i64; d]; d];
    polys.par_iter_mut().enumerate().for_each(|(k, poly)| {
        for (j, row) in masks.iter().enumerate() {
            let c = if k == 0 {
                row[0] as i64
            } else {
                -(row[d - k] as i64)
            };
            poly[(j + k) & (d - 1)] = if j + k >= d { -c } else { c };
        }
    });
    bit_reverse_rows(&mut polys);
    let mut len = 2;
    // After a length-L stage, |coefficient| <= L*(q-1). Stay in i64 only
    // while that public worst-case bound fits, then widen before the next stage.
    while len <= d && (len as u128) * (q as u128 - 1) <= i64::MAX as u128 {
        let half = len / 2;
        let step = d / len;
        polys.par_chunks_mut(len).with_min_len(4).for_each(|block| {
            let (left, right) = block.split_at_mut(half);
            left.par_iter_mut()
                .zip(right.par_iter_mut())
                .enumerate()
                .with_min_len(16)
                .for_each(|(k, (u, v))| {
                    let rot = 2 * step * k;
                    let old = v.clone();
                    for ((u, v), &t) in u[..rot].iter_mut().zip(&mut v[..rot]).zip(&old[d - rot..])
                    {
                        *v = *u + t;
                        *u -= t;
                    }
                    for ((u, v), &t) in u[rot..].iter_mut().zip(&mut v[rot..]).zip(&old[..d - rot])
                    {
                        *v = *u - t;
                        *u += t;
                    }
                });
        });
        len *= 2;
    }
    let shift = d.trailing_zeros();
    if len > d {
        return Ok(polys
            .into_par_iter()
            .map(|poly| {
                poly.into_iter()
                    .map(|x| ((x >> shift) as u64) & (q - 1))
                    .collect()
            })
            .collect());
    }
    let mut wide: Vec<Vec<i128>> = polys
        .into_iter()
        .map(|poly| poly.into_iter().map(i128::from).collect())
        .collect();
    integer_ring_fft_wide(&mut wide, len);
    Ok(wide
        .into_par_iter()
        .map(|poly| {
            poly.into_iter()
                .map(|x| ((x >> shift) as u64) & (q - 1))
                .collect()
        })
        .collect())
}
fn bit_reverse_rows<T>(a: &mut [T]) {
    let n = a.len();
    let mut j = 0;
    for i in 1..n {
        let mut bit = n >> 1;
        while j & bit != 0 {
            j ^= bit;
            bit >>= 1;
        }
        j ^= bit;
        if i < j {
            a.swap(i, j);
        }
    }
}
fn integer_ring_fft_wide(a: &mut [Vec<i128>], mut len: usize) {
    let d = a.len();
    while len <= d {
        let half = len / 2;
        let step = d / len;
        a.par_chunks_mut(len).with_min_len(4).for_each(|block| {
            let (left, right) = block.split_at_mut(half);
            left.par_iter_mut()
                .zip(right.par_iter_mut())
                .enumerate()
                .with_min_len(16)
                .for_each(|(k, (u, v))| {
                    let rot = 2 * step * k;
                    let old = v.clone();
                    for ((u, v), &t) in u[..rot].iter_mut().zip(&mut v[..rot]).zip(&old[d - rot..])
                    {
                        *v = *u + t;
                        *u -= t;
                    }
                    for ((u, v), &t) in u[rot..].iter_mut().zip(&mut v[rot..]).zip(&old[..d - rot])
                    {
                        *v = *u - t;
                        *u += t;
                    }
                });
        });
        len *= 2;
    }
}

fn invalid(s: &str) -> ReinspiringError {
    ReinspiringError::InvalidParams(s.into())
}
fn validate_poly(a: &[u64], p: &NativeParams) -> Result<(), ReinspiringError> {
    if a.len() != p.d || a.iter().any(|&x| x >= p.q) {
        Err(invalid("wrong degree or noncanonical coefficient"))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod oracle_tests {
    use super::*;
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    #[test]
    fn mixed_width_aggregation_matches_direct_integer_definition() {
        for d in [8, 256] {
            for q in [1u64 << 16, 1u64 << 56] {
                for offset in [0, 1] {
                    // At d=256,q=2^56 the diagonal gives a positive sum above
                    // i64::MAX; the shifted diagonal gives a negative overflow.
                    let mut masks = vec![vec![0; d]; d];
                    for (r, row) in masks.iter_mut().enumerate() {
                        if r + offset < d {
                            row[r + offset] = q - 1;
                        }
                    }
                    let actual = aggregate_masks(&masks, q).unwrap();
                    for (index, row) in actual.iter().enumerate() {
                        let g = 2 * index + 1;
                        let mut expected = vec![0i128; d];
                        for (j, mask) in masks.iter().enumerate() {
                            for k in 0..d {
                                let c = if k == 0 {
                                    mask[0] as i128
                                } else {
                                    -(mask[d - k] as i128)
                                };
                                let e = (k * g + j) % (2 * d);
                                expected[e % d] += if e >= d { -c } else { c };
                            }
                        }
                        let expected: Vec<_> = expected
                            .into_iter()
                            .map(|x| x.div_euclid(d as i128).rem_euclid(q as i128) as u64)
                            .collect();
                        assert_eq!(*row, expected, "d={d},q={q},offset={offset},g={g}");
                    }
                }
            }
        }
    }
    #[test]
    fn python_integer_trace_matches_fft_compiled_pack() {
        for ell in [2, 3] {
            let p = NativeParams::new(8, 54, 14, 19, ell, SecretDistribution::Gaussian).unwrap();
            let setup = NativeSetup::new(p.clone(), [8; 32]);
            let mut rng = ChaCha20Rng::seed_from_u64(91);
            let masks: Vec<Vec<_>> = (0..p.d)
                .map(|_| (0..p.d).map(|_| rng.next_u64() & (p.q - 1)).collect())
                .collect();
            let secret = NativeSecret::sample(&p, &mut rng);
            let keys = NativeKeys::generate(&setup, &secret, &mut rng).unwrap();
            let b: Vec<_> = (0..p.d).map(|_| rng.next_u64() & (p.q - 1)).collect();
            let pre = NativePreprocessed::build(&setup, &masks).unwrap();
            let ct = pre.pack(&b, &keys).unwrap();
            let input = serde_json::json!({"d":p.d,"q":p.q,"bits":p.bits,"ell":p.ell,"dropped":p.dropped,"masks":masks,"w":setup.w,"v":setup.v,"kg":keys.kg,"kh":keys.kh,"b":b});
            let mut child = Command::new("python3")
                .arg(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/tools/python-oracle/native_reference.py"
                ))
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();
            child
                .stdin
                .take()
                .unwrap()
                .write_all(input.to_string().as_bytes())
                .unwrap();
            let output = child.wait_with_output().unwrap();
            assert!(output.status.success());
            let got: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(got["a"], serde_json::json!(ct.a));
            assert_eq!(got["b"], serde_json::json!(ct.b));
        }
    }
}
