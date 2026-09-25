//! Native-modulus ReinspiRING (Algorithms 1–2, Appendices C and D.1–D.2).
//!
//! This is an experimental cryptographic profile: Gaussian and ternary secret
//! configurations are distinct. Neither inherits the security claims of the
//! odd-modulus InspiRING profile. Ciphertext convention is b + a*s = Delta*m+e.
use crate::native_gaussian::gaussian;
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

/// Public transforms for decoding a snapshot under one or two masks.
/// Preparation is independent of request secrets. Retain per snapshot.
pub struct NativeDecoder {
    params: NativeParams,
    lift: LiftContext,
    masks: Vec<PreparedLiftOperand>,
    two_mask: bool,
}
impl NativeDecoder {
    /// Prepare canonical public masks. The second family must have identical shape.
    pub fn new(
        params: &NativeParams,
        masks: &[Vec<u64>],
        others: Option<&[Vec<u64>]>,
    ) -> Result<Self, ReinspiringError> {
        if masks.is_empty() || others.is_some_and(|x| x.len() != masks.len()) {
            return Err(invalid("decoder mask shape mismatch"));
        }
        let support = match params.sampler {
            SecretDistribution::Gaussian => gaussian().max_val() as u64,
            SecretDistribution::TernaryResearch => 1,
        };
        let lift = LiftContext::new(params.d, params.q)?;
        let prepared = masks
            .iter()
            .enumerate()
            .map(|(i, a)| {
                let mut pair = vec![a.clone()];
                if let Some(other) = others {
                    pair.push(other[i].clone());
                }
                lift.prepare_decode_masks(&pair, support)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            params: params.clone(),
            lift,
            masks: prepared,
            two_mask: others.is_some(),
        })
    }
    /// Retained coefficient bytes, excluding context tables and allocator overhead.
    pub fn coefficient_bytes(&self) -> usize {
        self.masks
            .iter()
            .map(PreparedLiftOperand::storage_bytes)
            .sum()
    }
    /// Compute response-independent mask products for a fresh request.
    /// Charge this work to client request generation when benchmarking.
    pub fn prepare_request(
        &self,
        secret: &NativeSecret,
    ) -> Result<NativeDecodingState, ReinspiringError> {
        if secret.params != self.params {
            return Err(invalid("decoder secret profile mismatch"));
        }
        let right = self
            .lift
            .prepare_decode_secret(&secret.coeffs, self.two_mask)?;
        let mut state = NativeDecodingState {
            params: self.params.clone(),
            products: Vec::with_capacity(self.masks.len() * self.params.d),
        };
        for mask in &self.masks {
            let product = zeroize::Zeroizing::new(self.lift.sum_cached(mask, &right)?);
            state.products.extend_from_slice(&product);
        }
        Ok(state)
    }

    /// Decode all bodies, transforming the fresh secret once for the entire response.
    pub fn decrypt(
        &self,
        secret: &NativeSecret,
        bodies: &[u64],
    ) -> Result<Vec<u64>, ReinspiringError> {
        self.prepare_request(secret)?.decrypt(bodies)
    }
}

/// Request-local secret-dependent mask products, erased on drop.
/// Must only be used with responses for the request and public masks that created it.
pub struct NativeDecodingState {
    params: NativeParams,
    products: Vec<u64>,
}
impl Drop for NativeDecodingState {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.products.zeroize();
    }
}
impl NativeDecodingState {
    /// Decode canonical bodies with the precomputed request-local mask products.
    pub fn decrypt(&self, bodies: &[u64]) -> Result<Vec<u64>, ReinspiringError> {
        if bodies.len() != self.products.len() || bodies.iter().any(|&x| x >= self.params.q) {
            return Err(invalid("decoder body shape or range mismatch"));
        }
        let delta = self.params.q / self.params.p;
        Ok(self
            .products
            .iter()
            .zip(bodies)
            .map(|(&x, &y)| {
                ((((x + y) & (self.params.q - 1)) + delta / 2) / delta) & (self.params.p - 1)
            })
            .collect())
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
        let dg = gaussian();
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
        let e = gaussian().sample(q, rng);
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
        let dg = gaussian();
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
    /// Decode a pre-final ciphertext under s and tau_-1(s).
    pub fn decrypt_two_mask(
        &self,
        ct: &NativeTwoMaskCiphertext,
    ) -> Result<Vec<u64>, ReinspiringError> {
        let phase = self.phase_two_mask(ct)?;
        let delta = self.params.q / self.params.p;
        Ok(phase
            .into_iter()
            .map(|x| ((x + delta / 2) / delta) & (self.params.p - 1))
            .collect())
    }
    fn phase_two_mask(&self, ct: &NativeTwoMaskCiphertext) -> Result<Vec<u64>, ReinspiringError> {
        if ct.params != self.params {
            return Err(invalid("ciphertext profile mismatch"));
        }
        let lift = LiftContext::new(self.params.d, self.params.q)?;
        let first = lift.multiply(&ct.a, &self.coeffs)?;
        let conjugate = tau_coeffs(&self.coeffs, 2 * self.params.d as u64 - 1, self.params.q);
        let second = lift.multiply(&ct.a_other, &conjugate)?;
        Ok((0..self.params.d)
            .map(|i| (ct.b[i] + first[i] + second[i]) & (self.params.q - 1))
            .collect())
    }
    /// Maximum centered pre-final phase error.
    pub fn phase_error_two_mask(
        &self,
        ct: &NativeTwoMaskCiphertext,
        expected: &[u64],
    ) -> Result<u64, ReinspiringError> {
        if expected.len() != self.params.d || expected.iter().any(|&m| m >= self.params.p) {
            return Err(invalid("invalid expected plaintext"));
        }
        Ok(self
            .phase_two_mask(ct)?
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
        Self::generate_internal(setup, secret, rng, false)
    }
    fn generate_internal(
        setup: &NativeSetup,
        secret: &NativeSecret,
        rng: &mut ChaCha20Rng,
        one_key: bool,
    ) -> Result<Self, ReinspiringError> {
        let p = &setup.params;
        if secret.params != *p {
            return Err(invalid("key profile mismatch"));
        }
        let lift = LiftContext::new(p.d, p.q)?;
        let dg = gaussian();
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
            kh: if one_key {
                Vec::new()
            } else {
                bodies(&setup.v, 2 * p.d as u64 - 1)?
            },
        })
    }
    /// Generate only the key used by both collapse chains.
    pub fn generate_one_key(
        setup: &NativeSetup,
        secret: &NativeSecret,
        rng: &mut ChaCha20Rng,
    ) -> Result<Self, ReinspiringError> {
        Self::generate_internal(setup, secret, rng, true)
    }
    /// Canonical K_g body words.
    pub fn kg_words(&self) -> Vec<u64> {
        self.kg.iter().flatten().copied().collect()
    }
    /// Parse one canonical K_g body without K_h.
    pub fn from_kg_words(setup: &NativeSetup, words: &[u64]) -> Result<Self, ReinspiringError> {
        let p = &setup.params;
        if words.len() != p.ell * p.d || words.iter().any(|&x| x >= p.q) {
            return Err(invalid("malformed native K_g"));
        }
        Ok(Self {
            id: setup.id,
            kg: words.chunks_exact(p.d).map(|x| x.to_vec()).collect(),
            kh: Vec::new(),
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

/// One body with two public masks under s and tau_-1(s).
pub struct NativeTwoMaskCiphertext {
    params: NativeParams,
    a: Vec<u64>,
    a_other: Vec<u64>,
    b: Vec<u64>,
}
impl NativeTwoMaskCiphertext {
    /// Return both public masks and the response body.
    pub fn rows(&self) -> (&[u64], &[u64], &[u64]) {
        (&self.a, &self.a_other, &self.b)
    }
    /// Construct a bounded two-mask ciphertext under an explicit profile.
    pub fn from_rows(
        params: &NativeParams,
        a: Vec<u64>,
        a_other: Vec<u64>,
        b: Vec<u64>,
    ) -> Result<Self, ReinspiringError> {
        validate_poly(&a, params)?;
        validate_poly(&a_other, params)?;
        validate_poly(&b, params)?;
        Ok(Self {
            params: params.clone(),
            a,
            a_other,
            b,
        })
    }
}

/// Immutable public preprocessing. Online data cannot alter its mask trace.
pub struct NativePreprocessed {
    pub(crate) params: NativeParams,
    pub(crate) id: [u8; 32],
    pub(crate) a: Vec<u64>,
    pub(crate) a_other: Option<Vec<u64>>,
    pub(crate) h: NativeMatrix,
    pub(crate) leftover: Option<PreparedLiftOperand>,
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
    kh: Option<PreparedLiftRight>,
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
        if self.pre.a_other.is_some() {
            return Err(invalid("two-mask preprocessing requires finish_two_mask"));
        }
        validate_poly(b, &self.pre.params)?;
        for (dst, &x) in self.body.iter_mut().zip(b) {
            *dst = (*dst + x) & (self.pre.params.q - 1);
        }
        NativeCiphertext::from_rows(&self.pre.params, self.pre.a.clone(), self.body)
    }
    /// Add the scan body and retain both pre-final masks.
    pub fn finish_two_mask(
        mut self,
        b: &[u64],
    ) -> Result<NativeTwoMaskCiphertext, ReinspiringError> {
        validate_poly(b, &self.pre.params)?;
        let other = self
            .pre
            .a_other
            .as_ref()
            .ok_or_else(|| invalid("one-mask preprocessing"))?;
        for (dst, &x) in self.body.iter_mut().zip(b) {
            *dst = (*dst + x) & (self.pre.params.q - 1);
        }
        NativeTwoMaskCiphertext::from_rows(
            &self.pre.params,
            self.pre.a.clone(),
            other.clone(),
            self.body,
        )
    }
}
impl NativePreprocessed {
    /// Prepare uploaded key bodies once for all blocks from this setup.
    pub fn prepare_keys(&self, keys: &NativeKeys) -> Result<PreparedNativeKeys, ReinspiringError> {
        if keys.id != self.id
            || keys.kg.len() != self.params.ell
            || (self.a_other.is_some() && !keys.kh.is_empty())
            || (self.a_other.is_none() && keys.kh.len() != self.params.ell)
        {
            return Err(invalid("packing setup mismatch"));
        }
        Ok(PreparedNativeKeys {
            id: keys.id,
            y: keys.kg.iter().flatten().copied().collect(),
            kh: if self.a_other.is_some() {
                None
            } else {
                Some(self.lift.prepare_bounded_right(
                    &keys.kh,
                    (1u64 << (self.params.bits - 1)).min(self.params.q / 2),
                )?)
            },
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
        if let (Some(leftover), Some(kh)) = (&self.leftover, &keys.kh) {
            let product = self.lift.sum_cached(leftover, kh)?;
            for (dst, x) in body.iter_mut().zip(product) {
                *dst = (*dst + x) & (self.params.q - 1);
            }
        }
        Ok(PendingNativePack { pre: self, body })
    }
    /// Compile a d-by-d LWE mask matrix using D.2 aggregation and D.1 rounding.
    pub fn build(setup: &NativeSetup, masks: &[Vec<u64>]) -> Result<Self, ReinspiringError> {
        Self::build_timed(setup, masks).map(|(pre, _)| pre)
    }
    /// Compile public masks through the two independent K_g collapse chains.
    pub fn build_two_mask(
        setup: &NativeSetup,
        masks: &[Vec<u64>],
    ) -> Result<Self, ReinspiringError> {
        Self::build_internal(setup, masks, false, true, None).map(|(pre, _, _)| pre)
    }
    /// Compile the two-mask mode and collect its original-sample noise weights.
    pub fn build_two_mask_analyzed(
        setup: &NativeSetup,
        masks: &[Vec<u64>],
    ) -> Result<(Self, crate::noise::NativeNoiseAnalysis), ReinspiringError> {
        Self::build_internal(setup, masks, true, true, None)
            .map(|(pre, _, analysis)| (pre, analysis.unwrap()))
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
        Self::build_internal(setup, masks, false, false, None).map(|(pre, timing, _)| (pre, timing))
    }
    /// Compile with public noise accounting, including one-limb counterfactuals.
    /// This costs additional offline work and does not certify correctness itself.
    pub fn build_analyzed(
        setup: &NativeSetup,
        masks: &[Vec<u64>],
    ) -> Result<(Self, crate::noise::NativeNoiseAnalysis), ReinspiringError> {
        Self::build_internal(setup, masks, true, false, None)
            .map(|(pre, _, analysis)| (pre, analysis.unwrap()))
    }
    /// Counterfactual analysis only: recompile K_g using two unequal widths.
    /// No executable preprocessing or key format escapes this research entry point.
    pub fn screen_gadget(
        setup: &NativeSetup,
        masks: &[Vec<u64>],
        widths: [u32; 2],
    ) -> Result<crate::noise::NativeNoiseAnalysis, ReinspiringError> {
        if setup.params.ell != 2 || widths.iter().any(|&x| !(16..=22).contains(&x)) {
            return Err(invalid("unsupported research collapse gadget"));
        }
        Self::build_internal(setup, masks, true, false, Some(widths)).map(|(_, _, a)| a.unwrap())
    }
    fn build_internal(
        setup: &NativeSetup,
        masks: &[Vec<u64>],
        analyze: bool,
        two_mask: bool,
        research_widths: Option<[u32; 2]>,
    ) -> Result<
        (
            Self,
            NativeBuildTiming,
            Option<crate::noise::NativeNoiseAnalysis>,
        ),
        ReinspiringError,
    > {
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
        let widest = research_widths.map_or(p.bits, |w| *w.iter().max().unwrap());
        let public_w = lift.prepare_public_dot(&setup.w, (1u64 << (widest - 1)).min(q / 2))?;
        let public_v = if two_mask {
            None
        } else {
            Some(lift.prepare_public_dot(&setup.v, (1u64 << (p.bits - 1)).min(q / 2))?)
        };
        let trace_half = |half: &mut [Vec<u64>], exps: &[u64]| -> Result<_, ReinspiringError> {
            let mut digits = Vec::with_capacity(half.len() - 1);
            let mut residues = Vec::new();
            for (step, idx) in (1..half.len()).rev().enumerate() {
                let ds = if let Some(widths) = research_widths {
                    let (ds, residue) = crate::noise::mixed_digits(&half[idx], &widths, q)?;
                    residues.push(residue);
                    ds
                } else {
                    let ds = decompose(&half[idx], p)?;
                    if analyze {
                        residues.push(crate::noise::residual(
                            &half[idx], &ds, p.bits, p.dropped, q,
                        ));
                    }
                    ds
                };
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
            Ok((digits, residues))
        };
        // The two collapse chains are independent until the final K_h step.
        let (left, right) = slots.split_at_mut(d / 2);
        let (left_digits, right_digits) = rayon::join(
            || trace_half(left, &exponents[..d / 2 - 1]),
            || trace_half(right, &exponents[d / 2 - 1..]),
        );
        let (mut digits, mut residues) = left_digits?;
        let (right_digits, right_residues) = right_digits?;
        digits.extend(right_digits);
        residues.extend(right_residues);
        let last = if two_mask {
            None
        } else {
            Some(decompose(&slots[d / 2], p)?)
        };
        let a = if let Some(last) = &last {
            let update = lift.public_dot(public_v.as_ref().unwrap(), last)?;
            slots[0]
                .iter()
                .zip(update)
                .map(|(&a, x)| (a + x) & (q - 1))
                .collect()
        } else {
            slots[0].clone()
        };
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
        let analysis = if analyze {
            Some(if let Some(last) = &last {
                crate::noise::analyze(
                    &h.to_compiled(),
                    residues,
                    &exponents,
                    &slots[d / 2],
                    last,
                    p.bits,
                    p.dropped,
                    &a,
                )?
            } else {
                crate::noise::analyze_two_mask(
                    &h.to_compiled(),
                    residues,
                    &exponents,
                    [&slots[0], &slots[d / 2]],
                )?
            })
        } else {
            None
        };
        let pre = Self {
            params: p.clone(),
            id: setup.id,
            a,
            a_other: if two_mask {
                Some(slots[d / 2].clone())
            } else {
                None
            },
            h,
            leftover: if let Some(last) = &last {
                Some(lift.prepare_public(last)?)
            } else {
                None
            },
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
            analysis,
        ))
    }
    /// Pack d bodies with validated uploaded keys. All arithmetic is deterministic.
    pub fn pack(&self, b: &[u64], keys: &NativeKeys) -> Result<NativeCiphertext, ReinspiringError> {
        if self.a_other.is_some() {
            return Err(invalid("two-mask preprocessing requires pack_two_mask"));
        }
        validate_poly(b, &self.params)?;
        if keys.id != self.id
            || keys.kg.len() != self.params.ell
            || keys.kh.len() != self.params.ell
        {
            return Err(invalid("packing setup mismatch"));
        }
        let y: Vec<_> = keys.kg.iter().flatten().copied().collect();
        let mut out = self.h.multiply(&y)?;
        let leftover = self
            .lift
            .sum_prepared(self.leftover.as_ref().unwrap(), &keys.kh)?;
        for i in 0..self.params.d {
            out[i] = (out[i] + leftover[i] + b[i]) & (self.params.q - 1);
        }
        NativeCiphertext::from_rows(&self.params, self.a.clone(), out)
    }
    /// Pack with one K_g key, retaining the second public mask.
    pub fn pack_two_mask(
        &self,
        b: &[u64],
        keys: &NativeKeys,
    ) -> Result<NativeTwoMaskCiphertext, ReinspiringError> {
        validate_poly(b, &self.params)?;
        if keys.id != self.id || keys.kg.len() != self.params.ell || !keys.kh.is_empty() {
            return Err(invalid("packing key mode mismatch"));
        }
        let other = self
            .a_other
            .as_ref()
            .ok_or_else(|| invalid("one-mask preprocessing"))?;
        let y = keys.kg_words();
        let mut out = self.h.multiply(&y)?;
        for (dst, &x) in out.iter_mut().zip(b) {
            *dst = (*dst + x) & (self.params.q - 1);
        }
        NativeTwoMaskCiphertext::from_rows(&self.params, self.a.clone(), other.clone(), out)
    }
    /// Read/XOR diagnostic for coefficient memory traffic; not a cryptographic checksum.
    pub fn matrix_read_checksum(&self) -> u64 {
        self.h.read_checksum()
    }
    /// Matrix-only operation for benchmark attribution.
    pub fn matrix_product(&self, keys: &NativeKeys) -> Result<Vec<u64>, ReinspiringError> {
        if keys.id != self.id || keys.kg.len() != self.params.ell {
            return Err(invalid("packing setup mismatch"));
        }
        self.h
            .multiply(&keys.kg.iter().flatten().copied().collect::<Vec<_>>())
    }
    /// Leftover-only operation for benchmark attribution.
    pub fn leftover_product(&self, keys: &NativeKeys) -> Result<Vec<u64>, ReinspiringError> {
        if keys.id != self.id || keys.kh.len() != self.params.ell {
            return Err(invalid("packing setup mismatch"));
        }
        self.lift.sum_prepared(
            self.leftover
                .as_ref()
                .ok_or_else(|| invalid("no leftover in two-mask mode"))?,
            &keys.kh,
        )
    }
    /// Retained coefficient storage, excluding auxiliary NTT tables and headers.
    pub fn coefficient_bytes(&self) -> usize {
        self.h.storage_bytes()
            + self
                .leftover
                .as_ref()
                .map_or(0, PreparedLiftOperand::storage_bytes)
            + self.params.d * 8 * (1 + usize::from(self.a_other.is_some()))
    }
    /// Published c1 row; independent of the client's secret and uploaded bodies.
    pub fn mask(&self) -> &[u64] {
        &self.a
    }
    /// Second public mask, available only in two-mask mode.
    pub fn other_mask(&self) -> Option<&[u64]> {
        self.a_other.as_deref()
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
    fn prepared_decode_matches_generic_at_support_boundaries() {
        for d in [2, 8, 64, 2048] {
            let p = NativeParams::new(d, 54, 16, 19, 2, SecretDistribution::Gaussian).unwrap();
            let secret = NativeSecret {
                params: p.clone(),
                coeffs: (0..d)
                    .map(|i| if i % 2 == 0 { 65 } else { p.q - 65 })
                    .collect(),
            };
            let a: Vec<_> = (0..d)
                .map(|i| if i % 3 == 0 { p.q / 2 } else { p.q / 2 - 1 })
                .collect();
            let other = tau_coeffs(&a, 5, p.q);
            let b = vec![p.q - 1; d];
            for two in [false, true] {
                let first = vec![a.clone()];
                let others = vec![other.clone()];
                let prepared =
                    NativeDecoder::new(&p, &first, if two { Some(&others) } else { None }).unwrap();
                let expected = if two {
                    secret
                        .decrypt_two_mask(
                            &NativeTwoMaskCiphertext::from_rows(
                                &p,
                                a.clone(),
                                other.clone(),
                                b.clone(),
                            )
                            .unwrap(),
                        )
                        .unwrap()
                } else {
                    secret
                        .decrypt(&NativeCiphertext::from_rows(&p, a.clone(), b.clone()).unwrap())
                        .unwrap()
                };
                assert_eq!(prepared.decrypt(&secret, &b).unwrap(), expected);
                assert_eq!(
                    prepared
                        .prepare_request(&secret)
                        .unwrap()
                        .decrypt(&b)
                        .unwrap(),
                    expected
                );
                assert!(prepared.decrypt(&secret, &b[..d - 1]).is_err());
            }
        }
    }

    #[test]
    fn python_integer_trace_matches_fft_compiled_pack() {
        for (ell, wire_bits) in [(2, 54), (3, 54), (2, 48), (2, 46)] {
            let p = NativeParams::new(8, 54, 14, 19, ell, SecretDistribution::Gaussian).unwrap();
            let setup = NativeSetup::new(p.clone(), [8; 32]);
            let mut rng = ChaCha20Rng::seed_from_u64(91);
            let masks: Vec<Vec<_>> = (0..p.d)
                .map(|_| (0..p.d).map(|_| rng.next_u64() & (p.q - 1)).collect())
                .collect();
            let secret = NativeSecret::sample(&p, &mut rng);
            let mut keys = NativeKeys::generate(&setup, &secret, &mut rng).unwrap();
            if wire_bits < 54 {
                let step = 1u64 << (54 - wire_bits);
                for x in keys.kh.iter_mut().flatten() {
                    *x = ((*x + step / 2) / step * step) & (p.q - 1);
                }
            }
            let b: Vec<_> = (0..p.d).map(|_| rng.next_u64() & (p.q - 1)).collect();
            let (pre, analysis) = NativePreprocessed::build_analyzed(&setup, &masks).unwrap();
            let ct = pre.pack(&b, &keys).unwrap();
            if ell == 2 {
                let screen = NativePreprocessed::screen_gadget(&setup, &masks, [19, 19]).unwrap();
                assert_eq!(screen.weights, analysis.weights);
                assert_eq!(screen.kg_limbs, analysis.kg_limbs);
                assert_eq!(screen.collapse_secret, analysis.collapse_secret);
                assert_eq!(screen.final_mask, analysis.final_mask);
            }
            let input = serde_json::json!({"d":p.d,"q":p.q,"bits":p.bits,"ell":p.ell,"dropped":p.dropped,"masks":masks,"w":setup.w,"v":setup.v,"kg":keys.kg,"kh":keys.kh,"b":b,"secret":secret.coeffs,"include_weights":true});
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
            // Check the noise identity against actual encryption algebra, not
            // only another implementation of the public trace. The unaccounted
            // remainder is exactly the D.1 integer-division term.
            let lift = LiftContext::new(p.d, p.q).unwrap();
            let errors = |masks: &[Vec<u64>], bodies: &[Vec<u64>], g| {
                let from = tau_coeffs(&secret.coeffs, g, p.q);
                masks
                    .iter()
                    .zip(bodies)
                    .enumerate()
                    .map(|(j, (mask, body))| {
                        let ws = lift.multiply(mask, &secret.coeffs).unwrap();
                        body.iter()
                            .enumerate()
                            .map(|(i, &x)| {
                                x.wrapping_add(ws[i])
                                    .wrapping_sub(from[i].wrapping_mul(p.factor(j)))
                                    & (p.q - 1)
                            })
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>()
            };
            let eg: Vec<_> = errors(&setup.w, &keys.kg, 5)
                .into_iter()
                .flatten()
                .collect();
            let eh = errors(&setup.v, &keys.kh, 2 * p.d as u64 - 1);
            let sw: Vec<Vec<u64>> = serde_json::from_value(got["secret_weights"].clone()).unwrap();
            let gw: Vec<Vec<u64>> = serde_json::from_value(got["kg_weights"].clone()).unwrap();
            let hd: Vec<Vec<i64>> = serde_json::from_value(got["final_digits"].clone()).unwrap();
            let hd: Vec<Vec<u64>> = hd
                .iter()
                .map(|row| {
                    row.iter()
                        .map(|&x| (x as i128).rem_euclid(p.q as i128) as u64)
                        .collect()
                })
                .collect();
            // Exact compression identity, including unequal per-limb precision.
            let mut rounded = NativeKeys {
                id: keys.id,
                kg: keys.kg.clone(),
                kh: keys.kh.clone(),
            };
            let mut eps_g = Vec::new();
            let mut eps_h = Vec::new();
            for (family, errors) in [(&mut rounded.kg, &mut eps_g), (&mut rounded.kh, &mut eps_h)] {
                for (j, limb) in family.iter_mut().enumerate() {
                    let step = 1u64 << (4 + j * 3);
                    errors.push(
                        limb.iter_mut()
                            .map(|x| {
                                let old = *x;
                                *x = ((*x + step / 2) / step * step) & (p.q - 1);
                                x.wrapping_sub(old) & (p.q - 1)
                            })
                            .collect::<Vec<_>>(),
                    );
                }
            }
            let compressed = pre.pack(&b, &rounded).unwrap();
            let final_error = lift.sum(&hd, &eps_h).unwrap();
            let flat: Vec<_> = eps_g.into_iter().flatten().collect();
            for i in 0..p.d {
                let compiled = gw[i]
                    .iter()
                    .zip(&flat)
                    .fold(0u64, |sum, (&x, &y)| sum.wrapping_add(x.wrapping_mul(y)));
                assert_eq!(
                    compressed.b[i].wrapping_sub(ct.b[i]) & (p.q - 1),
                    compiled.wrapping_add(final_error[i]) & (p.q - 1)
                );
            }
            let kh_error = lift.sum(&hd, &eh).unwrap();
            let dot = |a: &[u64], b: &[u64]| {
                a.iter()
                    .zip(b)
                    .fold(0u64, |s, (&a, &b)| s.wrapping_add(a.wrapping_mul(b)))
                    & (p.q - 1)
            };
            let phase = secret.phase(&ct).unwrap();
            for i in 0..p.d {
                let predicted = b[i]
                    .wrapping_add(dot(&masks[i], &secret.coeffs))
                    .wrapping_add(dot(&sw[i], &secret.coeffs))
                    .wrapping_add(dot(&gw[i], &eg))
                    .wrapping_add(kh_error[i]);
                let remainder =
                    centered(phase[i].wrapping_sub(predicted) & (p.q - 1), p.q).unsigned_abs();
                assert!(remainder <= p.division_error_bound(65));
            }
            let norms =
                |n: crate::noise::WeightNorms| serde_json::json!([n.l1, n.l2_squared, n.max]);
            assert_eq!(analysis.public_mask_screens.len(), 9);
            assert_eq!(got["public_mask_screens"].as_array().unwrap().len(), 9);
            for (i, (bits, weights)) in analysis.public_mask_screens.iter().enumerate() {
                let screen = &got["public_mask_screens"][i];
                assert_eq!(screen["bits"], *bits);
                assert_eq!(screen["noise"], norms(*weights));
                assert_eq!(screen["phase_cases"].as_array().unwrap().len(), 2);
                for case in screen["phase_cases"].as_array().unwrap() {
                    let mask: Vec<u64> = serde_json::from_value(case["mask"].clone()).unwrap();
                    let step = p.q >> bits;
                    let rounded: Vec<_> = mask
                        .iter()
                        .map(|&x| ((x + step / 2) / step * step) & (p.q - 1))
                        .collect();
                    assert_eq!(case["rounded"], serde_json::json!(rounded));
                    let exact = NativeCiphertext::from_rows(&p, mask, ct.b.clone()).unwrap();
                    let rounded = NativeCiphertext::from_rows(&p, rounded, ct.b.clone()).unwrap();
                    let change: Vec<_> = secret
                        .phase(&rounded)
                        .unwrap()
                        .iter()
                        .zip(secret.phase(&exact).unwrap())
                        .map(|(&x, y)| x.wrapping_sub(y) & (p.q - 1))
                        .collect();
                    assert_eq!(case["delta"], serde_json::json!(change));
                }
            }
            assert_eq!(got["noise"], norms(analysis.weights));
            assert_eq!(got["kh_l1"], serde_json::json!(analysis.kh_l1));
            for (i, candidate) in analysis.one_limb.iter().enumerate() {
                assert_eq!(got["one_limb"][i]["bits"], candidate.bits);
                assert_eq!(got["one_limb"][i]["weights"], norms(candidate.weights));
            }
        }
    }
    #[test]
    fn python_integer_trace_matches_two_mask_pack_and_weights() {
        let p = NativeParams::new(8, 54, 16, 19, 2, SecretDistribution::Gaussian).unwrap();
        let setup = NativeSetup::new(p.clone(), [81; 32]);
        let mut rng = ChaCha20Rng::seed_from_u64(918);
        let masks: Vec<Vec<_>> = (0..p.d)
            .map(|_| (0..p.d).map(|_| rng.next_u64() & (p.q - 1)).collect())
            .collect();
        let secret = NativeSecret::sample(&p, &mut rng);
        let keys = NativeKeys::generate_one_key(&setup, &secret, &mut rng).unwrap();
        let b: Vec<_> = (0..p.d).map(|_| rng.next_u64() & (p.q - 1)).collect();
        let (pre, analysis) = NativePreprocessed::build_two_mask_analyzed(&setup, &masks).unwrap();
        let ct = pre.pack_two_mask(&b, &keys).unwrap();
        let input = serde_json::json!({"d":p.d,"q":p.q,"bits":p.bits,"ell":p.ell,"dropped":p.dropped,"masks":masks,"w":setup.w,"kg":keys.kg,"b":b,"two_mask":true,"include_weights":true});
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
        assert_eq!(got["a_other"], serde_json::json!(ct.a_other));
        assert_eq!(got["b"], serde_json::json!(ct.b));
        assert_eq!(got["noise"][0], serde_json::json!(analysis.weights.l1));
        assert_eq!(
            got["noise"][1],
            serde_json::json!(analysis.weights.l2_squared)
        );
        assert_eq!(got["noise"][2], serde_json::json!(analysis.weights.max));
        for (i, (bits, w)) in analysis.public_mask_screens.iter().enumerate() {
            assert_eq!(got["public_mask_screens"][i]["bits"], *bits);
            assert_eq!(
                got["public_mask_screens"][i]["noise"],
                serde_json::json!([w.l1, w.l2_squared, w.max])
            );
            let step = p.q >> bits;
            let round = |mask: &[u64]| {
                mask.iter()
                    .map(|&x| ((x + step / 2) / step * step) & (p.q - 1))
                    .collect::<Vec<_>>()
            };
            let rounded = NativeTwoMaskCiphertext::from_rows(
                &p,
                round(&ct.a),
                round(&ct.a_other),
                ct.b.clone(),
            )
            .unwrap();
            let difference = |a: &[u64], b: &[u64]| {
                a.iter()
                    .zip(b)
                    .map(|(&x, &y)| x.wrapping_sub(y) & (p.q - 1))
                    .collect::<Vec<_>>()
            };
            let lift = LiftContext::new(p.d, p.q).unwrap();
            let extra = lift
                .sum(
                    &[
                        difference(&rounded.a, &ct.a),
                        difference(&rounded.a_other, &ct.a_other),
                    ],
                    &[
                        secret.coeffs.clone(),
                        tau_coeffs(&secret.coeffs, (2 * p.d - 1) as u64, p.q),
                    ],
                )
                .unwrap();
            assert_eq!(
                difference(
                    &secret.phase_two_mask(&rounded).unwrap(),
                    &secret.phase_two_mask(&ct).unwrap()
                ),
                extra
            );
        }
    }
}
