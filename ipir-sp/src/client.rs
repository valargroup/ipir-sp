//! Client-side key material for the IPIR-SP packing layer.
//!
//! YPIR's CDKS path uploads `log d` expansion matrices. The InspiRING path
//! uploads the secret-dependent packing-key bodies for `K_g` and `K_h`; public
//! top rows are derived from fixed CRS seeds on both sides.

use inspiring::{PackingKeys, RlweParams};
use rand::{Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use spiral_rs::discrete_gaussian::DiscreteGaussian;
use spiral_rs::poly::{
    from_ntt_alloc, multiply, to_ntt_alloc, PolyMatrix, PolyMatrixNTT, PolyMatrixRaw,
};

use crate::bits::{contiguous_bytes_to_u64s, u64s_to_contiguous_bytes};
use crate::modulus_switch::modulus_bits;
use crate::modulus_switch::{
    query_coeff_down, query_coeff_up, recover_response_body, response_body_len,
};
use crate::params::{params_for_simplepir, YpirSchemeParams};

/// Seed used to regenerate IPIR client secret material with the current sampler.
/// Seeds are not versioned: finish outstanding responses with the client version
/// that generated them. See `MIGRATION.md` for the Gaussian-secret transition.
pub type IPIRSeed = [u8; 32];

/// A client secret in coefficient form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientSecret {
    /// Secret coefficients modulo `q`.
    pub coeffs: Vec<u64>,
}

impl ClientSecret {
    /// Build a secret from coefficients, reducing each coefficient modulo `q`.
    #[must_use]
    pub fn from_coeffs(params: &RlweParams, coeffs: impl Into<Vec<u64>>) -> Self {
        let coeffs = coeffs.into();
        assert_eq!(
            coeffs.len(),
            params.d,
            "client secret must have d coefficients"
        );

        Self {
            coeffs: coeffs.into_iter().map(|coeff| coeff % params.q).collect(),
        }
    }

    /// Sample a centred discrete-Gaussian secret, reduced modulo `q`.
    ///
    /// Uses the same standard deviation `sigma_chi` as the encryption errors
    /// (6.4 for the production profile). The pinned backend takes Gaussian
    /// width, so convert with `sqrt(2*pi)` and use its constant-time CDF sampler.
    /// The RNG must be private and cryptographically seeded. Deterministic
    /// regeneration requires the same parameters, RNG state and sampler version.
    pub fn sample_gaussian(params: &RlweParams, rng: &mut ChaCha20Rng) -> Self {
        let dg = DiscreteGaussian::init(params.sigma_chi * std::f64::consts::TAU.sqrt());
        let coeffs = (0..params.d).map(|_| dg.sample(params.q, rng)).collect();
        Self { coeffs }
    }

    /// Low-level ternary sampler retained for explicit research fixtures.
    /// High-level query generation and seed-based decoding use `sample_gaussian`.
    pub fn sample_ternary(params: &RlweParams, rng: &mut ChaCha20Rng) -> Self {
        let coeffs = (0..params.d)
            .map(|_| match rng.gen_range(0..3) {
                0 => 0,
                1 => 1,
                _ => params.q - 1,
            })
            .collect();

        Self { coeffs }
    }

    /// Convert the secret to a `[1, 1]` NTT polynomial matrix.
    #[must_use]
    pub fn to_ntt<'a>(&self, params: &'a RlweParams) -> spiral_rs::poly::PolyMatrixNTT<'a> {
        assert_eq!(
            self.coeffs.len(),
            params.d,
            "client secret must have d coefficients"
        );

        let mut raw = PolyMatrixRaw::zero(&params.spiral, 1, 1);
        raw.get_poly_mut(0, 0).copy_from_slice(&self.coeffs);
        to_ntt_alloc(&raw)
    }
}

/// High-level IPIR client facade with a YPIR-shaped API.
#[derive(Debug, Clone)]
pub struct IPIRClient {
    rlwe: RlweParams,
    ypir: YpirSchemeParams,
}

/// Online SimplePIR first-dimension query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IPIRSimpleQuery {
    first_dim: Vec<u64>,
}

impl IPIRSimpleQuery {
    /// Build a query from first-dimension coefficients.
    #[must_use]
    pub fn new(first_dim: Vec<u64>) -> Self {
        Self { first_dim }
    }

    /// Return the first-dimension query coefficients.
    #[must_use]
    pub fn as_slice(&self) -> &[u64] {
        &self.first_dim
    }

    /// Consume the query and return its first-dimension coefficients.
    ///
    /// Server callers want to own the vector; `as_slice().to_vec()` copied it.
    #[must_use]
    pub fn into_first_dim(self) -> Vec<u64> {
        self.first_dim
    }

    /// Serialize query coefficients using the exact bit width of `modulus`.
    #[must_use]
    pub fn to_packed_bytes(&self, modulus: u64) -> Vec<u8> {
        u64s_to_contiguous_bytes(&self.first_dim, modulus_bits(modulus))
    }

    /// Serialize query coefficients rounded down to `bits` bits.
    ///
    /// The coefficients are an LWE body modulo `q`; the extra precision above
    /// `bits` is noise the server's accumulator cannot use. See
    /// [`crate::modulus_switch::query_modulus_bits`] for how `bits` is chosen.
    #[must_use]
    pub fn to_switched_bytes(&self, modulus: u64, bits: usize) -> Vec<u8> {
        let switched: Vec<u64> = self
            .first_dim
            .iter()
            .map(|coeff| query_coeff_down(*coeff, modulus, bits))
            .collect();
        u64s_to_contiguous_bytes(&switched, bits)
    }

    /// Recover query coefficients packed by [`Self::to_switched_bytes`].
    pub fn from_switched_bytes(
        data: &[u8],
        coeff_count: usize,
        modulus: u64,
        bits: usize,
    ) -> Result<Self, inspiring::InspiringError> {
        let expected_len = (coeff_count * bits).div_ceil(8);
        if data.len() != expected_len {
            return Err(inspiring::InspiringError::PreprocessMismatch(format!(
                "switched query must be {expected_len} bytes for {coeff_count} coefficients at {bits} bits, got {}",
                data.len()
            )));
        }

        let mut coeffs = contiguous_bytes_to_u64s(data, bits);
        coeffs.truncate(coeff_count);
        if coeffs.len() != coeff_count {
            return Err(inspiring::InspiringError::PreprocessMismatch(format!(
                "switched query decoded to {} coefficients, expected {coeff_count}",
                coeffs.len()
            )));
        }
        for coeff in &mut coeffs {
            *coeff = query_coeff_up(*coeff, modulus, bits);
        }
        Ok(Self::new(coeffs))
    }

    /// Parse a query serialized by [`Self::to_packed_bytes`].
    pub fn from_packed_bytes(
        data: &[u8],
        coeff_count: usize,
        modulus: u64,
    ) -> Result<Self, inspiring::InspiringError> {
        let bits = modulus_bits(modulus);
        let expected_len = (coeff_count * bits).div_ceil(8);
        if data.len() != expected_len {
            return Err(inspiring::InspiringError::PreprocessMismatch(format!(
                "packed query must be {expected_len} bytes for {coeff_count} coefficients and {bits}-bit modulus, got {}",
                data.len()
            )));
        }

        let coeffs = contiguous_bytes_to_u64s(data, bits);
        if coeffs.len() != coeff_count {
            return Err(inspiring::InspiringError::PreprocessMismatch(format!(
                "packed query decoded to {} coefficients, expected {coeff_count}",
                coeffs.len()
            )));
        }

        Ok(Self::new(coeffs))
    }
}

impl IPIRClient {
    /// Build a client from explicit IPIR-SP parameters.
    #[must_use]
    pub fn new(rlwe: &RlweParams, ypir: &YpirSchemeParams) -> Self {
        Self {
            rlwe: rlwe.clone(),
            ypir: ypir.clone(),
        }
    }

    /// Build a client from database shape, mirroring `ypir::YPIRClient::from_db_sz`.
    #[must_use]
    pub fn from_db_sz(num_items: u64, item_size_bits: u64) -> Self {
        let (rlwe, ypir) =
            params_for_simplepir(num_items, item_size_bits).expect("valid SimplePIR parameters");
        Self { rlwe, ypir }
    }

    /// Return the RLWE parameters used by the packing layer.
    #[must_use]
    pub fn rlwe_params(&self) -> &RlweParams {
        &self.rlwe
    }

    /// Return the YPIR-shaped scheme parameters used by the database and transport layers.
    #[must_use]
    pub fn params(&self) -> &YpirSchemeParams {
        &self.ypir
    }

    /// Generate public offline query polynomials from shared setup randomness.
    ///
    /// These polynomials are secret-independent, so a server may precompute the
    /// corresponding CRS/hint once and clients can reuse the same public setup
    /// while still sampling a fresh secret and key-switching pair per query.
    pub fn generate_public_query_setup_simplepir_from_seed(
        &self,
        setup_seed: IPIRSeed,
    ) -> Vec<Vec<u64>> {
        assert_eq!(
            self.ypir.db_rows % self.rlwe.d,
            0,
            "db rows must split into d-row blocks"
        );

        let mut rng = ChaCha20Rng::from_seed(setup_seed);
        (0..self.ypir.db_rows / self.rlwe.d)
            .map(|_| {
                (0..self.rlwe.d)
                    .map(|_| rng.gen_range(0..self.rlwe.q))
                    .collect()
            })
            .collect()
    }

    /// Generate a fresh-secret online query with uploaded packing-key bodies.
    pub fn generate_fresh_query_simplepir(
        &self,
        offline_query_polys: &[Vec<u64>],
        target_row: usize,
    ) -> (IPIRSimpleQuery, PackingKeys<'_>, IPIRSeed) {
        // An out-of-range row would silently encrypt the all-zero selector, and
        // the decoded row would read as "absent". That is the failure a server
        // mis-reporting the row count would induce, so fail loudly instead.
        assert!(
            target_row < self.ypir.db_rows,
            "target_row {target_row} is out of range for {} db rows",
            self.ypir.db_rows
        );
        let mut client_seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut client_seed);
        let mut rng = ChaCha20Rng::from_seed(client_seed);
        let secret = ClientSecret::sample_gaussian(&self.rlwe, &mut rng);
        let secret_ntt = secret.to_ntt(&self.rlwe);
        let packing_keys = PackingKeys::generate_full(&self.rlwe, &secret_ntt, &mut rng);
        let first_dim = encrypted_selection_query(
            &self.rlwe,
            offline_query_polys,
            &secret.coeffs,
            target_row,
            self.ypir.db_rows,
            &mut rng,
        );

        (IPIRSimpleQuery::new(first_dim), packing_keys, client_seed)
    }

    /// Decode serialized response bytes into contiguous plaintext bytes.
    ///
    /// `published_c1` is the snapshot-constant `c1` row of each output block,
    /// fetched once from the server's metadata; see
    /// [`crate::modulus_switch::recover_published_c1`].
    #[must_use]
    pub fn decode_response_simplepir(
        &self,
        client_seed: IPIRSeed,
        published_c1: &[Vec<u64>],
        response: &[u8],
    ) -> Vec<u8> {
        let decoded = self.decode_response_simplepir_raw(client_seed, published_c1, response);
        u64s_to_contiguous_bytes(&decoded, plaintext_modulus_bits(self.rlwe.p))
    }

    /// Decode serialized response bytes into plaintext coefficients.
    #[must_use]
    pub fn decode_response_simplepir_raw(
        &self,
        client_seed: IPIRSeed,
        published_c1: &[Vec<u64>],
        response: &[u8],
    ) -> Vec<u64> {
        let blocks = self.ypir.db_cols / self.rlwe.d;
        let body_len = response_body_len(self.rlwe.d, self.ypir.q_prime_1);
        assert_eq!(
            response.len(),
            blocks * body_len,
            "serialized response length mismatch"
        );
        assert_eq!(
            published_c1.len(),
            blocks,
            "expected one published c1 row per output block"
        );

        let secret = self.secret_from_seed(client_seed);
        let secret_ntt = secret.to_ntt(&self.rlwe);
        let mut decoded = Vec::with_capacity(self.ypir.db_cols);
        for (chunk, row_0) in response.chunks_exact(body_len).zip(published_c1) {
            let row_1 = recover_response_body(chunk, self.rlwe.d, self.ypir.q_prime_1, self.rlwe.q);
            decoded.extend(decode_rows(&self.rlwe, row_0, &row_1, &secret_ntt));
        }
        decoded
    }

    /// Decode a response and report the worst decryption error observed.
    ///
    /// Returns `(coefficients, max_error)` where `max_error` is the largest
    /// centered distance between a recovered phase and the nearest multiple of
    /// `Δ`. Decryption is correct exactly while that stays under `Δ/2`, so this
    /// is the quantity any change to the query width, the plaintext modulus, or
    /// the database shape has to be judged against.
    #[must_use]
    pub fn decode_response_simplepir_with_margin(
        &self,
        client_seed: IPIRSeed,
        published_c1: &[Vec<u64>],
        response: &[u8],
    ) -> (Vec<u64>, u64) {
        let blocks = self.ypir.db_cols / self.rlwe.d;
        let body_len = response_body_len(self.rlwe.d, self.ypir.q_prime_1);
        assert_eq!(response.len(), blocks * body_len);
        assert_eq!(published_c1.len(), blocks);

        let secret = self.secret_from_seed(client_seed);
        let secret_ntt = secret.to_ntt(&self.rlwe);
        let mut decoded = Vec::with_capacity(self.ypir.db_cols);
        let mut max_error = 0_u64;

        for (chunk, row_0) in response.chunks_exact(body_len).zip(published_c1) {
            let row_1 = recover_response_body(chunk, self.rlwe.d, self.ypir.q_prime_1, self.rlwe.q);
            let phase = phase_of(&self.rlwe, row_0, &row_1, &secret_ntt);
            for coeff in &phase {
                let offset = coeff % self.rlwe.delta;
                let error = offset.min(self.rlwe.delta - offset);
                max_error = max_error.max(error);
                decoded.push(((coeff + self.rlwe.delta / 2) / self.rlwe.delta) % self.rlwe.p);
            }
        }

        (decoded, max_error)
    }

    fn secret_from_seed(&self, client_seed: IPIRSeed) -> ClientSecret {
        let mut rng = ChaCha20Rng::from_seed(client_seed);
        ClientSecret::sample_gaussian(&self.rlwe, &mut rng)
    }
}

/// Encrypt the one-hot row selector as `db_rows` scalar RLWE bodies.
///
/// Each entry is `b[row] = delta * [row == target_row] + e[row] - <a * X^j, s>`.
/// The mask side `a` is public — both peers derive it from the shared setup
/// seed — so the error term `e` is what makes the query hiding. Without it the
/// server recovers `s` by linear algebra from any block that does not contain
/// the target, and then reads `target_row` straight off the remaining block.
fn encrypted_selection_query(
    params: &RlweParams,
    offline_query: &[Vec<u64>],
    secret: &[u64],
    target_row: usize,
    db_rows: usize,
    rng: &mut ChaCha20Rng,
) -> Vec<u64> {
    assert_eq!(db_rows % params.d, 0);
    assert_eq!(offline_query.len(), db_rows / params.d);
    assert!(
        target_row < db_rows,
        "target_row {target_row} is out of range for {db_rows} db rows"
    );

    // spiral-rs parameterizes the sampler by width, not by standard deviation.
    let dg = DiscreteGaussian::init(params.sigma_chi * std::f64::consts::TAU.sqrt());

    let mut query = vec![0u64; db_rows];
    let secret_ntt = polynomial_to_ntt(params, secret);
    for (block_idx, query_poly) in offline_query.iter().enumerate() {
        let inner_products = query_inner_products_from_ntt(params, query_poly, &secret_ntt);
        for (coeff_idx, inner) in inner_products.iter().enumerate() {
            let row = block_idx * params.d + coeff_idx;
            let encoded_selection = select_u64(row == target_row, params.delta, 0);
            let noised = add_mod(
                encoded_selection,
                sample_error(&dg, rng, params.q),
                params.q,
            );
            query[row] = sub_mod(noised, *inner, params.q);
        }
    }

    query
}

/// Sample one centred discrete-Gaussian error, reduced into `[0, modulus)`.
fn sample_error(dg: &DiscreteGaussian, rng: &mut ChaCha20Rng, modulus: u64) -> u64 {
    let sample = dg.sample(modulus, rng);
    debug_assert!(sample < modulus);
    sample
}

/// Return `value` if `condition` holds, else `other`, without a branch.
///
/// Query generation selects `delta` for the target row and `0` everywhere
/// else; a data-dependent branch there would let a local timing observer
/// pick out the target row. Both operands are computed and a mask chooses.
fn select_u64(condition: bool, value: u64, other: u64) -> u64 {
    let mask = 0u64.wrapping_sub(u64::from(condition));
    (value & mask) | (other & !mask)
}

/// Return `lhs + rhs mod modulus` for already-reduced inputs.
///
/// Branch-free for the same reason as [`select_u64`]: `lhs` is `delta` or `0`
/// depending on the target row, so whether the sum wraps is secret-dependent.
fn add_mod(lhs: u64, rhs: u64, modulus: u64) -> u64 {
    debug_assert!(lhs < modulus);
    debug_assert!(rhs < modulus);
    let sum = lhs + rhs;
    let (reduced, borrow) = sum.overflowing_sub(modulus);
    select_u64(borrow, sum, reduced)
}

/// Convert one coefficient-form polynomial into the RLWE NTT domain.
///
/// This is used for the fixed client secret during query generation. Inputs are
/// reduced modulo `q` so callers can pass canonical secrets as well as small
/// test vectors without relying on upstream normalization.
fn polynomial_to_ntt<'a>(params: &'a RlweParams, coeffs: &[u64]) -> PolyMatrixNTT<'a> {
    assert_eq!(coeffs.len(), params.d);

    let mut raw = PolyMatrixRaw::zero(&params.spiral, 1, 1);
    raw.get_poly_mut(0, 0)
        .iter_mut()
        .zip(coeffs)
        .for_each(|(out, coeff)| *out = coeff % params.q);
    to_ntt_alloc(&raw)
}

/// Build `a(X^-1)` in coefficient form and transform it.
///
/// The scalar query path computes `<a(X) * X^j, s(X)>` for every shift `j`.
/// Those values are exactly the coefficients of `a(X^-1) * s(X)` in
/// `Z_q[X] / (X^d + 1)`, where `X^-i = -X^(d-i)` for non-zero `i`.
fn inverse_polynomial_to_ntt<'a>(params: &'a RlweParams, coeffs: &[u64]) -> PolyMatrixNTT<'a> {
    assert_eq!(coeffs.len(), params.d);

    let mut raw = PolyMatrixRaw::zero(&params.spiral, 1, 1);
    let poly = raw.get_poly_mut(0, 0);
    poly[0] = coeffs[0] % params.q;
    for coeff_idx in 1..params.d {
        let coeff = coeffs[params.d - coeff_idx] % params.q;
        poly[coeff_idx] = if coeff == 0 { 0 } else { params.q - coeff };
    }

    to_ntt_alloc(&raw)
}

/// Compute all scalar query inner products for one public query polynomial.
///
/// For a public polynomial `a`, the old scalar path computed
/// `<a(X) * X^j, s(X)>` independently for every coefficient index `j`.
/// Algebraically, that whole vector is the coefficient form of
/// `a(X^-1) * s(X)`. This helper performs that product with one NTT multiply
/// and returns the same `d` inner products in query-row order.
fn query_inner_products_from_ntt<'a>(
    params: &'a RlweParams,
    query_poly: &[u64],
    secret_ntt: &PolyMatrixNTT<'a>,
) -> Vec<u64> {
    assert_eq!(query_poly.len(), params.d);

    let query_ntt = inverse_polynomial_to_ntt(params, query_poly);
    let mut product = PolyMatrixNTT::zero(&params.spiral, 1, 1);
    multiply(&mut product, &query_ntt, secret_ntt);
    from_ntt_alloc(&product)
        .get_poly(0, 0)
        .iter()
        .map(|coeff| coeff % params.q)
        .collect()
}

/// Return `lhs - rhs mod modulus` without widening to `u128`.
///
/// Query generation only subtracts already-reduced values (`0`/`delta` and an
/// inner product modulo `q`), so a branch is enough and avoids reintroducing the
/// expensive 128-bit modulo helper that dominated the previous client profile.
fn sub_mod(lhs: u64, rhs: u64, modulus: u64) -> u64 {
    debug_assert!(lhs < modulus);
    debug_assert!(rhs < modulus);
    let (diff, borrow) = lhs.overflowing_sub(rhs);
    diff.wrapping_add(modulus & 0u64.wrapping_sub(u64::from(borrow)))
}

/// Compute `<poly * X^shift, rhs>` in `Z_modulus[X] / (X^d + 1)`.
///
/// Multiplication by `X^shift` is a signed rotation: coefficients move forward
/// by `shift`, and coefficients that wrap past degree `d` flip sign because
/// `X^d = -1` in the negacyclic ring.
///
/// For each `poly[idx]`, the product contributes to coefficient
/// `(idx + shift) mod d`. If `idx + shift >= d`, the contribution is negated.
/// Since query generation only needs the final inner product, this routine
/// applies that signed index mapping directly and avoids materializing the
/// shifted polynomial.
#[cfg(test)]
fn negacyclic_monomial_inner_product_mod(
    poly: &[u64],
    shift: usize,
    rhs: &[u64],
    modulus: u64,
) -> u64 {
    assert_eq!(poly.len(), rhs.len());
    let degree = poly.len();
    assert!(shift < degree, "monomial shift out of bounds");

    let mut acc = 0u128;
    let modulus_u128 = u128::from(modulus);
    for (idx, coeff) in poly.iter().enumerate() {
        if *coeff == 0 {
            continue;
        }

        // `poly[idx] * X^shift` lands at `target`; wrapping across degree `d`
        // contributes `-poly[idx]` because the modulus polynomial is `X^d + 1`.
        let target = idx + shift;
        let (rhs_idx, negated) = if target < degree {
            (target, false)
        } else {
            (target - degree, true)
        };
        let coeff = u128::from(*coeff);
        let rhs_coeff = u128::from(rhs[rhs_idx]);
        let product = (coeff * rhs_coeff) % modulus_u128;
        if negated {
            acc = (acc + modulus_u128 - product) % modulus_u128;
        } else {
            acc = (acc + product) % modulus_u128;
        }
    }

    acc as u64
}

/// `c2 + c1 · s mod q`, the value decoding rounds to a multiple of `Δ`.
fn phase_of(
    params: &RlweParams,
    row_0: &[u64],
    row_1: &[u64],
    secret_ntt: &PolyMatrixNTT<'_>,
) -> Vec<u64> {
    add_poly_mod(
        row_1,
        &negacyclic_mul_ntt(params, row_0, secret_ntt),
        params.q,
    )
}

fn decode_rows(
    params: &RlweParams,
    row_0: &[u64],
    row_1: &[u64],
    secret_ntt: &PolyMatrixNTT<'_>,
) -> Vec<u64> {
    let phase = phase_of(params, row_0, row_1, secret_ntt);
    phase
        .iter()
        .map(|coeff| ((coeff + params.delta / 2) / params.delta) % params.p)
        .collect()
}

fn add_poly_mod(lhs: &[u64], rhs: &[u64], modulus: u64) -> Vec<u64> {
    lhs.iter()
        .zip(rhs)
        .map(|(x, y)| {
            debug_assert!(*x < modulus);
            debug_assert!(*y < modulus);
            if *x >= modulus - *y {
                *x - (modulus - *y)
            } else {
                *x + *y
            }
        })
        .collect()
}

fn negacyclic_mul_ntt(
    params: &RlweParams,
    left: &[u64],
    right_ntt: &PolyMatrixNTT<'_>,
) -> Vec<u64> {
    assert_eq!(left.len(), params.d);
    assert_eq!(right_ntt.rows, 1);
    assert_eq!(right_ntt.cols, 1);

    let left_ntt = polynomial_to_ntt(params, left);
    let mut product = PolyMatrixNTT::zero(&params.spiral, 1, 1);
    multiply(&mut product, &left_ntt, right_ntt);
    from_ntt_alloc(&product).get_poly(0, 0).to_vec()
}

#[cfg(test)]
fn negacyclic_mul_mod(left: &[u64], right: &[u64], modulus: u64) -> Vec<u64> {
    assert_eq!(left.len(), right.len());
    let degree = left.len();
    let mut out = vec![0u64; degree];

    for (i, left_coeff) in left.iter().enumerate() {
        for (j, right_coeff) in right.iter().enumerate() {
            let product = (*left_coeff as u128 * *right_coeff as u128) % modulus as u128;
            let idx = i + j;
            if idx < degree {
                out[idx] = ((out[idx] as u128 + product) % modulus as u128) as u64;
            } else {
                let wrapped = idx - degree;
                out[wrapped] =
                    ((out[wrapped] as u128 + modulus as u128 - product) % modulus as u128) as u64;
            }
        }
    }

    out
}

fn plaintext_modulus_bits(modulus: u64) -> usize {
    assert!(modulus > 1, "plaintext modulus must be at least 2");
    (u64::BITS - (modulus - 1).leading_zeros()) as usize
}

#[cfg(test)]
mod tests {
    use inspiring::{GadgetParams, RlweParams};
    use rand_chacha::rand_core::SeedableRng;

    use super::*;

    fn params() -> RlweParams {
        RlweParams::new(
            8,
            12289,
            4,
            3.2,
            GadgetParams {
                bits_per: 3,
                ell: 5,
            },
        )
        .expect("valid params")
    }

    /// Slow reference for the original coefficient-by-coefficient query path.
    ///
    /// Production query generation uses the NTT implementation above; tests use
    /// this helper to prove the optimized path preserves the exact query vector,
    /// including negacyclic signs and the selected-row `delta` injection.
    fn scalar_encrypted_selection_query(
        params: &RlweParams,
        offline_query: &[Vec<u64>],
        secret: &[u64],
        target_row: usize,
        db_rows: usize,
    ) -> Vec<u64> {
        let mut query = vec![0u64; db_rows];
        for (block_idx, query_poly) in offline_query.iter().enumerate() {
            for coeff_idx in 0..params.d {
                let inner =
                    negacyclic_monomial_inner_product_mod(query_poly, coeff_idx, secret, params.q);
                let row = block_idx * params.d + coeff_idx;
                // Plain branch here on purpose: the reference must stay
                // independent of the branch-free production selector.
                let encoded_selection = if row == target_row { params.delta } else { 0 };
                query[row] = sub_mod(encoded_selection, inner, params.q);
            }
        }
        query
    }

    #[test]
    fn client_secret_reduces_coefficients_mod_q() {
        let params = params();
        let secret =
            ClientSecret::from_coeffs(&params, vec![0, 1, params.q, params.q + 2, 5, 6, 7, 8]);

        assert_eq!(secret.coeffs, vec![0, 1, 0, 2, 5, 6, 7, 8]);
    }

    #[test]
    fn simple_query_packed_bytes_roundtrip() {
        let params = params();
        let query = IPIRSimpleQuery::new(vec![0, 1, 42, params.q - 1, 7, 8, 9, 10]);

        let packed = query.to_packed_bytes(params.q);
        let decoded = IPIRSimpleQuery::from_packed_bytes(&packed, query.as_slice().len(), params.q)
            .expect("packed query decodes");

        assert_eq!(
            packed.len(),
            (query.as_slice().len() * modulus_bits(params.q)).div_ceil(8)
        );
        assert_eq!(decoded, query);
    }

    #[test]
    fn gaussian_secret_matches_backend_sampler_and_expected_scale() {
        let (r, _) = params_for_simplepir(2048, 2048 * 14).unwrap();
        // Public, test-only seed: never used for real client requests.
        let seed = [0x47; 32];
        let mut rng = ChaCha20Rng::from_seed(seed);
        let secret = ClientSecret::sample_gaussian(&r, &mut rng);
        let mut reference_rng = ChaCha20Rng::from_seed(seed);
        let dg = DiscreteGaussian::init(r.spiral.noise_width);
        let mut reference = PolyMatrixRaw::zero(&r.spiral, 1, 1);
        dg.sample_matrix(&mut reference, &mut reference_rng);
        assert_eq!(secret.coeffs, reference.get_poly(0, 0));
        assert_eq!(rng.next_u64(), reference_rng.next_u64());

        let centered = |v: u64| {
            if v > r.q / 2 {
                -((r.q - v) as i64)
            } else {
                v as i64
            }
        };
        let prefix: Vec<_> = secret.coeffs[..16].iter().copied().map(centered).collect();
        assert_eq!(
            prefix,
            vec![2, -2, 7, -2, 0, 14, 4, 11, -3, -6, 2, 1, -4, -16, 3, -5]
        );
        assert!(secret.coeffs.iter().all(|v| *v < r.q));
        assert!(secret.coeffs.iter().any(|v| centered(*v) < -1));
        assert!(secret.coeffs.iter().any(|v| centered(*v) > 1));

        // Pin the *standard deviation*, catching a missing sqrt(2*pi)
        // conversion as well as an accidental return to ternary sampling.
        let mut values = Vec::new();
        for _ in 0..16 {
            values.extend(
                ClientSecret::sample_gaussian(&r, &mut rng)
                    .coeffs
                    .into_iter()
                    .map(centered),
            );
        }
        let mean = values.iter().map(|v| *v as f64).sum::<f64>() / values.len() as f64;
        let variance = values
            .iter()
            .map(|v| (*v as f64 - mean).powi(2))
            .sum::<f64>()
            / values.len() as f64;
        assert!(mean.abs() < 0.2);
        assert!((variance - r.sigma_chi.powi(2)).abs() < 2.0);
    }

    #[test]
    fn fresh_query_seed_replays_gaussian_secret_keys_and_query() {
        let (r, y) = params_for_simplepir(2048, 2048 * 14).unwrap();
        let client = IPIRClient::new(&r, &y);
        let setup = client.generate_public_query_setup_simplepir_from_seed([0x42; 32]);
        let (query, keys, seed) = client.generate_fresh_query_simplepir(&setup, 2047);
        let mut rng = ChaCha20Rng::from_seed(seed);
        let secret = ClientSecret::sample_gaussian(&r, &mut rng);
        assert_eq!(client.secret_from_seed(seed), secret);
        let expected_keys = PackingKeys::generate_full(&r, &secret.to_ntt(&r), &mut rng);
        assert_eq!(keys.kg_body.as_slice(), expected_keys.kg_body.as_slice());
        assert_eq!(keys.kh_body.as_slice(), expected_keys.kh_body.as_slice());
        assert_eq!(
            query.as_slice(),
            encrypted_selection_query(&r, &setup, &secret.coeffs, 2047, y.db_rows, &mut rng)
        );
        // There is no automatic migration of an old unversioned client seed.
        let mut old_rng = ChaCha20Rng::from_seed(seed);
        assert_ne!(
            client.secret_from_seed(seed),
            ClientSecret::sample_ternary(&r, &mut old_rng)
        );
    }

    #[test]
    fn sampled_ternary_secret_uses_mod_q_minus_one_for_negative_one() {
        let params = params();
        let mut rng = ChaCha20Rng::seed_from_u64(0x5350);

        let secret = ClientSecret::sample_ternary(&params, &mut rng);

        assert_eq!(secret.coeffs.len(), params.d);
        assert!(secret
            .coeffs
            .iter()
            .all(|coeff| matches!(*coeff, 0 | 1) || *coeff == params.q - 1));
    }

    #[test]
    fn generate_fresh_query_returns_full_packing_key_bodies() {
        let params = params();
        let ypir = crate::params::YpirSchemeParams {
            num_items: 8,
            item_size_bits: 16,
            poly_len: 8,
            db_dim_1: 0,
            db_dim_2: 1,
            instances: 1,
            db_rows: 8,
            db_cols: 8,
            p: 4,
            q_prime_1: 16,
            q_prime_2: 257,
            q2_bits: 8,
            t_exp_left: 3,
            t_exp_right: 2,
            // Tiny fixtures exercise exact arithmetic, so they transmit the
            // query at full precision.
            query_bits: 14,
        };
        let client = IPIRClient::new(&params, &ypir);
        let offline_query_polys = client.generate_public_query_setup_simplepir_from_seed([9u8; 32]);

        let (query, packing_keys, client_seed) =
            client.generate_fresh_query_simplepir(&offline_query_polys, 3);

        assert_eq!(query.as_slice().len(), ypir.db_rows);
        assert_ne!(client_seed, [0u8; 32]);
        assert_eq!(packing_keys.kg_body.rows, 1);
        assert_eq!(packing_keys.kg_body.cols, params.gadget.ell);
        assert_eq!(packing_keys.kh_body.rows, 1);
        assert_eq!(packing_keys.kh_body.cols, params.gadget.ell);
    }

    #[test]
    fn monomial_inner_product_matches_full_negacyclic_multiply() {
        let params = params();
        let poly = vec![5, 9, 0, 12280, 17, 42, 100, 2];
        let rhs = vec![3, 1, 7, 11, 13, 19, 23, 29];

        for shift in 0..params.d {
            let mut basis = vec![0u64; params.d];
            basis[shift] = 1;
            let shifted = negacyclic_mul_mod(&poly, &basis, params.q);
            let expected = shifted.iter().zip(&rhs).fold(0u64, |acc, (a, b)| {
                ((u128::from(acc) + u128::from(*a) * u128::from(*b)) % u128::from(params.q)) as u64
            });

            assert_eq!(
                negacyclic_monomial_inner_product_mod(&poly, shift, &rhs, params.q),
                expected
            );
        }
    }

    #[test]
    fn ntt_query_inner_products_match_scalar_monomial_inner_products() {
        let params = params();
        let poly = vec![5, 9, 0, 12280, 17, 42, 100, 2];
        let secret = vec![3, 1, 7, 11, 13, 19, 23, 29];

        let secret_ntt = polynomial_to_ntt(&params, &secret);
        let inner_products = query_inner_products_from_ntt(&params, &poly, &secret_ntt);

        let expected: Vec<_> = (0..params.d)
            .map(|shift| negacyclic_monomial_inner_product_mod(&poly, shift, &secret, params.q))
            .collect();
        assert_eq!(inner_products, expected);
    }

    #[test]
    fn ntt_decode_multiply_matches_scalar_negacyclic_multiply() {
        let params = params();
        let row_0 = vec![5, 9, 0, 12280, 17, 42, 100, 2];
        let secret = ClientSecret::from_coeffs(&params, vec![3, 1, 7, 11, 13, 19, 23, 29]);

        let product = negacyclic_mul_ntt(&params, &row_0, &secret.to_ntt(&params));
        let expected = negacyclic_mul_mod(&row_0, &secret.coeffs, params.q);

        assert_eq!(product, expected);
    }

    #[test]
    fn encrypted_selection_query_matches_scalar_reference() {
        let params = params();
        let offline_query = vec![
            vec![5, 9, 0, 12280, 17, 42, 100, 2],
            vec![3, 1, 4, 1, 5, 9, 2, 6],
        ];
        let secret = vec![3, 1, 7, 11, 13, 19, 23, 29];
        let target_row = 11;
        let db_rows = offline_query.len() * params.d;

        let mut rng = ChaCha20Rng::from_seed([3u8; 32]);
        let query = encrypted_selection_query(
            &params,
            &offline_query,
            &secret,
            target_row,
            db_rows,
            &mut rng,
        );
        let expected =
            scalar_encrypted_selection_query(&params, &offline_query, &secret, target_row, db_rows);

        // The NTT path must reproduce the scalar mask arithmetic exactly; the
        // only permitted difference is the freshly sampled error term, which is
        // bounded by `NUM_WIDTHS * sigma_chi * sqrt(2*pi)` (~32 at sigma 3.2).
        assert_eq!(query.len(), expected.len());
        for (row, (actual, want)) in query.iter().zip(expected.iter()).enumerate() {
            let centered = centered_difference(*actual, *want, params.q);
            assert!(
                centered.abs() <= 64,
                "row {row}: error {centered} exceeds the discrete-Gaussian bound"
            );
        }
    }

    /// Return `lhs - rhs mod q` mapped into `(-q/2, q/2]`.
    fn centered_difference(lhs: u64, rhs: u64, q: u64) -> i64 {
        let diff = sub_mod(lhs, rhs, q);
        if diff > q / 2 {
            -((q - diff) as i64)
        } else {
            diff as i64
        }
    }

    #[test]
    #[should_panic(expected = "out of range")]
    fn encrypted_selection_query_rejects_out_of_range_target_row() {
        let params = params();
        let offline_query = vec![vec![1u64; params.d], vec![2u64; params.d]];
        let secret = vec![1u64; params.d];
        let db_rows = offline_query.len() * params.d;
        let mut rng = ChaCha20Rng::from_seed([3u8; 32]);
        let _ =
            encrypted_selection_query(&params, &offline_query, &secret, db_rows, db_rows, &mut rng);
    }

    #[test]
    fn branch_free_modular_helpers_match_reference() {
        let q = params().q;
        let samples = [0, 1, 2, q / 2 - 1, q / 2, q / 2 + 1, q - 2, q - 1];
        for &lhs in &samples {
            for &rhs in &samples {
                let want_add = ((u128::from(lhs) + u128::from(rhs)) % u128::from(q)) as u64;
                let want_sub =
                    ((u128::from(lhs) + u128::from(q) - u128::from(rhs)) % u128::from(q)) as u64;
                assert_eq!(add_mod(lhs, rhs, q), want_add, "add {lhs} {rhs}");
                assert_eq!(sub_mod(lhs, rhs, q), want_sub, "sub {lhs} {rhs}");
            }
        }
        assert_eq!(select_u64(true, 7, 9), 7);
        assert_eq!(select_u64(false, 7, 9), 9);
        assert_eq!(select_u64(true, u64::MAX, 0), u64::MAX);
        assert_eq!(select_u64(false, u64::MAX, 0), 0);
    }

    #[test]
    fn encrypted_selection_query_is_randomized() {
        let params = params();
        let offline_query = vec![
            vec![5, 9, 0, 12280, 17, 42, 100, 2],
            vec![3, 1, 4, 1, 5, 9, 2, 6],
        ];
        let secret = vec![3, 1, 7, 11, 13, 19, 23, 29];
        let db_rows = offline_query.len() * params.d;

        // Same public setup, same secret, same target row: without an error term
        // the query is a deterministic function of those inputs, and the server
        // can solve for the secret and recover the target row.
        let build = |seed: [u8; 32]| {
            let mut rng = ChaCha20Rng::from_seed(seed);
            encrypted_selection_query(&params, &offline_query, &secret, 11, db_rows, &mut rng)
        };

        assert_ne!(build([1u8; 32]), build([2u8; 32]));
    }
}
