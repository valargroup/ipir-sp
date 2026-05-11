//! Client-side key material for the IPIR-SP packing layer.
//!
//! YPIR's CDKS path uploads `log d` expansion matrices. The InspiRING path
//! uploads the secret-dependent packing-key bodies for `K_g` and `K_h`; public
//! top rows are derived from fixed CRS seeds on both sides.

use inspiring::{PackingKeys, RlweParams};
use rand::{Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use spiral_rs::poly::{
    from_ntt_alloc, multiply, to_ntt_alloc, PolyMatrix, PolyMatrixNTT, PolyMatrixRaw,
};

use crate::bits::{contiguous_bytes_to_u64s, u64s_to_contiguous_bytes};
use crate::modulus_switch::modulus_bits;
use crate::modulus_switch::{recover_rlwe_rows, switched_rlwe_response_len};
use crate::params::{params_for_simplepir, YpirSchemeParams};
use crate::serialize::{deserialize_u64s_le, serialize_u64s_le};

/// Seed used to regenerate IPIR client secret material.
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

    /// Sample a ternary secret with coefficients in `{0, 1, -1 mod q}`.
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

/// Client-only setup material needed to generate online SimplePIR queries.
#[derive(Debug, Clone)]
pub struct IPIRSimpleQuerySetup {
    /// Seed used to regenerate the client secret for online query generation and decoding.
    pub client_seed: IPIRSeed,
    /// Offline query polynomials, one per `d`-row database block.
    pub offline_query_polys: Vec<Vec<u64>>,
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

    /// Serialize as little-endian `u64` coefficients.
    ///
    /// This is the original uncompressed query encoding. New callers should
    /// prefer [`Self::to_packed_bytes`] to avoid uploading unused high bits.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        serialize_u64s_le(&self.first_dim)
    }

    /// Serialize query coefficients using the exact bit width of `modulus`.
    ///
    /// For the production 56-bit IPIR-SP modulus this saves one byte per query
    /// coefficient compared with [`Self::to_bytes`].
    #[must_use]
    pub fn to_packed_bytes(&self, modulus: u64) -> Vec<u8> {
        u64s_to_contiguous_bytes(&self.first_dim, modulus_bits(modulus))
    }

    /// Parse a query serialized by [`Self::to_bytes`].
    pub fn from_bytes(data: &[u8]) -> Result<Self, inspiring::InspiringError> {
        deserialize_u64s_le(data).map(Self::new)
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

    /// Generate only the client-side setup material needed for online queries.
    ///
    /// This exists for tests that need a deterministic query secret. Production
    /// callers with public CRS setup use [`Self::generate_fresh_query_simplepir`].
    pub fn generate_query_setup_simplepir_from_seed(
        &self,
        client_seed: IPIRSeed,
    ) -> IPIRSimpleQuerySetup {
        assert_eq!(
            self.ypir.db_rows % self.rlwe.d,
            0,
            "db rows must split into d-row blocks"
        );

        let mut rng = ChaCha20Rng::from_seed(client_seed);
        let _secret = ClientSecret::sample_ternary(&self.rlwe, &mut rng);
        let offline_query_polys = (0..self.ypir.db_rows / self.rlwe.d)
            .map(|_| {
                (0..self.rlwe.d)
                    .map(|_| rng.gen_range(0..self.rlwe.q))
                    .collect()
            })
            .collect();

        IPIRSimpleQuerySetup {
            client_seed,
            offline_query_polys,
        }
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
        let mut client_seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut client_seed);
        let mut rng = ChaCha20Rng::from_seed(client_seed);
        let secret = ClientSecret::sample_ternary(&self.rlwe, &mut rng);
        let secret_ntt = secret.to_ntt(&self.rlwe);
        let packing_keys = PackingKeys::generate_full(&self.rlwe, &secret_ntt, &mut rng);
        let first_dim = encrypted_selection_query(
            &self.rlwe,
            offline_query_polys,
            &secret.coeffs,
            target_row,
            self.ypir.db_rows,
        );

        (IPIRSimpleQuery::new(first_dim), packing_keys, client_seed)
    }

    /// Generate an online SimplePIR query from client-only setup material.
    pub fn generate_query_simplepir_from_query_setup(
        &self,
        setup: &IPIRSimpleQuerySetup,
        target_row: usize,
    ) -> (IPIRSimpleQuery, IPIRSeed) {
        assert!(target_row < self.ypir.db_rows, "target row out of bounds");
        assert_eq!(
            setup.offline_query_polys.len(),
            self.ypir.db_rows / self.rlwe.d,
            "setup offline query count does not match params"
        );

        let secret = self.secret_from_seed(setup.client_seed);
        let first_dim = encrypted_selection_query(
            &self.rlwe,
            &setup.offline_query_polys,
            &secret.coeffs,
            target_row,
            self.ypir.db_rows,
        );

        (IPIRSimpleQuery::new(first_dim), setup.client_seed)
    }

    /// Decode serialized response bytes into contiguous plaintext bytes.
    #[must_use]
    pub fn decode_response_simplepir(&self, client_seed: IPIRSeed, response: &[u8]) -> Vec<u8> {
        let decoded = self.decode_response_simplepir_raw(client_seed, response);
        u64s_to_contiguous_bytes(&decoded, plaintext_modulus_bits(self.rlwe.p))
    }

    /// Decode serialized response bytes into plaintext coefficients.
    #[must_use]
    pub fn decode_response_simplepir_raw(
        &self,
        client_seed: IPIRSeed,
        response: &[u8],
    ) -> Vec<u64> {
        let response_len =
            switched_rlwe_response_len(self.rlwe.d, self.ypir.q_prime_1, self.ypir.q_prime_2);
        let expected_len = (self.ypir.db_cols / self.rlwe.d) * response_len;
        assert_eq!(
            response.len(),
            expected_len,
            "serialized response length mismatch"
        );

        let secret = self.secret_from_seed(client_seed);
        let mut decoded = Vec::with_capacity(self.ypir.db_cols);
        for chunk in response.chunks_exact(response_len) {
            let (row_0, row_1) = recover_rlwe_rows(
                chunk,
                self.rlwe.d,
                self.ypir.q_prime_1,
                self.ypir.q_prime_2,
                self.rlwe.q,
            );
            decoded.extend(decode_rows(&self.rlwe, &row_0, &row_1, &secret.coeffs));
        }
        decoded
    }

    fn secret_from_seed(&self, client_seed: IPIRSeed) -> ClientSecret {
        let mut rng = ChaCha20Rng::from_seed(client_seed);
        ClientSecret::sample_ternary(&self.rlwe, &mut rng)
    }
}

fn encrypted_selection_query(
    params: &RlweParams,
    offline_query: &[Vec<u64>],
    secret: &[u64],
    target_row: usize,
    db_rows: usize,
) -> Vec<u64> {
    assert_eq!(db_rows % params.d, 0);
    assert_eq!(offline_query.len(), db_rows / params.d);

    let mut query = vec![0u64; db_rows];
    let secret_ntt = polynomial_to_ntt(params, secret);
    for (block_idx, query_poly) in offline_query.iter().enumerate() {
        let inner_products = query_inner_products_from_ntt(params, query_poly, &secret_ntt);
        for (coeff_idx, inner) in inner_products.iter().enumerate() {
            let row = block_idx * params.d + coeff_idx;
            let encoded_selection = if row == target_row { params.delta } else { 0 };
            query[row] = sub_mod(encoded_selection, *inner, params.q);
        }
    }

    query
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
    if lhs >= rhs {
        lhs - rhs
    } else {
        modulus - (rhs - lhs)
    }
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

fn decode_rows(params: &RlweParams, row_0: &[u64], row_1: &[u64], secret: &[u64]) -> Vec<u64> {
    let phase = add_poly_mod(
        row_1,
        &negacyclic_mul_mod(row_0, secret, params.q),
        params.q,
    );
    phase
        .iter()
        .map(|coeff| ((coeff + params.delta / 2) / params.delta) % params.p)
        .collect()
}

fn add_poly_mod(lhs: &[u64], rhs: &[u64], modulus: u64) -> Vec<u64> {
    lhs.iter()
        .zip(rhs)
        .map(|(x, y)| ((u128::from(*x) + u128::from(*y)) % u128::from(modulus)) as u64)
        .collect()
}

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
    fn encrypted_selection_query_matches_scalar_reference() {
        let params = params();
        let offline_query = vec![
            vec![5, 9, 0, 12280, 17, 42, 100, 2],
            vec![3, 1, 4, 1, 5, 9, 2, 6],
        ];
        let secret = vec![3, 1, 7, 11, 13, 19, 23, 29];
        let target_row = 11;
        let db_rows = offline_query.len() * params.d;

        let query =
            encrypted_selection_query(&params, &offline_query, &secret, target_row, db_rows);
        let expected =
            scalar_encrypted_selection_query(&params, &offline_query, &secret, target_row, db_rows);

        assert_eq!(query, expected);
    }
}
