//! Client-side key material for the IPIR-SP packing layer.
//!
//! YPIR's CDKS path uploads `log d` expansion matrices. The InspiRING path
//! instead uploads two key-switching matrices per preprocessing block:
//! `K_g = KS.Setup(τ_g(s) -> s)` and `K_h = KS.Setup(τ_h(s) -> s)`.

use inspiring::automorph::{h, tau_g_pow, tau_ntt};
use inspiring::key_switching::{ks_setup, KeySwitchingMatrix};
use inspiring::RlweParams;
use rand::{Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use spiral_rs::poly::{to_ntt_alloc, PolyMatrix, PolyMatrixRaw};

use crate::bits::u64s_to_contiguous_bytes;
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

/// Generate one `(K_g, K_h)` pair from a base secret.
pub fn generate_ks_pair<'a>(
    params: &'a RlweParams,
    secret: &ClientSecret,
    rng: &mut ChaCha20Rng,
) -> (KeySwitchingMatrix<'a>, KeySwitchingMatrix<'a>) {
    let s = secret.to_ntt(params);
    let tau_g_s = tau_ntt(&s, tau_g_pow(1, params.d));
    let tau_h_s = tau_ntt(&s, h(params.d));

    let kg = ks_setup(params, &tau_g_s, &s, rng);
    let kh = ks_setup(params, &tau_h_s, &s, rng);

    (kg, kh)
}

/// Generate `count` owned `(K_g, K_h)` pairs for preprocessing blocks.
///
/// `PackPreprocessed` owns its keys, so callers that build many blocks need
/// many owned pairs. They all encode the same automorphic source/target secret
/// relation, but use fresh setup randomness from `rng`.
pub fn generate_ks_pairs<'a>(
    params: &'a RlweParams,
    secret: &ClientSecret,
    count: usize,
    rng: &mut ChaCha20Rng,
) -> Vec<(KeySwitchingMatrix<'a>, KeySwitchingMatrix<'a>)> {
    (0..count)
        .map(|_| generate_ks_pair(params, secret, rng))
        .collect()
}

/// High-level IPIR client facade with a YPIR-shaped API.
#[derive(Debug, Clone)]
pub struct IPIRClient {
    rlwe: RlweParams,
    ypir: YpirSchemeParams,
}

/// Client-generated setup material consumed by the server's offline phase.
pub struct IPIRSimpleSetup<'a> {
    /// Seed used to regenerate the client secret for online query generation and decoding.
    pub client_seed: IPIRSeed,
    /// Offline query polynomials, one per `d`-row database block.
    pub offline_query_polys: Vec<Vec<u64>>,
    /// One `(K_g, K_h)` key-switching pair per response RLWE block.
    pub key_pairs: Vec<(KeySwitchingMatrix<'a>, KeySwitchingMatrix<'a>)>,
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

    /// Serialize as little-endian `u64` coefficients, matching the `/query` body.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        serialize_u64s_le(&self.first_dim)
    }

    /// Parse a query serialized by [`Self::to_bytes`].
    pub fn from_bytes(data: &[u8]) -> Result<Self, inspiring::InspiringError> {
        deserialize_u64s_le(data).map(Self::new)
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

    /// Generate setup material with a fresh random seed.
    pub fn generate_setup_simplepir(&self) -> IPIRSimpleSetup<'_> {
        let mut seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        self.generate_setup_simplepir_from_seed(seed)
    }

    /// Generate setup material deterministically from `client_seed`.
    pub fn generate_setup_simplepir_from_seed(&self, client_seed: IPIRSeed) -> IPIRSimpleSetup<'_> {
        assert_eq!(
            self.ypir.db_rows % self.rlwe.d,
            0,
            "db rows must split into d-row blocks"
        );
        assert_eq!(
            self.ypir.db_cols % self.rlwe.d,
            0,
            "db cols must split into RLWE output blocks"
        );

        let mut rng = ChaCha20Rng::from_seed(client_seed);
        let secret = ClientSecret::sample_ternary(&self.rlwe, &mut rng);
        let offline_query_polys = (0..self.ypir.db_rows / self.rlwe.d)
            .map(|_| {
                (0..self.rlwe.d)
                    .map(|_| rng.gen_range(0..self.rlwe.q))
                    .collect()
            })
            .collect();
        let key_pairs = generate_ks_pairs(
            &self.rlwe,
            &secret,
            self.ypir.db_cols / self.rlwe.d,
            &mut rng,
        );

        IPIRSimpleSetup {
            client_seed,
            offline_query_polys,
            key_pairs,
        }
    }

    /// Generate only the client-side setup material needed for online queries.
    ///
    /// This follows the same RNG stream as [`Self::generate_setup_simplepir_from_seed`]
    /// through the offline query polynomials, but skips the server-only
    /// key-switching matrices.
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

    /// Generate an online SimplePIR query for `target_row`.
    pub fn generate_query_simplepir(
        &self,
        setup: &IPIRSimpleSetup<'_>,
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
    for (block_idx, query_poly) in offline_query.iter().enumerate() {
        for coeff_idx in 0..params.d {
            let inner =
                negacyclic_monomial_inner_product_mod(query_poly, coeff_idx, secret, params.q);
            let row = block_idx * params.d + coeff_idx;
            let encoded_selection = if row == target_row { params.delta } else { 0 };
            query[row] = (params.q + encoded_selection - inner) % params.q;
        }
    }

    query
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

    #[test]
    fn client_secret_reduces_coefficients_mod_q() {
        let params = params();
        let secret =
            ClientSecret::from_coeffs(&params, vec![0, 1, params.q, params.q + 2, 5, 6, 7, 8]);

        assert_eq!(secret.coeffs, vec![0, 1, 0, 2, 5, 6, 7, 8]);
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
    fn generate_ks_pair_returns_two_expected_matrix_shapes() {
        let params = params();
        let secret = ClientSecret::from_coeffs(&params, vec![1, 0, params.q - 1, 1, 0, 1, 0, 0]);
        let mut rng = ChaCha20Rng::seed_from_u64(0xBEEF);

        let (kg, kh) = generate_ks_pair(&params, &secret, &mut rng);

        assert_eq!(kg.mat.rows, 2);
        assert_eq!(kg.mat.cols, params.gadget.ell);
        assert_eq!(kh.mat.rows, 2);
        assert_eq!(kh.mat.cols, params.gadget.ell);
        assert_eq!(kg.params.q, params.q);
        assert_eq!(kh.params.q, params.q);
    }

    #[test]
    fn generate_ks_pair_is_deterministic_under_fixed_seed() {
        let params = params();
        let secret = ClientSecret::from_coeffs(&params, vec![1, 0, params.q - 1, 1, 0, 1, 0, 0]);
        let mut left_rng = ChaCha20Rng::seed_from_u64(0xC0DE);
        let mut right_rng = ChaCha20Rng::seed_from_u64(0xC0DE);

        let left = generate_ks_pair(&params, &secret, &mut left_rng);
        let right = generate_ks_pair(&params, &secret, &mut right_rng);

        assert_eq!(left.0.mat.as_slice(), right.0.mat.as_slice());
        assert_eq!(left.1.mat.as_slice(), right.1.mat.as_slice());
    }

    #[test]
    fn generate_ks_pairs_returns_owned_pair_per_block() {
        let params = params();
        let secret = ClientSecret::from_coeffs(&params, vec![1, 0, params.q - 1, 1, 0, 1, 0, 0]);
        let mut rng = ChaCha20Rng::seed_from_u64(0xFACE);

        let pairs = generate_ks_pairs(&params, &secret, 3, &mut rng);

        assert_eq!(pairs.len(), 3);
        assert_eq!(pairs[2].0.mat.rows, 2);
        assert_eq!(pairs[2].1.mat.cols, params.gadget.ell);
    }

    #[test]
    fn query_setup_skips_server_keys_but_keeps_offline_polys() {
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
        let seed = [9u8; 32];

        let full = client.generate_setup_simplepir_from_seed(seed);
        let query_only = client.generate_query_setup_simplepir_from_seed(seed);

        assert_eq!(query_only.client_seed, full.client_seed);
        assert_eq!(query_only.offline_query_polys, full.offline_query_polys);
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
}
