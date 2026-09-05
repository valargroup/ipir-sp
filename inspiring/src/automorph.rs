//! Galois automorphisms `τ_g`, `τ_h`, and iterated `τ_g^j`.
//!
//! See SPEC.md §2 (Galois group) and §3 (Lemma 1, the trace operator).
//!
//! - `τ_g(p)(X) = p(X^5)` generates the `Z_{d/2}` factor of `Gal(R)`.
//! - `τ_h(p)(X) = p(X^{2d-1})` generates the `Z_2` factor.
//!
//! Both are realised by [`spiral_rs::poly::automorph_alloc`] which is
//! generic in the exponent. We add helpers for the iterated `τ_g^j`
//! (we cache the precomputed exponents `5^j mod 2d`) and NTT-form slot
//! permutations for the hot path.

use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use spiral_rs::poly::{
    automorph_alloc, from_ntt_alloc, to_ntt_alloc, PolyMatrix, PolyMatrixNTT, PolyMatrixRaw,
};
use std::collections::HashMap;

use crate::params::RlweParams;

/// The fixed generator of the `Z_{d/2}` factor of `Gal(R)`, per SPEC.md §2.
pub const G: u64 = 5;

/// `h = 2d − 1`, the generator of the `Z_2` factor of `Gal(R)`,
/// per SPEC.md §2.
#[must_use]
pub const fn h(d: usize) -> u64 {
    (2 * d as u64) - 1
}

/// `5^j mod 2d`, the exponent passed to `spiral_rs::poly::automorph` to
/// realise `τ_g^j`. SPEC.md §2.
///
#[must_use]
pub fn tau_g_pow(j: usize, d: usize) -> u64 {
    let modulus = 2 * d as u64;
    let mut acc = 1_u64;
    let mut base = G % modulus;
    let mut exp = j;

    while exp > 0 {
        if exp & 1 == 1 {
            acc = (u128::from(acc) * u128::from(base) % u128::from(modulus)) as u64;
        }
        base = (u128::from(base) * u128::from(base) % u128::from(modulus)) as u64;
        exp >>= 1;
    }

    acc
}

/// In-place application of `τ_t` to a coefficient-form polynomial matrix.
/// Trivial passthrough to [`spiral_rs::poly::automorph`]; declared here so
/// callers don't need to import spiral-rs directly.
///
pub fn tau_raw<'a>(a: &PolyMatrixRaw<'a>, t: u64) -> PolyMatrixRaw<'a> {
    automorph_alloc(a, t as usize)
}

/// NTT-slot permutation table for one automorphism exponent `t`.
///
/// In coefficient form, `τ_t` is the negacyclic substitution
/// `p(X) -> p(X^t)` for odd `t mod 2d`. In NTT form the same operation is only
/// a permutation of the evaluation slots, so applying it does not require an
/// inverse NTT, coefficient-domain automorphism, and forward NTT.
///
/// The table stores the permutation in output-to-input form:
/// `out[j] = input[indices[j]]`. This layout matches the request-time packing
/// key expansion loop, which writes fresh `K_g` body images from an uploaded
/// NTT-domain body row.
#[derive(Clone)]
pub struct NttAutomorphTable {
    exponent: u64,
    indices: Box<[u32]>,
}

impl NttAutomorphTable {
    /// Automorphism exponent modulo `2d`.
    #[must_use]
    pub fn exponent(&self) -> u64 {
        self.exponent
    }

    /// Output-slot to input-slot permutation.
    ///
    /// The slice length is exactly `d`, the RLWE polynomial degree. The entries
    /// are `u32` rather than `usize` to keep the full table cache compact; all
    /// supported parameter sets have `d` far below `u32::MAX`.
    ///
    /// # Invariant
    ///
    /// Every entry is `< d`: the table is a permutation of the NTT slots, so it
    /// is a bijection on `0..d` by construction. [`Self::validate_permutation`]
    /// checks it, and the packing hot loop depends on it to index operand
    /// slices without a per-element bounds check.
    #[must_use]
    pub fn indices(&self) -> &[u32] {
        &self.indices
    }

    /// Build a table, enforcing the permutation invariant at construction.
    ///
    /// # Panics
    ///
    /// Panics if `indices` is not a bijection on `0..d`. This is deliberately a
    /// hard panic in release builds, not a `debug_assert`: the packing hot loop
    /// indexes operand slices as `indices[dst] & (d - 1)` rather than with a
    /// bounds check, so a table violating the invariant would silently read the
    /// wrong slot and return a wrong plaintext instead of failing. Tables are
    /// built once per parameter set and cached, so the `O(d)` check costs
    /// nothing measurable against preprocessing.
    #[must_use]
    fn new_checked(exponent: u64, indices: Box<[u32]>, d: usize) -> Self {
        let table = Self { exponent, indices };
        assert!(
            table.validate_permutation(d),
            "NTT automorphism table for exponent {exponent} is not a permutation of 0..{d}; \
             the packing hot loop's index masking depends on this invariant"
        );
        table
    }

    /// Check that the table really is a permutation of `0..d`.
    ///
    /// Construction-time only. The packing hot loop reads operand slices at
    /// `indices[dst] & (d - 1)`, which is the identity given this invariant and
    /// lets the bound be proven statically; if the invariant were ever violated
    /// the mask would silently read the wrong slot instead of panicking, so the
    /// check belongs here, once, rather than nowhere.
    pub fn validate_permutation(&self, d: usize) -> bool {
        if self.indices.len() != d {
            return false;
        }
        let mut seen = vec![false; d];
        for &index in self.indices.iter() {
            let index = index as usize;
            if index >= d || seen[index] {
                return false;
            }
            seen[index] = true;
        }
        true
    }
}

/// Build one NTT-domain automorphism table by matching NTT slots against the
/// existing coefficient-domain automorphism.
///
/// This is used for the two generators (`τ_g` and `τ_h`) when constructing the
/// full request-time table cache. The fixed random probes make the discovered
/// slot ordering deterministic while remaining independent of spiral-rs's
/// internal NTT ordering.
///
/// The matching uses two independent random probe polynomials so each NTT slot
/// is identified by a pair of residues. If a collision occurs, the function
/// retries with a different deterministic seed. At the current 28-bit modulus
/// and `d <= 2048`, collisions are already unlikely for a single probe; the
/// paired probe makes the chance negligible while keeping table construction a
/// one-time setup cost.
///
/// # Panics
///
/// Panics if `exponent` is even modulo `2d`, or if every deterministic probe
/// attempt collides. The latter would indicate either an unexpectedly tiny
/// modulus/degree combination or an incompatible NTT representation.
#[must_use]
pub fn ntt_automorph_table(params: &RlweParams, exponent: u64) -> NttAutomorphTable {
    let two_d = 2 * params.d as u64;
    let exponent = exponent % two_d;
    assert!(
        exponent % 2 == 1,
        "automorphism exponent must be odd modulo 2d"
    );

    for attempt in 0..16_u64 {
        let mut rng = ChaCha20Rng::seed_from_u64(0xA770_0000 + attempt);
        let probe_a = PolyMatrixRaw::random_rng(&params.spiral, 1, 1, &mut rng);
        let probe_b = PolyMatrixRaw::random_rng(&params.spiral, 1, 1, &mut rng);
        let probe_a_ntt = to_ntt_alloc(&probe_a);
        let probe_b_ntt = to_ntt_alloc(&probe_b);
        let auto_a_ntt = to_ntt_alloc(&tau_raw(&probe_a, exponent));
        let auto_b_ntt = to_ntt_alloc(&tau_raw(&probe_b, exponent));

        if let Some(indices) =
            match_probe_slots(params, &probe_a_ntt, &probe_b_ntt, &auto_a_ntt, &auto_b_ntt)
        {
            return NttAutomorphTable::new_checked(exponent, indices, params.d);
        }
    }

    panic!("failed to build collision-free NTT automorphism table");
}

/// Build the left and right `τ_g^i` table families used by full InspiRING
/// packing-key expansion.
///
/// The returned vectors have length `count`. Entry `i` in the left vector is
/// the table for `τ_g^i`; entry `i` in the right vector is the corresponding
/// `τ_g^i ∘ τ_h` table. These are exactly the two `K_g` image families consumed
/// by the full-dimension InspiRING collapse.
///
/// Only the two generator tables (`τ_g` and `τ_h`) are discovered from probes.
/// The remaining powers are created by table composition, avoiding thousands of
/// coefficient-domain automorphism round trips during server startup.
#[must_use]
pub fn tau_g_power_tables(
    params: &RlweParams,
    count: usize,
) -> (Vec<NttAutomorphTable>, Vec<NttAutomorphTable>) {
    let two_d = 2 * params.d as u64;
    let g_table = ntt_automorph_table(params, G % two_d);
    let h_table = ntt_automorph_table(params, h(params.d));
    let mut current = identity_table(params);
    let mut left = Vec::with_capacity(count);
    let mut right = Vec::with_capacity(count);

    for _ in 0..count {
        left.push(current.clone());
        right.push(compose_tables(
            params,
            &current,
            &h_table,
            (current.exponent * h_table.exponent) % two_d,
        ));
        current = compose_tables(
            params,
            &current,
            &g_table,
            (current.exponent * g_table.exponent) % two_d,
        );
    }

    (left, right)
}

/// Apply `τ_t` to an NTT-form polynomial matrix using a precomputed table.
///
/// `out` and `input` must have identical matrix shape and polynomial degree.
/// The function overwrites `out`; it does not add into the destination. It also
/// handles all CRT chunks present in the underlying spiral-rs NTT layout, though
/// the current InspiRING parameter sets use a single CRT modulus.
///
/// # Panics
///
/// Panics if the matrix shapes differ or if `table` was built for a different
/// polynomial degree.
pub fn apply_tau_ntt_into<'a>(
    out: &mut PolyMatrixNTT<'a>,
    input: &PolyMatrixNTT<'a>,
    table: &NttAutomorphTable,
) {
    assert_eq!(out.rows, input.rows);
    assert_eq!(out.cols, input.cols);
    assert_eq!(out.params.poly_len, input.params.poly_len);
    assert_eq!(table.indices.len(), input.params.poly_len);

    let d = input.params.poly_len;
    for row in 0..input.rows {
        for col in 0..input.cols {
            let input_poly = input.get_poly(row, col);
            let out_poly = out.get_poly_mut(row, col);
            for (input_chunk, out_chunk) in
                input_poly.chunks_exact(d).zip(out_poly.chunks_exact_mut(d))
            {
                for (dst_idx, src_idx) in table.indices.iter().enumerate() {
                    out_chunk[dst_idx] = input_chunk[*src_idx as usize];
                }
            }
        }
    }
}

/// Allocate and apply `τ_t` to an NTT-form polynomial matrix.
///
/// This is a convenience wrapper for setup-time paths. Request-time code should
/// prefer [`apply_tau_ntt_into`] or [`apply_tau_ntt_double_into`] to reuse
/// destination buffers and avoid unnecessary allocations.
#[must_use]
pub fn apply_tau_ntt_alloc<'a>(
    input: &PolyMatrixNTT<'a>,
    table: &NttAutomorphTable,
) -> PolyMatrixNTT<'a> {
    let mut out = PolyMatrixNTT::zero(input.params, input.rows, input.cols);
    apply_tau_ntt_into(&mut out, input, table);
    out
}

/// Apply the paired `τ_t` and `τ_{-t}` images in one pass over the input.
///
/// Full InspiRING packing expands both the left `τ_g^i(K_g)` and right
/// `τ_g^i τ_h(K_g)` image families from the same uploaded body row. Since
/// `τ_h` is negation in the Galois group (`h = 2d - 1`), those two exponents
/// are paired as `t` and `-t mod 2d`. This helper mirrors the upstream
/// InsPIRe implementation by reading the input NTT slots once and writing both
/// output images.
///
/// `left_table` and `right_table` are not required to be mathematically paired;
/// tests and callers enforce that pairing where it matters. Keeping the helper
/// generic makes it useful as a correctness primitive for arbitrary table pairs.
///
/// # Panics
///
/// Panics if either output matrix has a different shape from `input`, or if a
/// table was built for a different polynomial degree.
pub fn apply_tau_ntt_double_into<'a>(
    out_left: &mut PolyMatrixNTT<'a>,
    out_right: &mut PolyMatrixNTT<'a>,
    input: &PolyMatrixNTT<'a>,
    left_table: &NttAutomorphTable,
    right_table: &NttAutomorphTable,
) {
    assert_eq!(out_left.rows, input.rows);
    assert_eq!(out_left.cols, input.cols);
    assert_eq!(out_right.rows, input.rows);
    assert_eq!(out_right.cols, input.cols);
    assert_eq!(left_table.indices.len(), input.params.poly_len);
    assert_eq!(right_table.indices.len(), input.params.poly_len);

    let d = input.params.poly_len;
    for row in 0..input.rows {
        for col in 0..input.cols {
            let input_poly = input.get_poly(row, col);
            let left_poly = out_left.get_poly_mut(row, col);
            let right_poly = out_right.get_poly_mut(row, col);
            for ((input_chunk, left_chunk), right_chunk) in input_poly
                .chunks_exact(d)
                .zip(left_poly.chunks_exact_mut(d))
                .zip(right_poly.chunks_exact_mut(d))
            {
                for dst_idx in 0..d {
                    left_chunk[dst_idx] = input_chunk[left_table.indices[dst_idx] as usize];
                    right_chunk[dst_idx] = input_chunk[right_table.indices[dst_idx] as usize];
                }
            }
        }
    }
}

/// `τ_t` for an NTT-form polynomial matrix.
///
/// This stable wrapper intentionally remains the coefficient-domain oracle:
/// it round-trips through [`tau_raw`] and is used by tests to validate the
/// faster table-based helpers. Hot paths should use precomputed
/// [`NttAutomorphTable`] values instead.
pub fn tau_ntt<'a>(a: &PolyMatrixNTT<'a>, t: u64) -> PolyMatrixNTT<'a> {
    to_ntt_alloc(&tau_raw(&from_ntt_alloc(a), t))
}

/// Lemma 1's trace `Tr(p) = Σ_{j=0}^{d/2-1} τ_g^j(p) + τ_h ∘ τ_g^j(p)`
/// (SPEC.md §3). Used by `tests/lemma1_trace.rs`.
///
pub fn trace<'a>(p: &PolyMatrixRaw<'a>) -> PolyMatrixRaw<'a> {
    let d = p.params.poly_len;
    let two_d = 2 * d as u64;
    let h_d = h(d);
    let mut out = PolyMatrixRaw::zero(p.params, p.rows, p.cols);

    for j in 0..(d / 2) {
        let gj = tau_g_pow(j, d);
        let left = tau_raw(p, gj);
        let right = tau_raw(p, (gj * h_d) % two_d);
        add_assign_raw_mod(&mut out, &left);
        add_assign_raw_mod(&mut out, &right);
    }

    out
}

fn add_assign_raw_mod(out: &mut PolyMatrixRaw<'_>, rhs: &PolyMatrixRaw<'_>) {
    debug_assert_eq!(out.rows, rhs.rows);
    debug_assert_eq!(out.cols, rhs.cols);

    let q = out.params.modulus;
    for row in 0..out.rows {
        for col in 0..out.cols {
            let out_poly = out.get_poly_mut(row, col);
            let rhs_poly = rhs.get_poly(row, col);
            for (out_coeff, rhs_coeff) in out_poly.iter_mut().zip(rhs_poly) {
                *out_coeff = (*out_coeff + *rhs_coeff) % q;
            }
        }
    }
}

fn identity_table(params: &RlweParams) -> NttAutomorphTable {
    NttAutomorphTable::new_checked(
        1,
        (0..params.d as u32).collect::<Vec<_>>().into_boxed_slice(),
        params.d,
    )
}

fn compose_tables(
    params: &RlweParams,
    first: &NttAutomorphTable,
    second: &NttAutomorphTable,
    exponent: u64,
) -> NttAutomorphTable {
    debug_assert_eq!(first.indices.len(), params.d);
    debug_assert_eq!(second.indices.len(), params.d);
    let indices = (0..params.d)
        .map(|idx| first.indices[second.indices[idx] as usize])
        .collect::<Vec<_>>()
        .into_boxed_slice();
    NttAutomorphTable::new_checked(exponent, indices, params.d)
}

fn match_probe_slots(
    params: &RlweParams,
    probe_a: &PolyMatrixNTT<'_>,
    probe_b: &PolyMatrixNTT<'_>,
    auto_a: &PolyMatrixNTT<'_>,
    auto_b: &PolyMatrixNTT<'_>,
) -> Option<Box<[u32]>> {
    let mut positions = HashMap::with_capacity(params.d);
    let a = probe_a.get_poly(0, 0);
    let b = probe_b.get_poly(0, 0);
    for idx in 0..params.d {
        if positions.insert((a[idx], b[idx]), idx as u32).is_some() {
            return None;
        }
    }

    let auto_a = auto_a.get_poly(0, 0);
    let auto_b = auto_b.get_poly(0, 0);
    let mut indices = Vec::with_capacity(params.d);
    for idx in 0..params.d {
        let src = positions.get(&(auto_a[idx], auto_b[idx]))?;
        indices.push(*src);
    }

    Some(indices.into_boxed_slice())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::{GadgetParams, RlweParams};

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

    fn raw_from_coeffs<'a>(params: &'a RlweParams, coeffs: &[u64]) -> PolyMatrixRaw<'a> {
        let mut poly = PolyMatrixRaw::zero(&params.spiral, 1, 1);
        poly.get_poly_mut(0, 0).copy_from_slice(coeffs);
        poly
    }

    fn raw_matrix<'a>(params: &'a RlweParams, rows: usize, cols: usize) -> PolyMatrixRaw<'a> {
        let mut matrix = PolyMatrixRaw::zero(&params.spiral, rows, cols);
        for row in 0..rows {
            for col in 0..cols {
                for coeff in 0..params.d {
                    matrix.get_poly_mut(row, col)[coeff] =
                        (1 + row * 100 + col * 10 + coeff) as u64;
                }
            }
        }
        matrix
    }

    fn coeffs(poly: &PolyMatrixRaw<'_>) -> Vec<u64> {
        poly.get_poly(0, 0).to_vec()
    }

    fn ntt_coeffs(poly: &PolyMatrixNTT<'_>) -> Vec<u64> {
        coeffs(&from_ntt_alloc(poly))
    }

    #[test]
    fn h_returns_negation_exponent() {
        assert_eq!(h(8), 15);
        assert_eq!(h(16), 31);
    }

    #[test]
    fn tau_g_pow_returns_powers_mod_2d() {
        assert_eq!(tau_g_pow(0, 8), 1);
        assert_eq!(tau_g_pow(1, 8), 5);
        assert_eq!(tau_g_pow(2, 8), 9);
        assert_eq!(tau_g_pow(3, 8), 13);
        assert_eq!(tau_g_pow(4, 8), 1);
    }

    #[test]
    fn tau_raw_applies_negacyclic_automorphism() {
        let params = params();
        let poly = raw_from_coeffs(&params, &[1, 2, 3, 4, 5, 6, 7, 8]);

        assert_eq!(
            coeffs(&tau_raw(&poly, h(params.d))),
            vec![1, 12281, 12282, 12283, 12284, 12285, 12286, 12287]
        );
    }

    #[test]
    fn tau_ntt_matches_tau_raw_after_round_trip() {
        let params = params();
        let poly = raw_from_coeffs(&params, &[9, 8, 7, 6, 5, 4, 3, 2]);
        let exponent = tau_g_pow(2, params.d);

        assert_eq!(
            ntt_coeffs(&tau_ntt(&to_ntt_alloc(&poly), exponent)),
            coeffs(&tau_raw(&poly, exponent))
        );
    }

    #[test]
    fn ntt_table_automorphism_matches_round_trip_for_all_odd_exponents() {
        let params = params();
        let poly = raw_from_coeffs(&params, &[9, 8, 7, 6, 5, 4, 3, 2]);
        let input_ntt = to_ntt_alloc(&poly);

        for exponent in (1..2 * params.d as u64).step_by(2) {
            let table = ntt_automorph_table(&params, exponent);
            let actual = apply_tau_ntt_alloc(&input_ntt, &table);
            let expected = to_ntt_alloc(&tau_raw(&poly, exponent));

            assert_eq!(
                actual.as_slice(),
                expected.as_slice(),
                "exponent {exponent}"
            );
        }
    }

    #[test]
    fn ntt_table_automorphism_handles_multi_polynomial_matrices() {
        let params = params();
        let matrix = raw_matrix(&params, 2, 3);
        let input_ntt = to_ntt_alloc(&matrix);
        let exponent = tau_g_pow(2, params.d);
        let table = ntt_automorph_table(&params, exponent);
        let mut actual = PolyMatrixNTT::zero(&params.spiral, 2, 3);

        apply_tau_ntt_into(&mut actual, &input_ntt, &table);
        let expected = to_ntt_alloc(&tau_raw(&matrix, exponent));

        assert_eq!(actual.as_slice(), expected.as_slice());
    }

    #[test]
    fn double_ntt_automorphism_matches_independent_applications() {
        let params = params();
        let matrix = raw_matrix(&params, 1, 2);
        let input_ntt = to_ntt_alloc(&matrix);
        let left_exp = tau_g_pow(1, params.d);
        let right_exp = (left_exp * h(params.d)) % (2 * params.d as u64);
        let left_table = ntt_automorph_table(&params, left_exp);
        let right_table = ntt_automorph_table(&params, right_exp);
        let mut actual_left = PolyMatrixNTT::zero(&params.spiral, 1, 2);
        let mut actual_right = PolyMatrixNTT::zero(&params.spiral, 1, 2);

        apply_tau_ntt_double_into(
            &mut actual_left,
            &mut actual_right,
            &input_ntt,
            &left_table,
            &right_table,
        );

        let expected_left = to_ntt_alloc(&tau_raw(&matrix, left_exp));
        let expected_right = to_ntt_alloc(&tau_raw(&matrix, right_exp));
        assert_eq!(actual_left.as_slice(), expected_left.as_slice());
        assert_eq!(actual_right.as_slice(), expected_right.as_slice());
    }

    #[test]
    fn tau_g_power_tables_match_left_and_right_exponents() {
        let params = params();
        let poly = raw_from_coeffs(&params, &[2, 7, 1, 8, 2, 8, 1, 8]);
        let input_ntt = to_ntt_alloc(&poly);
        let two_d = 2 * params.d as u64;
        let h_d = h(params.d);
        let (left, right) = tau_g_power_tables(&params, params.d / 2 - 1);

        for i in 0..(params.d / 2 - 1) {
            let left_exp = tau_g_pow(i, params.d);
            let right_exp = (left_exp * h_d) % two_d;
            assert_eq!(left[i].exponent(), left_exp);
            assert_eq!(right[i].exponent(), right_exp);

            let actual_left = apply_tau_ntt_alloc(&input_ntt, &left[i]);
            let actual_right = apply_tau_ntt_alloc(&input_ntt, &right[i]);
            let expected_left = to_ntt_alloc(&tau_raw(&poly, left_exp));
            let expected_right = to_ntt_alloc(&tau_raw(&poly, right_exp));

            assert_eq!(actual_left.as_slice(), expected_left.as_slice());
            assert_eq!(actual_right.as_slice(), expected_right.as_slice());
        }
    }

    #[test]
    fn trace_keeps_only_d_times_constant_coefficient() {
        let params = params();
        let poly = raw_from_coeffs(&params, &[42, 1, 9, 2, 6, 5, 3, 8]);

        assert_eq!(
            coeffs(&trace(&poly)),
            vec![(params.d as u64 * 42) % params.q, 0, 0, 0, 0, 0, 0, 0]
        );
    }
}
