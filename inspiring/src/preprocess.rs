//! `PackPreprocessed`: the CRS-model offline cache.
//!
//! See SPEC.md §8 (offline / online split). Every quantity in Algorithm 1
//! that depends only on `(A, K_g, K_h)` (and not on the LWE `b` scalars)
//! is materialised here, in NTT form, so the online [`crate::pack::pack`]
//! call is a pure function of `(b_0, …, b_{d-1}, &PackPreprocessed)`.
//!
//! The deterministic collapse result is cached here as an affine form:
//! online packing only adds `NTT(b̃)` to the precomputed `b` offset and stacks
//! that with the precomputed final `c1`.

use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rayon::prelude::*;
use spiral_rs::discrete_gaussian::DiscreteGaussian;
use spiral_rs::gadget::build_gadget;
use spiral_rs::poly::{
    add_into, from_ntt_alloc, multiply, stack_ntt, to_ntt_alloc, PolyMatrix, PolyMatrixNTT,
    PolyMatrixRaw,
};

use crate::automorph::{apply_tau_ntt_alloc, h, tau_g_pow, tau_g_power_tables, NttAutomorphTable};
use crate::collapse::{
    collapse_one as collapse_one_materialized, precompute_collapse_affine, CollapseState,
};
use crate::error::InspiringError;
use crate::key_switching::{automorphic_image, ks_digits_ntt_from_c1, KeySwitchingMatrix};
use crate::pack::RlweCiphertext;
use crate::params::RlweParams;

/// Reference InsPIRe seed for the first fixed packing mask.
pub const REFERENCE_W_SEED: [u8; 32] = [7; 32];

/// Reference InsPIRe seed for the second fixed packing mask used by full packing.
pub const REFERENCE_V_SEED: [u8; 32] = [
    8, 8, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
];

/// CRS/public-randomness preprocessing for a single CRS `A`.
///
/// This layer is independent of the client's secret and key-switching matrices.
/// Servers can build it once for a fixed public setup, then bind fresh
/// per-query `(K_g, K_h)` pairs with [`PackPublicPreprocessed::bind_keys`].
pub struct PackPublicPreprocessed<'a> {
    /// Underlying parameter set.
    pub params: &'a RlweParams,
    /// Aggregated deterministic `a` slots before the key-dependent collapse.
    pub a_agg: Vec<PolyMatrixNTT<'a>>,
}

/// Lean online cache for a single CRS `A` and key-switching pair `(K_g, K_h)`.
///
/// **API invariant (SPEC.md §10)**: this struct holds **exactly two**
/// affine collapse outputs. The key-switching matrices and their automorphic
/// images are consumed during [`PackPreprocessed::build`] and are not retained
/// on the online path.
///
pub struct PackPreprocessed<'a> {
    /// Underlying parameter set.
    pub params: &'a RlweParams,

    /// Final RLWE `c1` from collapsing the deterministic `a` trace.
    pub collapse_a_final_ntt: PolyMatrixNTT<'a>,

    /// Deterministic `c2` offset from collapsing with zero online `b`.
    ///
    /// Online packing computes `c2 = NTT(b̃) + collapse_b_offset_ntt`.
    pub collapse_b_offset_ntt: PolyMatrixNTT<'a>,
}

/// Secret-dependent packing-key upload.
///
/// The fixed top rows/masks are derived by both client and server from
/// [`REFERENCE_W_SEED`] and [`REFERENCE_V_SEED`]. The client uploads only these
/// body rows, matching the reference `PackingKeys` split.
pub struct PackingKeys<'a> {
    /// Body row for the `tau_g` switching key.
    pub kg_body: PolyMatrixNTT<'a>,
    /// Body row for the final `tau_h` switching key.
    pub kh_body: PolyMatrixNTT<'a>,
}

/// Public fixed top-row images and NTT automorphism tables for packing-key
/// expansion.
///
/// Reference-compatible requests upload only the secret-dependent `K_g` and
/// `K_h` body rows. The public top rows are derived from fixed seeds on both
/// the client and server. This cache holds the top-row automorphic images and
/// the matching NTT slot tables needed to expand uploaded `K_g` bodies without
/// performing an inverse/forward NTT pair for every image.
pub struct TopKeyImages<'a> {
    /// Fixed top rows for left-half `K_g` images.
    pub kg_top_left: Vec<PolyMatrixNTT<'a>>,
    /// Fixed top rows for right-half `K_g` images.
    pub kg_top_right: Vec<PolyMatrixNTT<'a>>,
    /// Fixed top row for the final `K_h` matrix.
    pub kh_top: PolyMatrixNTT<'a>,
    /// NTT slot tables for uploaded left-half `K_g` body images.
    ///
    /// Entry `i` applies `τ_g^i` to the uploaded `kg_body`.
    pub kg_body_left_tables: Vec<NttAutomorphTable>,
    /// NTT slot tables for uploaded right-half `K_g` body images.
    ///
    /// Entry `i` applies `τ_g^i ∘ τ_h` to the uploaded `kg_body`.
    pub kg_body_right_tables: Vec<NttAutomorphTable>,
}

/// Public/static packing precomputation for one CRS block.
///
/// This records the fixed-mask collapse digit schedule. Per request, the server
/// combines it with uploaded [`PackingKeys`] and online `b` values.
pub struct QueryPackPreprocessed<'a> {
    /// Underlying parameter set.
    pub params: &'a RlweParams,
    /// Aggregated public `a` slots.
    pub a_agg: Vec<PolyMatrixNTT<'a>>,
    /// Precomputed gadget digits in collapse execution order.
    pub digits_ntt: Vec<PolyMatrixNTT<'a>>,
}

impl<'a> PackPreprocessed<'a> {
    /// Build all CRS-side data from `(A, K_g, K_h)`. Online callers then
    /// call [`crate::pack::pack`] with just the `b_k` scalars.
    ///
    /// API invariant: this signature accepts exactly two key-switching
    /// matrices. Adding a third is a breaking change and a CDKS-drift
    /// red flag (SPEC.md §9.h).
    ///
    pub fn build(
        params: &'a RlweParams,
        crs: &PolyMatrixNTT<'a>,
        kg: &KeySwitchingMatrix<'a>,
        kh: &KeySwitchingMatrix<'a>,
    ) -> Result<Self, InspiringError> {
        PackPublicPreprocessed::build(params, crs)?.bind_keys(kg, kh)
    }
}

impl<'a> PackPublicPreprocessed<'a> {
    /// Build the CRS/public-randomness preprocessing for one CRS block.
    pub fn build(params: &'a RlweParams, crs: &PolyMatrixNTT<'a>) -> Result<Self, InspiringError> {
        if crs.rows != params.d || crs.cols != 1 {
            return Err(InspiringError::PreprocessMismatch(format!(
                "expected CRS shape {}x1, got {}x{}",
                params.d, crs.rows, crs.cols
            )));
        }

        let crs_raw = from_ntt_alloc(crs);
        let a_tildes: Vec<_> = (0..params.d)
            .map(|row| a_tilde_coeffs(params, crs_raw.get_poly(row, 0)))
            .collect();
        let a_agg = build_a_agg(params, &a_tildes);

        Ok(Self { params, a_agg })
    }

    /// Bind a fresh per-query `(K_g, K_h)` pair to this public cache.
    pub fn bind_keys(
        &self,
        kg: &KeySwitchingMatrix<'a>,
        kh: &KeySwitchingMatrix<'a>,
    ) -> Result<PackPreprocessed<'a>, InspiringError> {
        let params = self.params;
        if kg.mat.rows != 2 || kg.mat.cols != params.gadget.ell {
            return Err(InspiringError::PreprocessMismatch(format!(
                "K_g must have shape 2x{}, got {}x{}",
                params.gadget.ell, kg.mat.rows, kg.mat.cols
            )));
        }
        if kh.mat.rows != 2 || kh.mat.cols != params.gadget.ell {
            return Err(InspiringError::PreprocessMismatch(format!(
                "K_h must have shape 2x{}, got {}x{}",
                params.gadget.ell, kh.mat.rows, kh.mat.cols
            )));
        }

        let two_d = 2 * params.d as u64;
        let h_d = h(params.d);
        let kg_images_left: Vec<_> = (0..(params.d / 2 - 1))
            .map(|i| automorphic_image(kg, tau_g_pow(i, params.d)))
            .collect();
        let kg_images_right: Vec<_> = (0..(params.d / 2 - 1))
            .map(|i| automorphic_image(kg, (tau_g_pow(i, params.d) * h_d) % two_d))
            .collect();
        let collapse_affine = precompute_collapse_affine(
            params,
            self.a_agg.clone(),
            &kg_images_left,
            &kg_images_right,
            kh,
        );

        Ok(PackPreprocessed {
            params,
            collapse_a_final_ntt: collapse_affine.a_final_ntt,
            collapse_b_offset_ntt: collapse_affine.b_offset_ntt,
        })
    }
}

impl<'a> PackingKeys<'a> {
    /// Generate full packing keys from a fresh secret.
    pub fn generate_full(
        params: &'a RlweParams,
        secret_ntt: &PolyMatrixNTT<'a>,
        rng: &mut ChaCha20Rng,
    ) -> Self {
        let kg_body = generate_reference_body(
            params,
            secret_ntt,
            tau_g_pow(1, params.d),
            REFERENCE_W_SEED,
            rng,
        );
        let kh_body =
            generate_reference_body(params, secret_ntt, h(params.d), REFERENCE_V_SEED, rng);

        Self { kg_body, kh_body }
    }

    /// Convert uploaded bodies into full key-switching matrices by restoring
    /// the fixed public mask rows.
    pub fn to_key_pair(
        &self,
        params: &'a RlweParams,
    ) -> Result<(KeySwitchingMatrix<'a>, KeySwitchingMatrix<'a>), InspiringError> {
        self.validate(params)?;

        let y_top = reference_mask_top(params, REFERENCE_W_SEED);
        let z_top = reference_mask_top(params, REFERENCE_V_SEED);
        Ok((
            KeySwitchingMatrix {
                mat: stack_ntt(&y_top, &self.kg_body),
                params,
            },
            KeySwitchingMatrix {
                mat: stack_ntt(&z_top, &self.kh_body),
                params,
            },
        ))
    }

    /// Validate that uploaded packing-key bodies match the reference wire shape.
    pub fn validate(&self, params: &RlweParams) -> Result<(), InspiringError> {
        validate_reference_body(params, &self.kg_body, "reference K_g body")?;
        validate_reference_body(params, &self.kh_body, "reference K_h body")?;
        Ok(())
    }
}

impl<'a> QueryPackPreprocessed<'a> {
    /// Build public/static packing preprocessing for one CRS block.
    pub fn build(params: &'a RlweParams, crs: &PolyMatrixNTT<'a>) -> Result<Self, InspiringError> {
        let public = PackPublicPreprocessed::build(params, crs)?;
        let digits_ntt = precompute_reference_digits(params, public.a_agg.clone());

        Ok(Self {
            params,
            a_agg: public.a_agg,
            digits_ntt,
        })
    }

    /// Pack one block of online `b` scalars using uploaded reference key bodies.
    ///
    /// This is the hot-path variant for callers whose LWE `a` rows were already
    /// consumed during preprocessing. It keeps the reference-compatible upload
    /// shape while fusing key-body automorphisms into the collapse products.
    pub fn pack_b(
        &self,
        b_scalars: &[u64],
        keys: &PackingKeys<'a>,
        top_images: &TopKeyImages<'a>,
    ) -> Result<RlweCiphertext<'a>, InspiringError> {
        keys.validate(self.params)?;
        top_images.validate(self.params)?;
        self.pack_b_prevalidated(b_scalars, keys, top_images)
    }

    /// Pack `b` scalars after the caller has validated `keys` and `top_images`.
    ///
    /// This keeps multi-block server callers from repeating key-shape and
    /// top-image checks for every independent output block.
    pub fn pack_b_prevalidated(
        &self,
        b_scalars: &[u64],
        keys: &PackingKeys<'a>,
        top_images: &TopKeyImages<'a>,
    ) -> Result<RlweCiphertext<'a>, InspiringError> {
        if b_scalars.len() != self.params.d {
            return Err(InspiringError::LweShape(format!(
                "expected {} LWE b scalars, got {}",
                self.params.d,
                b_scalars.len()
            )));
        }
        let mut b_tilde = PolyMatrixRaw::zero(&self.params.spiral, 1, 1);
        for (idx, b) in b_scalars.iter().copied().enumerate() {
            b_tilde.get_poly_mut(0, 0)[idx] = b % self.params.q;
        }

        Ok(collapse(
            self.params,
            crate::intermediate::IRCtx {
                a_hat: self.a_agg.clone(),
                b_tilde,
            },
            &keys.kg_body,
            &keys.kh_body,
            top_images,
            &self.digits_ntt,
        ))
    }
}

impl<'a> TopKeyImages<'a> {
    /// Build fixed public top-row key images and body automorphism tables from
    /// reference seeds.
    ///
    /// Servers should construct this once for an [`RlweParams`] instance and
    /// reuse it for every reference-compatible request. At `d = 2048`, this
    /// moves the NTT slot-table discovery and top-row image generation out of
    /// the online query path; request-time expansion only copies NTT slots for
    /// the uploaded body rows and stacks them with these cached top rows.
    pub fn build(params: &'a RlweParams) -> Self {
        let kg_top = reference_mask_top(params, REFERENCE_W_SEED);
        let kh_top = reference_mask_top(params, REFERENCE_V_SEED);
        let (kg_body_left_tables, kg_body_right_tables) =
            tau_g_power_tables(params, params.d / 2 - 1);
        let kg_top_left = kg_body_left_tables
            .iter()
            .map(|table| apply_tau_ntt_alloc(&kg_top, table))
            .collect();
        let kg_top_right = kg_body_right_tables
            .iter()
            .map(|table| apply_tau_ntt_alloc(&kg_top, table))
            .collect();

        Self {
            kg_top_left,
            kg_top_right,
            kh_top,
            kg_body_left_tables,
            kg_body_right_tables,
        }
    }

    /// Validate that cached fixed key images and automorphism tables match `params`.
    pub fn validate(&self, params: &RlweParams) -> Result<(), InspiringError> {
        let expected = params.d / 2 - 1;
        if self.kg_top_left.len() != expected {
            return Err(InspiringError::PreprocessMismatch(format!(
                "expected {expected} left fixed K_g top images, got {}",
                self.kg_top_left.len()
            )));
        }
        if self.kg_top_right.len() != expected {
            return Err(InspiringError::PreprocessMismatch(format!(
                "expected {expected} right fixed K_g top images, got {}",
                self.kg_top_right.len()
            )));
        }
        if self.kg_body_left_tables.len() != expected {
            return Err(InspiringError::PreprocessMismatch(format!(
                "expected {expected} left K_g body tables, got {}",
                self.kg_body_left_tables.len()
            )));
        }
        if self.kg_body_right_tables.len() != expected {
            return Err(InspiringError::PreprocessMismatch(format!(
                "expected {expected} right K_g body tables, got {}",
                self.kg_body_right_tables.len()
            )));
        }
        validate_reference_body(params, &self.kh_top, "reference kh top")?;
        for (idx, top) in self.kg_top_left.iter().enumerate() {
            validate_reference_body(params, top, "reference left kg top").map_err(|err| {
                InspiringError::PreprocessMismatch(format!("left K_g top image {idx}: {err}"))
            })?;
            if self.kg_body_left_tables[idx].indices().len() != params.d {
                return Err(InspiringError::PreprocessMismatch(format!(
                    "left K_g body table {idx} has length {}, expected {}",
                    self.kg_body_left_tables[idx].indices().len(),
                    params.d
                )));
            }
        }
        for (idx, top) in self.kg_top_right.iter().enumerate() {
            validate_reference_body(params, top, "reference right kg top").map_err(|err| {
                InspiringError::PreprocessMismatch(format!("right K_g top image {idx}: {err}"))
            })?;
            if self.kg_body_right_tables[idx].indices().len() != params.d {
                return Err(InspiringError::PreprocessMismatch(format!(
                    "right K_g body table {idx} has length {}, expected {}",
                    self.kg_body_right_tables[idx].indices().len(),
                    params.d
                )));
            }
        }
        Ok(())
    }
}

fn precompute_reference_digits<'a>(
    params: &'a RlweParams,
    a_agg: Vec<PolyMatrixNTT<'a>>,
) -> Vec<PolyMatrixNTT<'a>> {
    let kg = fixed_reference_key(params, REFERENCE_W_SEED);
    let kh = fixed_reference_key(params, REFERENCE_V_SEED);
    let two_d = 2 * params.d as u64;
    let h_d = h(params.d);
    let kg_images_left: Vec<_> = (0..(params.d / 2 - 1))
        .map(|i| automorphic_image(&kg, tau_g_pow(i, params.d)))
        .collect();
    let kg_images_right: Vec<_> = (0..(params.d / 2 - 1))
        .map(|i| automorphic_image(&kg, (tau_g_pow(i, params.d) * h_d) % two_d))
        .collect();

    let mut digits_ntt = Vec::with_capacity(params.d - 1);
    let mut slots = a_agg;
    let right = slots.split_off(params.d / 2);
    let left = slots;
    let b = PolyMatrixNTT::zero(&params.spiral, 1, 1);

    let mut left_state = CollapseState { a: left, b };
    collect_half_digits(&mut left_state, &kg_images_left, &mut digits_ntt);
    let left_a = left_state
        .a
        .pop()
        .expect("collapse_half leaves one left component");

    let mut right_state = CollapseState {
        a: right,
        b: left_state.b,
    };
    collect_half_digits(&mut right_state, &kg_images_right, &mut digits_ntt);
    let right_a = right_state
        .a
        .pop()
        .expect("collapse_half leaves one right component");

    let mut final_state = CollapseState {
        a: vec![left_a, right_a],
        b: right_state.b,
    };
    digits_ntt.push(ks_digits_ntt_from_c1(params, &final_state.a[1]));
    collapse_one_materialized(&mut final_state, &kh);
    debug_assert_eq!(digits_ntt.len(), params.d - 1);
    digits_ntt
}

fn collect_half_digits<'a>(
    state: &mut CollapseState<'a>,
    kg_images: &[KeySwitchingMatrix<'a>],
    digits_ntt: &mut Vec<PolyMatrixNTT<'a>>,
) {
    while state.a.len() > 1 {
        let image_idx = state.a.len() - 2;
        digits_ntt.push(ks_digits_ntt_from_c1(
            kg_images[image_idx].params,
            &state.a[image_idx + 1],
        ));
        collapse_one_materialized(state, &kg_images[image_idx]);
    }
}

fn generate_reference_body<'a>(
    params: &'a RlweParams,
    secret_ntt: &PolyMatrixNTT<'a>,
    secret_from_exponent: u64,
    mask_seed: [u8; 32],
    rng: &mut ChaCha20Rng,
) -> PolyMatrixNTT<'a> {
    let spiral = &params.spiral;
    let ell = params.gadget.ell;
    let mask_raw = reference_mask_raw(params, mask_seed);
    let mask_ntt = to_ntt_alloc(&mask_raw);
    let secret_from = crate::automorph::tau_ntt(secret_ntt, secret_from_exponent);
    let gadget = build_gadget(spiral, 1, ell);
    let scaled = spiral_rs::poly::scalar_multiply_alloc(&secret_from, &to_ntt_alloc(&gadget));
    let dg = DiscreteGaussian::init(params.sigma_chi * std::f64::consts::TAU.sqrt());
    let error = PolyMatrixRaw::noise(spiral, 1, ell, &dg, rng);

    let mut body = PolyMatrixNTT::zero(spiral, 1, ell);
    multiply(&mut body, secret_ntt, &mask_ntt);
    add_into(&mut body, &to_ntt_alloc(&error));
    add_into(&mut body, &scaled);
    body
}

fn fixed_reference_key<'a>(params: &'a RlweParams, mask_seed: [u8; 32]) -> KeySwitchingMatrix<'a> {
    let top = reference_mask_top(params, mask_seed);
    let body = PolyMatrixNTT::zero(&params.spiral, 1, params.gadget.ell);
    KeySwitchingMatrix {
        mat: stack_ntt(&top, &body),
        params,
    }
}

/// Collapse the wide intermediate ciphertext using uploaded key bodies.
///
/// The reference wire format gives us only the secret-dependent `K_g` and `K_h`
/// body rows. Public top rows and NTT automorphism tables are cached in
/// [`TopKeyImages`]. This function performs the same `d - 1` logical
/// key-switches as the materialized-key collapse, but applies each `K_g` body
/// automorphism inside the product that consumes it.
fn collapse<'a>(
    params: &'a RlweParams,
    agg: crate::intermediate::IRCtx<'a>,
    kg_body: &PolyMatrixNTT<'a>,
    kh_body: &PolyMatrixNTT<'a>,
    top_images: &TopKeyImages<'a>,
    digits_ntt: &[PolyMatrixNTT<'a>],
) -> RlweCiphertext<'a> {
    assert_eq!(
        digits_ntt.len(),
        params.d - 1,
        "preprocess::collapse expects d - 1 digit blocks"
    );
    assert_eq!(
        agg.a_hat.len(),
        params.d,
        "preprocess::collapse expects d a_hat slots"
    );

    let mut slots = agg.a_hat;
    let right = slots.split_off(params.d / 2);
    let left = slots;
    let b = to_ntt_alloc(&agg.b_tilde);
    let mut digit_idx = 0;

    let mut left_state = CollapseState { a: left, b };
    collapse_half(
        &mut left_state,
        kg_body,
        &top_images.kg_top_left,
        &top_images.kg_body_left_tables,
        digits_ntt,
        &mut digit_idx,
    );
    let left_a = left_state
        .a
        .pop()
        .expect("left collapse leaves one component");

    let mut right_state = CollapseState {
        a: right,
        b: left_state.b,
    };
    collapse_half(
        &mut right_state,
        kg_body,
        &top_images.kg_top_right,
        &top_images.kg_body_right_tables,
        digits_ntt,
        &mut digit_idx,
    );
    let right_a = right_state
        .a
        .pop()
        .expect("right collapse leaves one component");

    let mut final_state = CollapseState {
        a: vec![left_a, right_a],
        b: right_state.b,
    };
    collapse_final(
        &mut final_state,
        &top_images.kh_top,
        kh_body,
        &digits_ntt[digit_idx],
    );
    digit_idx += 1;
    assert_eq!(digit_idx, digits_ntt.len());

    RlweCiphertext {
        inner: stack_ntt(&final_state.a[0], &final_state.b),
    }
}

/// Collapse one `d/2` side of the aggregate by consuming its `K_g` image table.
///
/// `top_images` is already expanded for the side being collapsed. `kg_body`
/// remains the single uploaded body row; each `body_tables` entry describes the
/// automorphism that would have been applied to materialize the matching body.
fn collapse_half<'a>(
    state: &mut CollapseState<'a>,
    kg_body: &PolyMatrixNTT<'a>,
    top_images: &[PolyMatrixNTT<'a>],
    body_tables: &[NttAutomorphTable],
    digits_ntt: &[PolyMatrixNTT<'a>],
    digit_idx: &mut usize,
) {
    assert_eq!(
        top_images.len(),
        state.a.len().saturating_sub(1),
        "preprocess::collapse_half expects one top image per collapse step"
    );
    assert_eq!(
        body_tables.len(),
        state.a.len().saturating_sub(1),
        "preprocess::collapse_half expects one body table per collapse step"
    );

    while state.a.len() > 1 {
        let image_idx = state.a.len() - 2;
        // The top row is already stored as this automorphic image. The body row
        // stays in uploaded form; `body_tables[image_idx]` supplies the slot
        // permutation needed for this logical `K_g` image.
        collapse_one(
            state,
            &top_images[image_idx],
            kg_body,
            &body_tables[image_idx],
            &digits_ntt[*digit_idx],
        );
        *digit_idx += 1;
    }
}

/// Apply one logical `K_g` switch and remove the consumed aggregate component.
///
/// This mirrors [`crate::collapse::collapse_one`] but accepts split key parts:
/// an already-expanded public top row plus the base uploaded body row and the
/// table needed to read that body as the current automorphic image.
fn collapse_one<'a>(
    state: &mut CollapseState<'a>,
    top_row: &PolyMatrixNTT<'a>,
    body_row: &PolyMatrixNTT<'a>,
    body_table: &NttAutomorphTable,
    digits_ntt: &PolyMatrixNTT<'a>,
) {
    let k = state.a.len();
    assert!(
        k >= 2,
        "preprocess::collapse_one requires at least two a components"
    );

    let (delta_a, delta_b) =
        switch_with_permuted_body(top_row, body_row, body_table, digits_ntt, &state.b);
    add_into(&mut state.a[k - 2], &delta_a);
    state.a.pop();
    state.b = delta_b;
}

/// Apply the final `K_h` switch after left and right halves have collapsed.
///
/// `K_h` is not rotated across a family of images, so its uploaded body row can
/// be multiplied directly rather than through a permutation table.
fn collapse_final<'a>(
    state: &mut CollapseState<'a>,
    top_row: &PolyMatrixNTT<'a>,
    body_row: &PolyMatrixNTT<'a>,
    digits_ntt: &PolyMatrixNTT<'a>,
) {
    let k = state.a.len();
    assert!(
        k >= 2,
        "preprocess::collapse_final requires at least two a components"
    );

    let (delta_a, delta_b) = switch_with_body(top_row, body_row, digits_ntt, &state.b);
    add_into(&mut state.a[k - 2], &delta_a);
    state.a.pop();
    state.b = delta_b;
}

/// Switch using a key whose body row is represented by an NTT slot permutation.
///
/// The result is identical to multiplying `[top_row; tau(body_row)]` by
/// `digits_ntt`, but the `tau(body_row)` matrix is never allocated.
fn switch_with_permuted_body<'a>(
    top_row: &PolyMatrixNTT<'a>,
    body_row: &PolyMatrixNTT<'a>,
    body_table: &NttAutomorphTable,
    digits_ntt: &PolyMatrixNTT<'a>,
    c2: &PolyMatrixNTT<'a>,
) -> (PolyMatrixNTT<'a>, PolyMatrixNTT<'a>) {
    validate_key_parts(top_row, body_row, digits_ntt, c2);
    assert_eq!(body_table.indices().len(), top_row.params.poly_len);

    // `top_row * digits` is ordinary matrix multiplication because the public
    // top row was pre-expanded at server setup.
    let mut delta_a = PolyMatrixNTT::zero(top_row.params, 1, 1);
    multiply(&mut delta_a, top_row, digits_ntt);

    // `body_row * digits` is evaluated as if `body_row` had first been
    // automorphed by `body_table`, but without allocating that image.
    let mut delta_b = multiply_permuted_body_by_digits(body_row, body_table, digits_ntt);
    add_into(&mut delta_b, c2);
    (delta_a, delta_b)
}

/// Switch using explicit top and body rows with no body automorphism.
///
/// This is used for the final `K_h` switch, where there is only one key image.
fn switch_with_body<'a>(
    top_row: &PolyMatrixNTT<'a>,
    body_row: &PolyMatrixNTT<'a>,
    digits_ntt: &PolyMatrixNTT<'a>,
    c2: &PolyMatrixNTT<'a>,
) -> (PolyMatrixNTT<'a>, PolyMatrixNTT<'a>) {
    validate_key_parts(top_row, body_row, digits_ntt, c2);

    let mut delta_a = PolyMatrixNTT::zero(top_row.params, 1, 1);
    multiply(&mut delta_a, top_row, digits_ntt);
    let mut delta_b = PolyMatrixNTT::zero(top_row.params, 1, 1);
    multiply(&mut delta_b, body_row, digits_ntt);
    add_into(&mut delta_b, c2);
    (delta_a, delta_b)
}

/// Validate split key-switch operands before evaluating a switch product.
fn validate_key_parts(
    top_row: &PolyMatrixNTT<'_>,
    body_row: &PolyMatrixNTT<'_>,
    digits_ntt: &PolyMatrixNTT<'_>,
    c2: &PolyMatrixNTT<'_>,
) {
    assert_eq!(top_row.rows, 1);
    assert_eq!(top_row.cols, body_row.cols);
    assert_eq!(body_row.rows, 1);
    assert_eq!(digits_ntt.rows, top_row.cols);
    assert_eq!(digits_ntt.cols, 1);
    assert_eq!(c2.rows, 1);
    assert_eq!(c2.cols, 1);
}

/// Multiply an implicit automorphic body image by precomputed gadget digits.
///
/// In NTT form the automorphism is a slot permutation, so the multiply reads
/// `body_row` through `body_table.indices()` and accumulates directly into the
/// output polynomial.
fn multiply_permuted_body_by_digits<'a>(
    body_row: &PolyMatrixNTT<'a>,
    body_table: &NttAutomorphTable,
    digits_ntt: &PolyMatrixNTT<'a>,
) -> PolyMatrixNTT<'a> {
    assert_eq!(body_row.rows, 1);
    assert_eq!(digits_ntt.cols, 1);
    assert_eq!(body_row.cols, digits_ntt.rows);

    let spiral = body_row.params;
    let d = spiral.poly_len;
    let mut out = PolyMatrixNTT::zero(spiral, 1, 1);
    let out_poly = out.get_poly_mut(0, 0);

    for digit_idx in 0..body_row.cols {
        let body_poly = body_row.get_poly(0, digit_idx);
        let digit_poly = digits_ntt.get_poly(digit_idx, 0);
        for crt_idx in 0..spiral.crt_count {
            let modulus = u128::from(spiral.moduli[crt_idx]);
            let offset = crt_idx * d;
            let body_chunk = &body_poly[offset..offset + d];
            let digit_chunk = &digit_poly[offset..offset + d];
            let out_chunk = &mut out_poly[offset..offset + d];
            for dst_idx in 0..d {
                // NTT-domain automorphisms are slot permutations. Reading the
                // source slot here is equivalent to multiplying by the
                // materialized automorphic body image at `dst_idx`.
                let src_idx = body_table.indices()[dst_idx] as usize;
                let product = u128::from(body_chunk[src_idx]) * u128::from(digit_chunk[dst_idx]);
                out_chunk[dst_idx] = ((u128::from(out_chunk[dst_idx]) + product) % modulus) as u64;
            }
        }
    }

    out
}

fn reference_mask_top<'a>(params: &'a RlweParams, mask_seed: [u8; 32]) -> PolyMatrixNTT<'a> {
    (-&reference_mask_raw(params, mask_seed)).ntt()
}

fn reference_mask_raw<'a>(params: &'a RlweParams, mask_seed: [u8; 32]) -> PolyMatrixRaw<'a> {
    PolyMatrixRaw::random_rng(
        &params.spiral,
        1,
        params.gadget.ell,
        &mut ChaCha20Rng::from_seed(mask_seed),
    )
}

fn validate_reference_body(
    params: &RlweParams,
    body: &PolyMatrixNTT<'_>,
    label: &'static str,
) -> Result<(), InspiringError> {
    if body.rows != 1 || body.cols != params.gadget.ell {
        return Err(InspiringError::PreprocessMismatch(format!(
            "{label} must have shape 1x{}, got {}x{}",
            params.gadget.ell, body.rows, body.cols
        )));
    }
    Ok(())
}

fn build_a_agg<'a>(params: &'a RlweParams, a_tildes: &[Vec<u64>]) -> Vec<PolyMatrixNTT<'a>> {
    (0..params.d)
        .into_par_iter()
        .map(|slot| aggregate_slot(params, a_tildes, slot))
        .collect()
}

fn aggregate_slot<'a>(
    params: &'a RlweParams,
    a_tildes: &[Vec<u64>],
    slot: usize,
) -> PolyMatrixNTT<'a> {
    let mut out = vec![0_u64; params.d];
    let exponent = if slot < params.d / 2 {
        tau_g_pow(slot, params.d)
    } else {
        let two_d = 2 * params.d as u64;
        (tau_g_pow(slot - params.d / 2, params.d) * h(params.d)) % two_d
    };

    for (shift, a_tilde) in a_tildes.iter().enumerate() {
        add_shifted_tau(&mut out, a_tilde, exponent, shift, params.q);
    }

    for coeff in &mut out {
        *coeff = (u128::from(*coeff) * u128::from(params.d_inv) % u128::from(params.q)) as u64;
    }

    let mut raw = PolyMatrixRaw::zero(&params.spiral, 1, 1);
    raw.get_poly_mut(0, 0).copy_from_slice(&out);
    to_ntt_alloc(&raw)
}

fn a_tilde_coeffs(params: &RlweParams, a: &[u64]) -> Vec<u64> {
    assert_eq!(
        a.len(),
        params.d,
        "preprocess::a_tilde_coeffs expects an LWE vector of length d"
    );

    let mut out = vec![0_u64; params.d];
    out[0] = a[0] % params.q;
    for (i, coeff) in a.iter().enumerate().skip(1) {
        let reduced = coeff % params.q;
        out[params.d - i] = if reduced == 0 { 0 } else { params.q - reduced };
    }
    out
}

fn add_shifted_tau(out: &mut [u64], poly: &[u64], exponent: u64, shift: usize, q: u64) {
    let d = out.len();
    let two_d = 2 * d as u64;

    for (source_idx, coeff) in poly.iter().enumerate() {
        let reduced = *coeff % q;
        if reduced == 0 {
            continue;
        }

        let exp = (source_idx as u64 * exponent) % two_d;
        let mut idx = if exp < d as u64 {
            exp as usize
        } else {
            (exp - d as u64) as usize
        };
        let mut negate = exp >= d as u64;

        idx += shift;
        if idx >= d {
            idx -= d;
            negate = !negate;
        }

        let term = if negate { q - reduced } else { reduced };
        out[idx] = ((u128::from(out[idx]) + u128::from(term)) % u128::from(q)) as u64;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::GadgetParams;
    use spiral_rs::poly::{to_ntt_alloc, PolyMatrixRaw};

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

    fn zero_ks<'a>(params: &'a RlweParams) -> KeySwitchingMatrix<'a> {
        KeySwitchingMatrix {
            mat: PolyMatrixNTT::zero(&params.spiral, 2, params.gadget.ell),
            params,
        }
    }

    fn crs<'a>(params: &'a RlweParams) -> PolyMatrixNTT<'a> {
        let mut raw = PolyMatrixRaw::zero(&params.spiral, params.d, 1);
        for row in 0..params.d {
            for col in 0..params.d {
                raw.get_poly_mut(row, 0)[col] = (row * params.d + col + 1) as u64;
            }
        }
        to_ntt_alloc(&raw)
    }

    fn b_scalars(params: &RlweParams) -> Vec<u64> {
        (0..params.d)
            .map(|idx| (idx as u64 * 17 + 3) % params.q)
            .collect()
    }

    fn ntt_matrix<'a>(
        params: &'a RlweParams,
        rows: usize,
        cols: usize,
        seed: u64,
    ) -> PolyMatrixNTT<'a> {
        let mut matrix = PolyMatrixNTT::zero(&params.spiral, rows, cols);
        for (idx, coeff) in matrix.as_mut_slice().iter_mut().enumerate() {
            *coeff = (seed + idx as u64 * 19 + (idx / params.d) as u64 * 7) % params.q;
        }
        matrix
    }

    #[test]
    fn build_precomputes_affine_collapse_cache() {
        let params = params();
        let crs = crs(&params);

        let kg = zero_ks(&params);
        let kh = zero_ks(&params);
        let pre = PackPreprocessed::build(&params, &crs, &kg, &kh).expect("valid preprocessing");

        assert_eq!(pre.collapse_a_final_ntt.rows, 1);
        assert_eq!(pre.collapse_a_final_ntt.cols, 1);
        assert_eq!(pre.collapse_b_offset_ntt.rows, 1);
        assert_eq!(pre.collapse_b_offset_ntt.cols, 1);
    }

    #[test]
    fn build_rejects_wrong_crs_shape() {
        let params = params();
        let wrong = PolyMatrixNTT::zero(&params.spiral, 1, 1);

        let kg = zero_ks(&params);
        let kh = zero_ks(&params);
        assert!(matches!(
            PackPreprocessed::build(&params, &wrong, &kg, &kh),
            Err(InspiringError::PreprocessMismatch(_))
        ));
    }

    #[test]
    fn top_key_images_cache_matching_body_automorphism_tables() {
        let params = params();
        let kg_top = reference_mask_top(&params, REFERENCE_W_SEED);
        let images = TopKeyImages::build(&params);
        let two_d = 2 * params.d as u64;
        let h_d = h(params.d);

        for i in 0..(params.d / 2 - 1) {
            let left_exp = tau_g_pow(i, params.d);
            let right_exp = (left_exp * h_d) % two_d;
            let expected_left = crate::automorph::tau_ntt(&kg_top, left_exp);
            let expected_right = crate::automorph::tau_ntt(&kg_top, right_exp);

            assert_eq!(images.kg_body_left_tables[i].exponent(), left_exp);
            assert_eq!(images.kg_body_right_tables[i].exponent(), right_exp);
            assert_eq!(images.kg_top_left[i].as_slice(), expected_left.as_slice());
            assert_eq!(images.kg_top_right[i].as_slice(), expected_right.as_slice());
        }
    }

    #[test]
    fn permuted_body_multiply_matches_materialized_body_image() {
        let params = params();
        let images = TopKeyImages::build(&params);
        let body = ntt_matrix(&params, 1, params.gadget.ell, 11);
        let digits = ntt_matrix(&params, params.gadget.ell, 1, 29);
        let table = &images.kg_body_right_tables[1];

        let materialized_body = apply_tau_ntt_alloc(&body, table);
        let mut expected = PolyMatrixNTT::zero(&params.spiral, 1, 1);
        multiply(&mut expected, &materialized_body, &digits);

        let actual = multiply_permuted_body_by_digits(&body, table, &digits);

        assert_eq!(actual.as_slice(), expected.as_slice());
    }

    #[test]
    fn switch_with_permuted_body_matches_materialized_key_product() {
        let params = params();
        let images = TopKeyImages::build(&params);
        let top = ntt_matrix(&params, 1, params.gadget.ell, 5);
        let body = ntt_matrix(&params, 1, params.gadget.ell, 13);
        let digits = ntt_matrix(&params, params.gadget.ell, 1, 31);
        let c2 = ntt_matrix(&params, 1, 1, 43);
        let table = &images.kg_body_left_tables[2];

        let (actual_a, actual_b) = switch_with_permuted_body(&top, &body, table, &digits, &c2);

        let materialized_body = apply_tau_ntt_alloc(&body, table);
        let mut expected_a = PolyMatrixNTT::zero(&params.spiral, 1, 1);
        multiply(&mut expected_a, &top, &digits);
        let mut expected_b = PolyMatrixNTT::zero(&params.spiral, 1, 1);
        multiply(&mut expected_b, &materialized_body, &digits);
        add_into(&mut expected_b, &c2);

        assert_eq!(actual_a.as_slice(), expected_a.as_slice());
        assert_eq!(actual_b.as_slice(), expected_b.as_slice());
    }

    #[test]
    fn pack_with_uploaded_key_bodies_returns_rlwe_ciphertext() {
        let params = params();
        let crs = crs(&params);
        let pre = QueryPackPreprocessed::build(&params, &crs).expect("preprocess");
        let secret_raw = {
            let mut raw = PolyMatrixRaw::zero(&params.spiral, 1, 1);
            raw.get_poly_mut(0, 0)[0] = 1;
            raw.get_poly_mut(0, 0)[2] = params.q - 1;
            raw
        };
        let secret_ntt = to_ntt_alloc(&secret_raw);
        let mut rng = ChaCha20Rng::from_seed([42; 32]);
        let keys = PackingKeys::generate_full(&params, &secret_ntt, &mut rng);
        let top_images = TopKeyImages::build(&params);
        let b_scalars = b_scalars(&params);
        let ct = pre.pack_b(&b_scalars, &keys, &top_images).expect("pack b");

        assert_eq!(ct.inner.rows, 2);
        assert_eq!(ct.inner.cols, 1);
    }
}
