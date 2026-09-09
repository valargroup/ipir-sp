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
use spiral_rs::arith::barrett_reduction_u128;
use spiral_rs::discrete_gaussian::DiscreteGaussian;
use spiral_rs::gadget::build_gadget;
use spiral_rs::ntt::ntt_forward;
use spiral_rs::params::Params as SpiralParams;
use spiral_rs::poly::{
    add_into, from_ntt_alloc, multiply, stack_ntt, to_ntt_alloc, PolyMatrix, PolyMatrixNTT,
    PolyMatrixRaw,
};

use crate::automorph::{apply_tau_ntt_alloc, h, tau_g_pow, tau_g_power_tables, NttAutomorphTable};
use crate::collapse::{collapse_one_with_digits, precompute_collapse_affine, CollapseState};
use crate::error::InspiringError;
use crate::key_switching::{
    automorphic_image_with_table, ks_digits_ntt_from_c1, KeySwitchingMatrix,
};
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
    /// Final RLWE `c1` from collapsing the fixed public top-row trace.
    pub collapse_a_final_ntt: PolyMatrixNTT<'a>,
    /// Precomputed gadget digits in collapse execution order.
    pub digits_ntt: Vec<PolyMatrixNTT<'a>>,
}

struct QueryReferencePrecomputed<'a> {
    collapse_a_final_ntt: PolyMatrixNTT<'a>,
    digits_ntt: Vec<PolyMatrixNTT<'a>>,
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

        // `τ_g^i(K_g)` and `τ_g^i ∘ τ_h(K_g)` for every collapse step. Both
        // families are slot permutations of the same matrix, so they are built
        // from composed tables rather than `d - 2` NTT round trips.
        let (left_tables, right_tables) = tau_g_power_tables(params, params.d / 2 - 1);
        let kg_images_left: Vec<_> = left_tables
            .iter()
            .map(|table| automorphic_image_with_table(kg, table))
            .collect();
        let kg_images_right: Vec<_> = right_tables
            .iter()
            .map(|table| automorphic_image_with_table(kg, table))
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
    /// Build the same public preprocessing as `build`, reusing fixed public
    /// mask images already held for online packing. `top` must come from
    /// `TopKeyImages::build(params)` and remain unmodified. No database-dependent
    /// values or client key bodies are reused.
    pub fn build_with_top(
        params: &'a RlweParams,
        crs: &PolyMatrixNTT<'a>,
        top: &TopKeyImages<'a>,
    ) -> Result<Self, InspiringError> {
        crate::preprocess_reuse::build(params, crs, top)
    }

    /// Build public/static packing preprocessing for one CRS block.
    pub fn build(params: &'a RlweParams, crs: &PolyMatrixNTT<'a>) -> Result<Self, InspiringError> {
        let public = PackPublicPreprocessed::build(params, crs)?;
        let reference = precompute_reference_trace(params, public.a_agg);

        Ok(Self {
            params,
            collapse_a_final_ntt: reference.collapse_a_final_ntt,
            digits_ntt: reference.digits_ntt,
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

        let b_final = collapse_uploaded_body_b(
            self.params,
            to_ntt_alloc(&b_tilde),
            &keys.kg_body,
            &keys.kh_body,
            top_images,
            &self.digits_ntt,
        );

        Ok(RlweCiphertext {
            inner: stack_ntt(&self.collapse_a_final_ntt, &b_final),
        })
    }

    /// Pack `k` independent queries against this block in one pass.
    ///
    /// Equivalent to calling [`Self::pack_b_prevalidated`] once per query, and
    /// pinned to that by `batched_pack_matches_sequential`. The difference is
    /// only in memory traffic: the shared `digits_ntt` stream is read once for
    /// the whole batch instead of once per query.
    ///
    /// The queries are independent — different secrets, different key bodies,
    /// possibly different clients. Batching them shares no secret state and
    /// changes no ciphertext, so it carries no cryptographic assumption; it is
    /// server-side request coalescing, not batch PIR.
    ///
    /// Callers must validate `keys` and `top_images` beforehand, exactly as for
    /// [`Self::pack_b_prevalidated`].
    pub fn pack_b_batched_prevalidated(
        &self,
        b_scalars: &[&[u64]],
        keys: &[&PackingKeys<'a>],
        top_images: &TopKeyImages<'a>,
    ) -> Result<Vec<RlweCiphertext<'a>>, InspiringError> {
        if b_scalars.len() != keys.len() {
            return Err(InspiringError::LweShape(format!(
                "expected one key set per query, got {} b blocks and {} key sets",
                b_scalars.len(),
                keys.len()
            )));
        }
        if b_scalars.is_empty() {
            return Ok(Vec::new());
        }

        let mut b_tildes = Vec::with_capacity(b_scalars.len());
        for block in b_scalars {
            if block.len() != self.params.d {
                return Err(InspiringError::LweShape(format!(
                    "expected {} LWE b scalars, got {}",
                    self.params.d,
                    block.len()
                )));
            }
            let mut b_tilde = PolyMatrixRaw::zero(&self.params.spiral, 1, 1);
            for (idx, b) in block.iter().copied().enumerate() {
                b_tilde.get_poly_mut(0, 0)[idx] = b % self.params.q;
            }
            b_tildes.push(to_ntt_alloc(&b_tilde));
        }

        let bodies: Vec<(&PolyMatrixNTT<'a>, &PolyMatrixNTT<'a>)> =
            keys.iter().map(|k| (&k.kg_body, &k.kh_body)).collect();

        let finals = collapse_uploaded_body_b_batched(
            self.params,
            b_tildes,
            &bodies,
            top_images,
            &self.digits_ntt,
        );

        Ok(finals
            .iter()
            .map(|b_final| RlweCiphertext {
                inner: stack_ntt(&self.collapse_a_final_ntt, b_final),
            })
            .collect())
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

fn precompute_reference_trace<'a>(
    params: &'a RlweParams,
    a_agg: Vec<PolyMatrixNTT<'a>>,
) -> QueryReferencePrecomputed<'a> {
    let kg = fixed_reference_key(params, REFERENCE_W_SEED);
    let kh = fixed_reference_key(params, REFERENCE_V_SEED);
    let (left_tables, right_tables) = tau_g_power_tables(params, params.d / 2 - 1);
    let kg_images_left: Vec<_> = left_tables
        .iter()
        .map(|table| automorphic_image_with_table(&kg, table))
        .collect();
    let kg_images_right: Vec<_> = right_tables
        .iter()
        .map(|table| automorphic_image_with_table(&kg, table))
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
    let final_digits = ks_digits_ntt_from_c1(params, &final_state.a[1]);
    collapse_one_with_digits(&mut final_state, &kh, &final_digits);
    digits_ntt.push(final_digits);
    debug_assert_eq!(digits_ntt.len(), params.d - 1);
    let collapse_a_final_ntt = final_state
        .a
        .pop()
        .expect("final reference collapse leaves one component");
    QueryReferencePrecomputed {
        collapse_a_final_ntt,
        digits_ntt,
    }
}

fn collect_half_digits<'a>(
    state: &mut CollapseState<'a>,
    kg_images: &[KeySwitchingMatrix<'a>],
    digits_ntt: &mut Vec<PolyMatrixNTT<'a>>,
) {
    while state.a.len() > 1 {
        let image_idx = state.a.len() - 2;
        // `collapse_one` switches on `state.a[len - 1]`, which is the same `c1`
        // the digits were just taken from, so it must be handed the digits
        // rather than decomposing and re-transforming them a second time.
        let digits = ks_digits_ntt_from_c1(kg_images[image_idx].params, &state.a[image_idx + 1]);
        collapse_one_with_digits(state, &kg_images[image_idx], &digits);
        digits_ntt.push(digits);
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

/// Collapse only the `c2` chain for uploaded packing-key bodies.
///
/// `QueryPackPreprocessed` already stores the matching fixed public `c1` trace,
/// so online packing only needs to add the body-row products to the initial
/// `NTT(b̃)` value.
///
/// The running `c2` enters every collapse step purely additively — it is never
/// permuted or multiplied — so the whole cascade is a *sum*, not a dependency
/// chain:
///
/// ```text
/// b_final = NTT(b̃) + Σ_i τ_i(kg_body) · digits_i + kh_body · digits_last
/// ```
///
/// That has two consequences this implementation exploits. The `d - 1` terms
/// are independent, so they are accumulated by a parallel reduction instead of
/// a serial loop; and every product is bounded by `(q-1)²`, so a single `u128`
/// accumulator per NTT slot absorbs all `(d-1)·ell` of them and needs exactly
/// one Barrett reduction at the end. The previous formulation reduced once per
/// (step, slot), i.e. `(d-1)·d` times per block.
fn collapse_uploaded_body_b<'a>(
    params: &'a RlweParams,
    b: PolyMatrixNTT<'a>,
    kg_body: &PolyMatrixNTT<'a>,
    kh_body: &PolyMatrixNTT<'a>,
    top_images: &TopKeyImages<'a>,
    digits_ntt: &[PolyMatrixNTT<'a>],
) -> PolyMatrixNTT<'a> {
    assert_eq!(
        digits_ntt.len(),
        params.d - 1,
        "preprocess::collapse_uploaded_body_b expects d - 1 digit blocks"
    );

    if !fused_accumulator_fits(params, kg_body.cols) {
        return collapse_uploaded_body_b_stepwise(
            params, b, kg_body, kh_body, top_images, digits_ntt,
        );
    }

    // Collapse execution order: the left half runs its tables from the last
    // image down to the first, then the right half does the same, then the
    // single `K_h` step. `digits_ntt` was recorded in exactly this order.
    let left = &top_images.kg_body_left_tables;
    let right = &top_images.kg_body_right_tables;
    assert_eq!(left.len(), params.d / 2 - 1);
    assert_eq!(right.len(), params.d / 2 - 1);

    let mut schedule: Vec<CollapseTerm<'_, 'a>> = Vec::with_capacity(params.d - 1);
    for (digit_idx, image_idx) in (0..left.len()).rev().enumerate() {
        schedule.push(CollapseTerm {
            body: kg_body,
            table: Some(&left[image_idx]),
            digits: &digits_ntt[digit_idx],
        });
    }
    let right_base = left.len();
    for (digit_idx, image_idx) in (0..right.len()).rev().enumerate() {
        schedule.push(CollapseTerm {
            body: kg_body,
            table: Some(&right[image_idx]),
            digits: &digits_ntt[right_base + digit_idx],
        });
    }
    schedule.push(CollapseTerm {
        body: kh_body,
        table: None,
        digits: &digits_ntt[params.d - 2],
    });
    debug_assert_eq!(schedule.len(), params.d - 1);

    let spiral = &params.spiral;
    let d = spiral.poly_len;
    let lanes = d * spiral.crt_count;

    // Steps are split across threads, each with a private `u128` accumulator
    // over all slots. Splitting by step rather than by slot keeps every thread
    // streaming the digit blocks and permutation tables contiguously, and the
    // per-thread accumulator is only `lanes * 16` bytes.
    let partials = schedule
        .par_chunks(collapse_steps_per_task(schedule.len()))
        .map(|chunk| {
            let mut acc = vec![0_u128; lanes];
            for term in chunk {
                accumulate_collapse_term(spiral, term, &mut acc);
            }
            acc
        })
        .reduce(
            || vec![0_u128; lanes],
            |mut lhs, rhs| {
                for (slot, add) in lhs.iter_mut().zip(rhs.iter()) {
                    *slot += *add;
                }
                lhs
            },
        );

    let mut out = b;
    let out_poly = out.get_poly_mut(0, 0);
    for crt_idx in 0..spiral.crt_count {
        let modulus = spiral.moduli[crt_idx];
        let offset = crt_idx * d;
        for lane in 0..d {
            let acc = partials[offset + lane];
            debug_assert!(
                acc <= u128::MAX - u128::from(modulus),
                "fused collapse accumulator overflowed its proven bound"
            );
            let reduced = barrett_reduction_u128(spiral, acc);
            let sum = out_poly[offset + lane] + reduced;
            out_poly[offset + lane] = if sum >= modulus { sum - modulus } else { sum };
        }
    }
    out
}

/// Collapse `k` queries against one shared digit stream.
///
/// This is the batched counterpart of [`collapse_uploaded_body_b`], and it
/// exists because of an asymmetry in the inner loop: for every product, the
/// gadget-digit operand comes from `digits_ntt` — 100.6 MB per block at
/// `d = 2048, ell = 3`, derived from the CRS alone and therefore identical for
/// every client — while the key-body operand is 48 KB and private to one query.
/// Packing one query streams the whole digit block to perform exactly one
/// multiply-accumulate per 8 bytes read, which is why it is memory-bound rather
/// than arithmetic-bound.
///
/// Batching `k` queries reads that stream once and performs `k` products per 8
/// bytes. The queries are otherwise unrelated: separate secrets, separate key
/// bodies, separate clients. Nothing is shared between them except the public
/// preprocessing they would each have streamed anyway.
///
/// Returns one `b_final` per query, in the order the bodies were given.
fn collapse_uploaded_body_b_batched<'a>(
    params: &'a RlweParams,
    b: Vec<PolyMatrixNTT<'a>>,
    bodies: &[(&PolyMatrixNTT<'a>, &PolyMatrixNTT<'a>)],
    top_images: &TopKeyImages<'a>,
    digits_ntt: &[PolyMatrixNTT<'a>],
) -> Vec<PolyMatrixNTT<'a>> {
    assert_eq!(
        digits_ntt.len(),
        params.d - 1,
        "preprocess::collapse_uploaded_body_b_batched expects d - 1 digit blocks"
    );
    assert_eq!(b.len(), bodies.len(), "one b per key-body pair");

    // The accumulator bound is per accumulator, so it does not depend on `k`;
    // a batch is `k` independent sums, not one longer one. If any query would
    // overflow, every query would, so fall back for the whole batch.
    let fits = bodies
        .iter()
        .all(|(kg, _)| fused_accumulator_fits(params, kg.cols));
    if !fits {
        return b
            .into_iter()
            .zip(bodies.iter())
            .map(|(b_one, (kg, kh))| {
                collapse_uploaded_body_b_stepwise(params, b_one, kg, kh, top_images, digits_ntt)
            })
            .collect();
    }

    let left = &top_images.kg_body_left_tables;
    let right = &top_images.kg_body_right_tables;
    assert_eq!(left.len(), params.d / 2 - 1);
    assert_eq!(right.len(), params.d / 2 - 1);

    // The schedule is shared across the batch: only the body operand varies per
    // query, so a term names its table and digits plus which of the two bodies
    // to use. Execution order matches `collapse_uploaded_body_b` exactly, which
    // is the order `digits_ntt` was recorded in.
    struct BatchedTerm<'t, 'a> {
        table: Option<&'t NttAutomorphTable>,
        digits: &'t PolyMatrixNTT<'a>,
        use_kh: bool,
    }

    let mut schedule: Vec<BatchedTerm<'_, 'a>> = Vec::with_capacity(params.d - 1);
    for (digit_idx, image_idx) in (0..left.len()).rev().enumerate() {
        schedule.push(BatchedTerm {
            table: Some(&left[image_idx]),
            digits: &digits_ntt[digit_idx],
            use_kh: false,
        });
    }
    let right_base = left.len();
    for (digit_idx, image_idx) in (0..right.len()).rev().enumerate() {
        schedule.push(BatchedTerm {
            table: Some(&right[image_idx]),
            digits: &digits_ntt[right_base + digit_idx],
            use_kh: false,
        });
    }
    schedule.push(BatchedTerm {
        table: None,
        digits: &digits_ntt[params.d - 2],
        use_kh: true,
    });
    debug_assert_eq!(schedule.len(), params.d - 1);

    let spiral = &params.spiral;
    let d = spiral.poly_len;
    let lanes = d * spiral.crt_count;
    let k = bodies.len();

    // One contiguous `k * lanes` accumulator per task. At the production shape
    // (`crt_count == 1`, `lanes == 2048`) that is 32 KiB per query, so a batch
    // of eight is 256 KiB per task and stays in L2 on the deployed host.
    let partials = schedule
        .par_chunks(collapse_steps_per_task(schedule.len()))
        .map(|chunk| {
            let mut acc = vec![0_u128; k * lanes];
            for term in chunk {
                for (query_idx, (kg, kh)) in bodies.iter().enumerate() {
                    let body = if term.use_kh { *kh } else { *kg };
                    let slot = &mut acc[query_idx * lanes..(query_idx + 1) * lanes];
                    accumulate_collapse_term(
                        spiral,
                        &CollapseTerm {
                            body,
                            table: term.table,
                            digits: term.digits,
                        },
                        slot,
                    );
                }
            }
            acc
        })
        .reduce(
            || vec![0_u128; k * lanes],
            |mut lhs, rhs| {
                for (slot, add) in lhs.iter_mut().zip(rhs.iter()) {
                    *slot += *add;
                }
                lhs
            },
        );

    b.into_iter()
        .enumerate()
        .map(|(query_idx, mut out)| {
            let acc = &partials[query_idx * lanes..(query_idx + 1) * lanes];
            let out_poly = out.get_poly_mut(0, 0);
            for crt_idx in 0..spiral.crt_count {
                let modulus = spiral.moduli[crt_idx];
                let offset = crt_idx * d;
                for lane in 0..d {
                    let value = acc[offset + lane];
                    debug_assert!(
                        value <= u128::MAX - u128::from(modulus),
                        "batched collapse accumulator overflowed its proven bound"
                    );
                    let reduced = barrett_reduction_u128(spiral, value);
                    let sum = out_poly[offset + lane] + reduced;
                    out_poly[offset + lane] = if sum >= modulus { sum - modulus } else { sum };
                }
            }
            out
        })
        .collect()
}

/// One term of the fused collapse sum.
///
/// `table` is `None` for the final `K_h` step, which uses the body row directly
/// rather than an automorphic image of it.
struct CollapseTerm<'t, 'a> {
    body: &'t PolyMatrixNTT<'a>,
    table: Option<&'t NttAutomorphTable>,
    digits: &'t PolyMatrixNTT<'a>,
}

/// Whether one `u128` accumulator can hold every product of a whole block.
///
/// Each product is at most `(q-1)²` and there are `(d-1) · ell` of them. The
/// production set leaves ample room — `2047 · 3 · (2^56)² ≈ 2^124.6` — but a
/// future parameter set with a larger `q` or `ell` would not, so the stepwise
/// path is retained as a fallback rather than assumed away.
fn fused_accumulator_fits(params: &RlweParams, ell: usize) -> bool {
    let terms = ((params.d - 1) * ell) as u128;
    let max_product = u128::from(params.q - 1).saturating_mul(u128::from(params.q - 1));
    max_product.checked_mul(terms).is_some()
}

/// Steps handed to one rayon task.
///
/// Each task streams `steps * ell` digit polynomials, so the chunk is sized to
/// give every worker a few tasks without making the per-task accumulator setup
/// and the final reduction dominate.
fn collapse_steps_per_task(steps: usize) -> usize {
    let tasks = rayon::current_num_threads().max(1) * 4;
    steps.div_ceil(tasks).max(1)
}

/// Accumulate `τ_table(body) · digits` into `acc` without reducing.
///
/// Slot `dst` of the automorphic image is slot `table[dst]` of `body`, so the
/// image is read through the permutation instead of being materialized.
fn accumulate_collapse_term(spiral: &SpiralParams, term: &CollapseTerm<'_, '_>, acc: &mut [u128]) {
    let d = spiral.poly_len;
    let ell = term.body.cols;
    debug_assert_eq!(term.digits.rows, ell);
    debug_assert_eq!(term.digits.cols, 1);

    // Slot-outer, digit-inner.
    //
    // All `ell` digits of a term accumulate into the *same* slot, so running
    // digits on the outside makes each 32 KiB accumulator take `ell` separate
    // read-modify-write passes. Summing the digits in a register and touching
    // the accumulator once cuts accumulator traffic by `ell` — 3x at the
    // production gadget — and accumulator traffic, not the digit stream, is
    // what this loop is bound by: on the deployed Xeon 8358 it runs at 0.134
    // MAC/cycle while using only 42% of STREAM bandwidth.
    //
    // The reordering is exact, not approximate. These are `u128` integer adds
    // with no modular reduction between them and a proven no-overflow bound
    // (`fused_accumulator_fits`), so the sum is associative and the result is
    // bit-identical; `fused_collapse_matches_stepwise_cascade` pins that.
    // Fast path for the production gadget. Naming the six operand slices
    // directly, rather than indexing an array of slices, is worth more than it
    // looks: `bodies[digit_idx]` reloads a (pointer, length) pair and
    // bounds-checks it on every element, which measured at 16.8 instructions
    // and 7.9 L1 loads per multiply-accumulate on the deployed Xeon at IPC
    // 1.71 — instruction-bound, not memory-bound.
    if ell == 3 && spiral.crt_count == 1 {
        let b0 = &term.body.get_poly(0, 0)[..d];
        let b1 = &term.body.get_poly(0, 1)[..d];
        let b2 = &term.body.get_poly(0, 2)[..d];
        let g0 = &term.digits.get_poly(0, 0)[..d];
        let g1 = &term.digits.get_poly(1, 0)[..d];
        let g2 = &term.digits.get_poly(2, 0)[..d];
        let acc = &mut acc[..d];
        let mask = d - 1;

        match term.table {
            Some(table) => {
                let indices = &table.indices()[..d];
                for dst in 0..d {
                    // `d` is a power of two and every table entry is `< d`
                    // (`NttAutomorphTable::validate_permutation`), so the mask
                    // is the identity here and exists only to let the bound be
                    // proven without a branch.
                    let src = indices[dst] as usize & mask;
                    debug_assert!((indices[dst] as usize) < d, "table index out of range");
                    acc[dst] += u128::from(b0[src]) * u128::from(g0[dst])
                        + u128::from(b1[src]) * u128::from(g1[dst])
                        + u128::from(b2[src]) * u128::from(g2[dst]);
                }
            }
            None => {
                for dst in 0..d {
                    acc[dst] += u128::from(b0[dst]) * u128::from(g0[dst])
                        + u128::from(b1[dst]) * u128::from(g1[dst])
                        + u128::from(b2[dst]) * u128::from(g2[dst]);
                }
            }
        }
        return;
    }

    if ell > MAX_INLINE_ELL {
        accumulate_collapse_term_digit_outer(spiral, term, acc);
        return;
    }

    let mut bodies: [&[u64]; MAX_INLINE_ELL] = [&[]; MAX_INLINE_ELL];
    let mut digits: [&[u64]; MAX_INLINE_ELL] = [&[]; MAX_INLINE_ELL];

    for crt_idx in 0..spiral.crt_count {
        let offset = crt_idx * d;
        for digit_idx in 0..ell {
            bodies[digit_idx] = &term.body.get_poly(0, digit_idx)[offset..offset + d];
            digits[digit_idx] = &term.digits.get_poly(digit_idx, 0)[offset..offset + d];
        }
        let acc_chunk = &mut acc[offset..offset + d];

        match term.table {
            Some(table) => {
                let indices = table.indices();
                debug_assert_eq!(indices.len(), d);
                for (dst, slot) in acc_chunk.iter_mut().enumerate() {
                    let src = indices[dst] as usize;
                    let mut sum = 0_u128;
                    for digit_idx in 0..ell {
                        sum +=
                            u128::from(bodies[digit_idx][src]) * u128::from(digits[digit_idx][dst]);
                    }
                    *slot += sum;
                }
            }
            None => {
                for (dst, slot) in acc_chunk.iter_mut().enumerate() {
                    let mut sum = 0_u128;
                    for digit_idx in 0..ell {
                        sum +=
                            u128::from(bodies[digit_idx][dst]) * u128::from(digits[digit_idx][dst]);
                    }
                    *slot += sum;
                }
            }
        }
    }
}

/// Largest gadget length the slot-outer path keeps its operand slices inline
/// for. Production uses `ell = 3`; anything wider falls back rather than
/// allocating per term.
const MAX_INLINE_ELL: usize = 8;

/// The original digit-outer accumulation, retained for `ell > MAX_INLINE_ELL`.
///
/// Kept as the reference ordering: `accumulate_collapse_term_orderings_agree`
/// pins the fast path against it.
fn accumulate_collapse_term_digit_outer(
    spiral: &SpiralParams,
    term: &CollapseTerm<'_, '_>,
    acc: &mut [u128],
) {
    let d = spiral.poly_len;
    let ell = term.body.cols;

    for crt_idx in 0..spiral.crt_count {
        let offset = crt_idx * d;
        let acc_chunk = &mut acc[offset..offset + d];
        for digit_idx in 0..ell {
            let body_chunk = &term.body.get_poly(0, digit_idx)[offset..offset + d];
            let digit_chunk = &term.digits.get_poly(digit_idx, 0)[offset..offset + d];
            match term.table {
                Some(table) => {
                    let indices = table.indices();
                    debug_assert_eq!(indices.len(), d);
                    for (dst, (slot, digit)) in
                        acc_chunk.iter_mut().zip(digit_chunk.iter()).enumerate()
                    {
                        let src = indices[dst] as usize;
                        *slot += u128::from(body_chunk[src]) * u128::from(*digit);
                    }
                }
                None => {
                    for ((slot, body), digit) in acc_chunk
                        .iter_mut()
                        .zip(body_chunk.iter())
                        .zip(digit_chunk.iter())
                    {
                        *slot += u128::from(*body) * u128::from(*digit);
                    }
                }
            }
        }
    }
}

/// Original per-step collapse, retained for parameter sets whose products do
/// not fit a single `u128` accumulator across a whole block.
fn collapse_uploaded_body_b_stepwise<'a>(
    params: &'a RlweParams,
    mut b: PolyMatrixNTT<'a>,
    kg_body: &PolyMatrixNTT<'a>,
    kh_body: &PolyMatrixNTT<'a>,
    top_images: &TopKeyImages<'a>,
    digits_ntt: &[PolyMatrixNTT<'a>],
) -> PolyMatrixNTT<'a> {
    let mut digit_idx = 0;
    b = collapse_uploaded_body_half(
        b,
        kg_body,
        &top_images.kg_body_left_tables,
        digits_ntt,
        &mut digit_idx,
    );
    b = collapse_uploaded_body_half(
        b,
        kg_body,
        &top_images.kg_body_right_tables,
        digits_ntt,
        &mut digit_idx,
    );

    let mut final_b = PolyMatrixNTT::zero(&params.spiral, 1, 1);
    multiply(&mut final_b, kh_body, &digits_ntt[digit_idx]);
    add_into(&mut final_b, &b);
    digit_idx += 1;
    assert_eq!(digit_idx, digits_ntt.len());
    final_b
}

/// One half of the stepwise fallback cascade.
fn collapse_uploaded_body_half<'a>(
    mut b: PolyMatrixNTT<'a>,
    kg_body: &PolyMatrixNTT<'a>,
    body_tables: &[NttAutomorphTable],
    digits_ntt: &[PolyMatrixNTT<'a>],
    digit_idx: &mut usize,
) -> PolyMatrixNTT<'a> {
    for image_idx in (0..body_tables.len()).rev() {
        let mut next_b = multiply_permuted_body_by_digits(
            kg_body,
            &body_tables[image_idx],
            &digits_ntt[*digit_idx],
        );
        add_into(&mut next_b, &b);
        b = next_b;
        *digit_idx += 1;
    }
    b
}

/// Switch using a key whose body row is represented by an NTT slot permutation.
///
/// The result is identical to multiplying `[top_row; tau(body_row)]` by
/// `digits_ntt`, but the `tau(body_row)` matrix is never allocated.
#[cfg(test)]
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
#[cfg(test)]
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
#[cfg(test)]
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
    let body_indices = body_table.indices();
    let mut out = PolyMatrixNTT::zero(spiral, 1, 1);
    let out_poly = out.get_poly_mut(0, 0);

    for crt_idx in 0..spiral.crt_count {
        let modulus = u128::from(spiral.moduli[crt_idx]);
        let max_product = (modulus - 1) * (modulus - 1);
        let can_reduce_once = max_product.checked_mul(body_row.cols as u128).is_some();
        let offset = crt_idx * d;
        let out_chunk = &mut out_poly[offset..offset + d];
        for dst_idx in 0..d {
            // NTT-domain automorphisms are slot permutations. Reading the
            // source slot here is equivalent to multiplying by the materialized
            // automorphic body image at `dst_idx`.
            let src_idx = body_indices[dst_idx] as usize;
            let mut acc = 0_u128;
            for digit_idx in 0..body_row.cols {
                let body_poly = body_row.get_poly(0, digit_idx);
                let digit_poly = digits_ntt.get_poly(digit_idx, 0);
                let body_chunk = &body_poly[offset..offset + d];
                let digit_chunk = &digit_poly[offset..offset + d];
                let product = u128::from(body_chunk[src_idx]) * u128::from(digit_chunk[dst_idx]);
                acc = if can_reduce_once {
                    acc + product
                } else {
                    (acc + product) % modulus
                };
            }
            out_chunk[dst_idx] = (acc % modulus) as u64;
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

/// Build the `d` aggregated CRS slots of `PackPublicPreprocessed`.
///
/// Slot `e` is `Σ_j X^j · τ_e(ã_j)` scaled by `d^{-1}`, where `e` runs over the
/// `d/2` powers of `τ_g` and then those same powers composed with `τ_h`.
///
/// Evaluated literally that is `Θ(d³)` — `d` slots × `d` rows × `d` coefficients
/// — which at `d = 2048` is 8.6e9 scatter-adds and was essentially all of the
/// offline cost. The NTT domain collapses it to `Θ(d² log d)`:
///
/// - an automorphism is a slot permutation there, so `τ_e(ã_j)` at slot `s` is
///   just `Â_j` read at slot `π_e(s)` (this is what [`NttAutomorphTable`]
///   already encodes for the online path);
/// - multiplying by `X^j` is pointwise multiplication by `ω_s^j`.
///
/// So `out_e[s] = Σ_j ω_s^j · Â_j[π_e(s)] = Q_{π_e(s)}(ω_s)`, where
/// `Q_v(Y) = Σ_j Â_j[v] · Y^j` is the polynomial whose coefficients are slot `v`
/// taken across all `d` rows. Evaluating `Q_v` at every `ω_s` *is* one forward
/// NTT, and with `s` fixed `π_e(s)` runs over every slot as `e` varies — so the
/// whole family needs the single table `E[v][s] = Q_v(ω_s)`, which is `d` NTTs.
///
/// Total: `2d` length-`d` NTTs plus `O(d²)` data movement, against `d³`.
/// The result is exact — the NTT is a ring isomorphism, so this agrees with the
/// direct computation coefficient for coefficient, which
/// `build_a_agg_matches_direct_transform` pins.
fn build_a_agg<'a>(params: &'a RlweParams, a_tildes: &[Vec<u64>]) -> Vec<PolyMatrixNTT<'a>> {
    let spiral = &params.spiral;
    let d = params.d;
    assert_eq!(a_tildes.len(), d, "preprocess::build_a_agg expects d rows");

    // The transposed formulation indexes NTT slots and CRS rows by the same
    // range, which only lines up for a single CRT modulus. Every `inspiring`
    // parameter set is single-CRT; a hypothetical multi-CRT one falls back.
    if spiral.crt_count != 1 {
        return build_a_agg_direct(params, a_tildes);
    }

    // Step 1: Â_j = NTT(ã_j), one row per CRS row.
    let mut a_hat = vec![0_u64; d * d];
    a_hat
        .par_chunks_mut(d)
        .zip(a_tildes.par_iter())
        .for_each(|(dst, src)| {
            debug_assert!(src.iter().all(|coeff| *coeff < params.q));
            dst.copy_from_slice(src);
            ntt_forward(spiral, dst);
        });

    // Step 2: Q_v has coefficients (Â_j[v])_j, so transpose and NTT again.
    // `e_table[v * d + s]` is then Q_v(ω_s).
    let mut e_table = vec![0_u64; d * d];
    transpose_square(&a_hat, &mut e_table, d);
    drop(a_hat);
    e_table
        .par_chunks_mut(d)
        .for_each(|row| ntt_forward(spiral, row));

    // Step 3 reads `E[π_e(s)][s]` for every `(e, s)`. Transposing once more so
    // the varying index is contiguous turns that from a 16 KiB-stride gather
    // into a scan of one cache-resident row per `s`.
    let mut e_by_slot = vec![0_u64; d * d];
    transpose_square(&e_table, &mut e_by_slot, d);
    drop(e_table);

    // Slot order matches `aggregate_slot`: τ_g^e for the left half, then
    // τ_g^(e - d/2) ∘ τ_h for the right half.
    let (left_tables, right_tables) = tau_g_power_tables(params, d / 2);

    let mut out: Vec<PolyMatrixNTT<'a>> =
        (0..d).map(|_| PolyMatrixNTT::zero(spiral, 1, 1)).collect();
    out.par_chunks_mut(A_AGG_SLOT_BLOCK)
        .enumerate()
        .for_each(|(block_idx, out_block)| {
            let base = block_idx * A_AGG_SLOT_BLOCK;
            for s_start in (0..d).step_by(A_AGG_COEFF_BLOCK) {
                let s_end = (s_start + A_AGG_COEFF_BLOCK).min(d);
                for (offset, out_poly) in out_block.iter_mut().enumerate() {
                    let slot = base + offset;
                    let table = if slot < d / 2 {
                        &left_tables[slot]
                    } else {
                        &right_tables[slot - d / 2]
                    };
                    let indices = table.indices();
                    let dst = out_poly.get_poly_mut(0, 0);
                    for s in s_start..s_end {
                        let value = e_by_slot[s * d + indices[s] as usize];
                        dst[s] = ((u128::from(value) * u128::from(params.d_inv))
                            % u128::from(params.q)) as u64;
                    }
                }
            }
        });

    out
}

/// Output slots handed to one rayon task.
const A_AGG_SLOT_BLOCK: usize = 64;

/// Coefficient tile held in cache while a task sweeps its output slots.
///
/// Each `s` needs a whole `d`-wide row of `e_by_slot`, so the tile is sized so
/// that `A_AGG_COEFF_BLOCK * d * 8` bytes stay resident across the inner slot
/// loop rather than being re-streamed per slot.
const A_AGG_COEFF_BLOCK: usize = 32;

/// Cache-blocked square transpose.
fn transpose_square(src: &[u64], dst: &mut [u64], d: usize) {
    const TILE: usize = 32;
    debug_assert_eq!(src.len(), d * d);
    debug_assert_eq!(dst.len(), d * d);

    dst.par_chunks_mut(TILE * d)
        .enumerate()
        .for_each(|(tile_idx, dst_rows)| {
            let row_start = tile_idx * TILE;
            let rows = dst_rows.len() / d;
            for col_start in (0..d).step_by(TILE) {
                let col_end = (col_start + TILE).min(d);
                for (local_row, row) in (row_start..row_start + rows).enumerate() {
                    let dst_row = &mut dst_rows[local_row * d..local_row * d + d];
                    for col in col_start..col_end {
                        dst_row[col] = src[col * d + row];
                    }
                }
            }
        });
}

/// Direct `Θ(d³)` aggregate: the definition, retained as the multi-CRT
/// fallback and as the differential oracle for [`build_a_agg`].
fn build_a_agg_direct<'a>(params: &'a RlweParams, a_tildes: &[Vec<u64>]) -> Vec<PolyMatrixNTT<'a>> {
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

/// Accumulate `X^shift * tau_exponent(poly)` into `out`, modulo `q`.
///
/// This is the innermost loop of [`build_a_agg`] and runs `d^3` times per CRS
/// block, so it avoids hardware division entirely:
///
/// - `poly` is an `a_tilde`, and [`a_tilde_coeffs`] already reduces every
///   coefficient modulo `q`, so no input reduction is needed.
/// - `2d` is a power of two, so the exponent wrap is a mask rather than a `%`.
/// - both addends are already below `q`, so the accumulation is a conditional
///   subtract rather than a 128-bit modulo.
///
/// # Panics
///
/// Panics in debug builds if `out.len()` is not a power of two, or if any
/// coefficient of `poly` is not already reduced modulo `q`.
fn add_shifted_tau(out: &mut [u64], poly: &[u64], exponent: u64, shift: usize, q: u64) {
    let d = out.len();
    debug_assert!(
        d.is_power_of_two(),
        "add_shifted_tau requires power-of-two d"
    );
    debug_assert!(
        poly.iter().all(|coeff| *coeff < q),
        "add_shifted_tau expects a_tilde coefficients already reduced mod q"
    );

    let d_u64 = d as u64;
    let two_d_mask = 2 * d_u64 - 1;

    for (source_idx, coeff) in poly.iter().enumerate() {
        let reduced = *coeff;
        if reduced == 0 {
            continue;
        }

        let exp = (source_idx as u64 * exponent) & two_d_mask;
        let mut idx = if exp < d_u64 {
            exp as usize
        } else {
            (exp - d_u64) as usize
        };
        let mut negate = exp >= d_u64;

        idx += shift;
        if idx >= d {
            idx -= d;
            negate = !negate;
        }

        let term = if negate { q - reduced } else { reduced };
        let sum = out[idx] + term;
        out[idx] = if sum >= q { sum - q } else { sum };
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

    fn packing_keys<'a>(params: &'a RlweParams, seed: u64) -> PackingKeys<'a> {
        PackingKeys {
            kg_body: ntt_matrix(params, 1, params.gadget.ell, seed),
            kh_body: ntt_matrix(
                params,
                1,
                params.gadget.ell,
                seed.wrapping_mul(31).wrapping_add(7),
            ),
        }
    }

    /// Production gadget length, so the specialized `ell == 3` path is the one
    /// under test. The default `params()` uses `ell = 5` and would silently
    /// exercise only the generic path.
    fn params_ell3() -> RlweParams {
        RlweParams::new(
            8,
            12289,
            4,
            3.2,
            GadgetParams {
                bits_per: 5,
                ell: 3,
            },
        )
        .expect("valid ell=3 params")
    }

    /// The `ell == 3` specialization must match the generic ordering exactly.
    ///
    /// It indexes operand slices as `indices[dst] & (d - 1)` instead of with a
    /// bounds check, so this also guards the masking against the permutation
    /// invariant it relies on.
    #[test]
    fn accumulate_collapse_term_ell3_specialization_matches_generic() {
        let params = params_ell3();
        let d = params.d;
        let ell = params.gadget.ell;
        assert_eq!(ell, 3, "this test must drive the specialized path");
        assert_eq!(params.spiral.crt_count, 1);

        let images = TopKeyImages::build(&params);
        let body = ntt_matrix(&params, 1, ell, params.q - 5);
        let digits = ntt_matrix(&params, ell, 1, params.q - 17);

        for table in [
            Some(&images.kg_body_left_tables[0]),
            Some(&images.kg_body_right_tables[0]),
            None,
        ] {
            if let Some(table) = table {
                assert!(
                    table.validate_permutation(d),
                    "hot-path masking requires a genuine permutation of 0..d"
                );
            }
            let term = CollapseTerm {
                body: &body,
                table,
                digits: &digits,
            };

            let mut fast = vec![0_u128; d];
            let mut reference = vec![0_u128; d];
            for _ in 0..2 {
                accumulate_collapse_term(&params.spiral, &term, &mut fast);
                accumulate_collapse_term_digit_outer(&params.spiral, &term, &mut reference);
            }

            assert_eq!(
                fast,
                reference,
                "ell=3 specialization disagrees with the generic path (table: {})",
                table.is_some()
            );
            assert!(fast.iter().any(|v| *v != 0), "all-zero accumulator");
        }
    }

    /// Every cached automorphism table must be a permutation of `0..d`.
    ///
    /// The packing hot loop masks its operand index instead of bounds-checking
    /// it, so a table that was not a bijection would read the wrong slot
    /// silently rather than panicking.
    #[test]
    fn cached_automorphism_tables_are_permutations() {
        for params in [params(), params_ell3()] {
            let images = TopKeyImages::build(&params);
            for table in images
                .kg_body_left_tables
                .iter()
                .chain(images.kg_body_right_tables.iter())
            {
                assert!(
                    table.validate_permutation(params.d),
                    "cached table is not a permutation of 0..{}",
                    params.d
                );
            }
        }
    }

    /// The slot-outer reordering must be bit-exact against digit-outer.
    ///
    /// Both the permuted (`K_g`) and contiguous (`K_h`) branches are covered,
    /// with operands near `q` so any lost carry in the `u128` accumulation
    /// shows up rather than cancelling.
    #[test]
    fn accumulate_collapse_term_orderings_agree() {
        let params = params();
        let d = params.d;
        let ell = params.gadget.ell;
        let images = TopKeyImages::build(&params);

        let body = ntt_matrix(&params, 1, ell, params.q - 3);
        let digits = ntt_matrix(&params, ell, 1, params.q - 11);

        for table in [Some(&images.kg_body_left_tables[0]), None] {
            let term = CollapseTerm {
                body: &body,
                table,
                digits: &digits,
            };

            let mut fast = vec![0_u128; d * params.spiral.crt_count];
            let mut reference = vec![0_u128; d * params.spiral.crt_count];
            // Accumulate twice so a term is exercised on a non-zero
            // accumulator, which is how the real cascade uses it.
            for _ in 0..2 {
                accumulate_collapse_term(&params.spiral, &term, &mut fast);
                accumulate_collapse_term_digit_outer(&params.spiral, &term, &mut reference);
            }

            assert_eq!(
                fast,
                reference,
                "slot-outer and digit-outer accumulation disagree (table: {})",
                table.is_some()
            );
            assert!(
                fast.iter().any(|v| *v != 0),
                "test inputs produced an all-zero accumulator"
            );
        }
    }

    /// Batching changes memory traffic, not arithmetic.
    ///
    /// Every batched ciphertext must be bit-identical to the one the
    /// single-query path produces for the same input, for every query in the
    /// batch. Distinct key bodies and distinct `b` blocks are used so a bug
    /// that crossed accumulator slots between queries — the obvious failure
    /// mode — cannot pass by symmetry.
    #[test]
    fn batched_pack_matches_sequential() {
        // Both gadget lengths: `ell = 5` drives the generic accumulation and
        // `ell = 3` the production specialization. Testing only the default
        // params would leave the path the server actually runs uncovered.
        for params in [params(), params_ell3()] {
            batched_pack_matches_sequential_at(&params);
        }
    }

    fn batched_pack_matches_sequential_at(params: &RlweParams) {
        let crs = crs(params);
        let pre = QueryPackPreprocessed::build(params, &crs).expect("valid preprocessing");
        let top = TopKeyImages::build(params);

        for k in [1_usize, 2, 3, 5] {
            let keys: Vec<PackingKeys<'_>> = (0..k)
                .map(|idx| packing_keys(params, 1_000 + idx as u64 * 977))
                .collect();
            let blocks: Vec<Vec<u64>> = (0..k)
                .map(|idx| {
                    (0..params.d)
                        .map(|c| ((c as u64 + 1) * (idx as u64 * 13 + 5) + idx as u64) % params.q)
                        .collect()
                })
                .collect();

            let expected: Vec<RlweCiphertext<'_>> = blocks
                .iter()
                .zip(keys.iter())
                .map(|(b, key)| {
                    pre.pack_b_prevalidated(b, key, &top)
                        .expect("sequential pack succeeds")
                })
                .collect();

            let block_refs: Vec<&[u64]> = blocks.iter().map(|b| b.as_slice()).collect();
            let key_refs: Vec<&PackingKeys<'_>> = keys.iter().collect();
            let batched = pre
                .pack_b_batched_prevalidated(&block_refs, &key_refs, &top)
                .expect("batched pack succeeds");

            assert_eq!(batched.len(), k, "batch returns one ciphertext per query");
            for (idx, (got, want)) in batched.iter().zip(expected.iter()).enumerate() {
                assert_eq!(
                    got.inner.as_slice(),
                    want.inner.as_slice(),
                    "batched query {idx} of {k} differs from the sequential result"
                );
            }
        }
    }

    #[test]
    fn batched_pack_rejects_mismatched_lengths() {
        let params = params();
        let crs = crs(&params);
        let pre = QueryPackPreprocessed::build(&params, &crs).expect("valid preprocessing");
        let top = TopKeyImages::build(&params);
        let key = packing_keys(&params, 5);
        let block = b_scalars(&params);

        assert!(matches!(
            pre.pack_b_batched_prevalidated(&[block.as_slice()], &[], &top),
            Err(InspiringError::LweShape(_))
        ));
        assert!(pre
            .pack_b_batched_prevalidated(&[], &[], &top)
            .expect("empty batch is not an error")
            .is_empty());

        let short = vec![0_u64; params.d - 1];
        assert!(matches!(
            pre.pack_b_batched_prevalidated(&[short.as_slice()], &[&key], &top),
            Err(InspiringError::LweShape(_))
        ));
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
    fn switch_with_body_matches_materialized_key_product() {
        let params = params();
        let top = ntt_matrix(&params, 1, params.gadget.ell, 5);
        let body = ntt_matrix(&params, 1, params.gadget.ell, 13);
        let digits = ntt_matrix(&params, params.gadget.ell, 1, 31);
        let c2 = ntt_matrix(&params, 1, 1, 43);

        let (actual_a, actual_b) = switch_with_body(&top, &body, &digits, &c2);

        let mut expected_a = PolyMatrixNTT::zero(&params.spiral, 1, 1);
        multiply(&mut expected_a, &top, &digits);
        let mut expected_b = PolyMatrixNTT::zero(&params.spiral, 1, 1);
        multiply(&mut expected_b, &body, &digits);
        add_into(&mut expected_b, &c2);

        assert_eq!(actual_a.as_slice(), expected_a.as_slice());
        assert_eq!(actual_b.as_slice(), expected_b.as_slice());
    }

    fn uploaded_key_fixture() -> (
        &'static RlweParams,
        QueryPackPreprocessed<'static>,
        PackPublicPreprocessed<'static>,
        PackingKeys<'static>,
        TopKeyImages<'static>,
    ) {
        let params = Box::leak(Box::new(params()));
        let crs = crs(params);
        let public = PackPublicPreprocessed::build(params, &crs).expect("public preprocess");
        let pre = QueryPackPreprocessed::build(params, &crs).expect("preprocess");
        let secret_raw = {
            let mut raw = PolyMatrixRaw::zero(&params.spiral, 1, 1);
            raw.get_poly_mut(0, 0)[0] = 1;
            raw.get_poly_mut(0, 0)[2] = params.q - 1;
            raw
        };
        let secret_ntt = to_ntt_alloc(&secret_raw);
        let mut rng = ChaCha20Rng::from_seed([42; 32]);
        let keys = PackingKeys::generate_full(params, &secret_ntt, &mut rng);
        let top_images = TopKeyImages::build(params);

        (params, pre, public, keys, top_images)
    }

    #[test]
    fn pack_b_prevalidated_matches_pack_b() {
        let (params, pre, _public, keys, top_images) = uploaded_key_fixture();
        let b_scalars = b_scalars(params);

        let checked = pre.pack_b(&b_scalars, &keys, &top_images).expect("pack b");
        keys.validate(pre.params).expect("keys validate");
        top_images
            .validate(pre.params)
            .expect("top images validate");
        let prevalidated = pre
            .pack_b_prevalidated(&b_scalars, &keys, &top_images)
            .expect("pack b prevalidated");

        assert_eq!(prevalidated.inner.as_slice(), checked.inner.as_slice());
    }

    #[test]
    fn query_preprocess_stores_fixed_c1_trace() {
        let (params, pre, public, _keys, _top_images) = uploaded_key_fixture();
        let expected = precompute_reference_trace(params, public.a_agg);

        assert_eq!(pre.collapse_a_final_ntt.rows, 1);
        assert_eq!(pre.collapse_a_final_ntt.cols, 1);
        assert_eq!(pre.digits_ntt.len(), pre.params.d - 1);
        assert_eq!(
            pre.collapse_a_final_ntt.as_slice(),
            expected.collapse_a_final_ntt.as_slice()
        );
        assert_eq!(pre.digits_ntt.len(), expected.digits_ntt.len());
        for (actual, expected) in pre.digits_ntt.iter().zip(expected.digits_ntt.iter()) {
            assert_eq!(actual.as_slice(), expected.as_slice());
        }
    }

    #[test]
    fn pack_with_uploaded_key_bodies_returns_rlwe_ciphertext() {
        let (params, pre, _public, keys, top_images) = uploaded_key_fixture();
        let b_scalars = b_scalars(params);
        let ct = pre.pack_b(&b_scalars, &keys, &top_images).expect("pack b");
        let mut b_tilde = PolyMatrixRaw::zero(&params.spiral, 1, 1);
        for (idx, b) in b_scalars.iter().copied().enumerate() {
            b_tilde.get_poly_mut(0, 0)[idx] = b;
        }
        let expected_b = collapse_uploaded_body_b(
            params,
            to_ntt_alloc(&b_tilde),
            &keys.kg_body,
            &keys.kh_body,
            &top_images,
            &pre.digits_ntt,
        );
        let expected = RlweCiphertext {
            inner: stack_ntt(&pre.collapse_a_final_ntt, &expected_b),
        };

        assert_eq!(ct.inner.rows, 2);
        assert_eq!(ct.inner.cols, 1);
        assert_eq!(ct.inner.as_slice(), expected.inner.as_slice());
    }

    /// A `d = 128`, 56-bit-`q`, `ell = 3` set: the production shape in
    /// miniature, so the fused accumulator carries realistic magnitudes.
    fn production_like_params() -> RlweParams {
        RlweParams::new(
            128,
            72_057_594_037_641_217,
            1 << 14,
            6.4,
            GadgetParams {
                bits_per: 19,
                ell: 3,
            },
        )
        .expect("valid production-like params")
    }

    fn random_crs<'a>(params: &'a RlweParams, seed: u64) -> PolyMatrixNTT<'a> {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let mut raw = PolyMatrixRaw::zero(&params.spiral, params.d, 1);
        for coeff in raw.as_mut_slice().iter_mut() {
            *coeff = rand::Rng::gen_range(&mut rng, 0..params.q);
        }
        to_ntt_alloc(&raw)
    }

    /// The fused collapse must be byte-identical to the per-step cascade it
    /// replaced. The accumulator bound is what makes it safe, so this runs at a
    /// 56-bit modulus rather than the 14-bit fixture modulus.
    #[test]
    fn fused_collapse_matches_stepwise_cascade() {
        let params = production_like_params();
        assert!(
            fused_accumulator_fits(&params, params.gadget.ell),
            "the fused path must be the one under test here"
        );

        let crs = random_crs(&params, 0x_C0_11_AB_5E);
        let pre = QueryPackPreprocessed::build(&params, &crs).expect("preprocess");
        let top_images = TopKeyImages::build(&params);

        let mut rng = ChaCha20Rng::from_seed([7; 32]);
        let secret_ntt = to_ntt_alloc(&PolyMatrixRaw::random_rng(&params.spiral, 1, 1, &mut rng));
        let keys = PackingKeys::generate_full(&params, &secret_ntt, &mut rng);

        let mut b_tilde = PolyMatrixRaw::zero(&params.spiral, 1, 1);
        for coeff in b_tilde.get_poly_mut(0, 0).iter_mut() {
            *coeff = rand::Rng::gen_range(&mut rng, 0..params.q);
        }
        let b_ntt = to_ntt_alloc(&b_tilde);

        let fused = collapse_uploaded_body_b(
            &params,
            b_ntt.clone(),
            &keys.kg_body,
            &keys.kh_body,
            &top_images,
            &pre.digits_ntt,
        );
        let stepwise = collapse_uploaded_body_b_stepwise(
            &params,
            b_ntt,
            &keys.kg_body,
            &keys.kh_body,
            &top_images,
            &pre.digits_ntt,
        );

        assert_eq!(fused.as_slice(), stepwise.as_slice());
    }

    /// The fallback exists for parameter sets whose products would overflow one
    /// `u128` across a block. Pin both sides of that decision.
    #[test]
    fn fused_accumulator_bound_gates_on_q_and_ell() {
        let production = production_like_params();
        assert!(fused_accumulator_fits(&production, 3));
        // 2^63-scale moduli leave no room: (2^63)^2 * 3 * (d-1) exceeds 2^128.
        let wide = RlweParams {
            q: (1 << 63) - 25,
            ..production
        };
        assert!(!fused_accumulator_fits(&wide, 3));
    }

    /// The NTT-domain aggregate must reproduce the `Θ(d³)` definition exactly,
    /// not approximately: the NTT is a ring isomorphism, so any mismatch is a
    /// bug in the index algebra, not rounding.
    #[test]
    fn build_a_agg_matches_direct_transform() {
        for params in [params(), production_like_params()] {
            let mut rng = ChaCha20Rng::seed_from_u64(0x_A6_6E_60);
            let a_tildes: Vec<Vec<u64>> = (0..params.d)
                .map(|_| {
                    (0..params.d)
                        .map(|_| rand::Rng::gen_range(&mut rng, 0..params.q))
                        .collect()
                })
                .collect();

            let fast = build_a_agg(&params, &a_tildes);
            let direct = build_a_agg_direct(&params, &a_tildes);

            assert_eq!(fast.len(), direct.len());
            for (slot, (fast, direct)) in fast.iter().zip(direct.iter()).enumerate() {
                assert_eq!(
                    fast.as_slice(),
                    direct.as_slice(),
                    "aggregate slot {slot} differs at d={}",
                    params.d
                );
            }
        }
    }

    #[test]
    fn transpose_square_moves_every_element() {
        let d = 64;
        let src: Vec<u64> = (0..(d * d) as u64).collect();
        let mut dst = vec![0_u64; d * d];
        transpose_square(&src, &mut dst, d);
        for row in 0..d {
            for col in 0..d {
                assert_eq!(dst[row * d + col], src[col * d + row]);
            }
        }
    }
}
