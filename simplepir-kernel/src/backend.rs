use inspiring::RlweParams;

/// Plaintext database element type accepted by SimplePIR kernels.
///
/// The database is stored as a flat column-major slice. Kernels convert each
/// element through [`ToU64::to_u64`] before multiplying it by a `u64` query
/// coefficient. [`ToU64::MAX_VALUE`] lets optimized kernels choose safe
/// accumulation windows without inspecting the database contents.
///
/// `Send + Sync` is required because kernels evaluate column bands in parallel;
/// the database itself is only ever read.
pub trait ToU64: Copy + Send + Sync {
    /// Largest representable value for the database scalar type.
    ///
    /// Implementations should report the type-level maximum, not the maximum of
    /// a particular database instance. `ChunkedSplitKernel` uses this as a
    /// conservative bound to avoid overflowing limb accumulators.
    const MAX_VALUE: u64;

    /// Convert a plaintext database element to a `u64`.
    ///
    /// The returned value is interpreted as a non-negative plaintext integer.
    fn to_u64(self) -> u64;
}

impl ToU64 for u8 {
    const MAX_VALUE: u64 = u8::MAX as u64;

    fn to_u64(self) -> u64 {
        self as u64
    }
}

impl ToU64 for u16 {
    const MAX_VALUE: u64 = u16::MAX as u64;

    fn to_u64(self) -> u64 {
        self as u64
    }
}

impl ToU64 for u32 {
    const MAX_VALUE: u64 = u32::MAX as u64;

    fn to_u64(self) -> u64 {
        self as u64
    }
}

impl ToU64 for u64 {
    const MAX_VALUE: u64 = u64::MAX;

    fn to_u64(self) -> u64 {
        self
    }
}

/// Backend for multiplying one packed first-dimension query by a column-major DB.
///
/// Implementors receive the database exactly as `ipir-sp` stores it:
/// `db[col * rows_padded + row]`. The output slice has one value per database
/// column, reduced modulo `rlwe.q`.
///
/// The trait is object-safe by design. Servers can store
/// `Box<dyn FirstDimKernel<T>>`, which makes the online multiplication backend a
/// runtime choice while keeping the public server API stable.
pub trait FirstDimKernel<T>: Send + Sync
where
    T: Copy + ToU64,
{
    /// Optional one-shot backend setup hook.
    ///
    /// `ipir-sp::YServer::with_kernel` calls this after the input iterator has
    /// been materialized into column-major storage and before the server is
    /// returned to the caller. CPU kernels leave this as a no-op. A future GPU
    /// backend can use it to upload the database once and cache device-side
    /// state keyed by `(rows_padded, cols)`.
    fn prepare(&mut self, _db: &[T], _rows_padded: usize, _cols: usize) {}

    /// Compute the first-dimension query/database product.
    ///
    /// Required shapes:
    ///
    /// - `query.len() == rows_padded`
    /// - `db.len() == rows_padded * cols`
    /// - `out.len() == cols`
    ///
    /// `element_max` is an upper bound on every value in `db`, which kernels
    /// use to size delayed-reduction windows. It must be a true bound: a value
    /// larger than it silently overflows the accumulators. `ToU64::MAX_VALUE`
    /// is always safe but is usually far too loose — SimplePIR plaintexts are
    /// `log2(p)`-bit values, so the production database of 14-bit plaintexts in
    /// `u16` storage gets a `2^18`-row window from the real bound against
    /// `2^16` from the type, which decides whether a 112,640-row column is
    /// swept in one pass or two.
    ///
    /// Implementations should write every element of `out`. They may panic on
    /// shape mismatches, matching the existing `ipir-sp` server behavior.
    #[allow(clippy::too_many_arguments)]
    fn multiply_query(
        &self,
        rlwe: &RlweParams,
        db: &[T],
        rows_padded: usize,
        cols: usize,
        query: &[u64],
        element_max: u64,
        out: &mut [u64],
    );
}
