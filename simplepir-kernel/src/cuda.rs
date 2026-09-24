//! Exact u16 matrix/vector multiplication with persistent CUDA allocations.
use crate::{FirstDimKernel, KernelError};
use cudarc::{
    driver::{CudaContext, CudaFunction, CudaSlice, CudaStream, LaunchConfig, PushKernelArg},
    nvrtc::compile_ptx,
};
use inspiring::RlweParams;
use std::sync::{Arc, Mutex};
fn error(e: impl std::fmt::Display) -> KernelError {
    KernelError(format!("CUDA: {e}"))
}
struct Prepared {
    db: CudaSlice<u16>,
    query: CudaSlice<u64>,
    partial: CudaSlice<u64>,
    out: CudaSlice<u64>,
    rows: usize,
    cols: usize,
    tiles: usize,
}
/// A device-bound kernel. Preparation uploads an immutable database snapshot.
/// Evaluation uses that snapshot; callers must reprepare after changing the DB.
/// Concurrent evaluations serialize access to reusable scratch allocations.
pub struct CudaKernel {
    stream: Arc<CudaStream>,
    tile: CudaFunction,
    reduce: CudaFunction,
    prepared: Mutex<Option<Prepared>>,
}
impl CudaKernel {
    /// Open a device and compile exact arithmetic kernels, without CPU fallback.
    pub fn new(device: usize) -> Result<Self, KernelError> {
        // SAFETY: these probes only load the vendor libraries.
        if !unsafe { cudarc::driver::sys::is_culib_present() }
            || !unsafe { cudarc::nvrtc::sys::is_culib_present() }
        {
            return Err(error("CUDA driver and NVRTC shared libraries are required"));
        }
        let ctx = CudaContext::new(device).map_err(error)?;
        let ptx = compile_ptx(include_str!("matvec.cu")).map_err(error)?;
        let module = ctx.load_module(ptx).map_err(error)?;
        Ok(Self {
            stream: ctx.new_stream().map_err(error)?,
            tile: module.load_function("tile_products").map_err(error)?,
            reduce: module.load_function("reduce_tiles").map_err(error)?,
            prepared: Mutex::new(None),
        })
    }
}
impl FirstDimKernel<u16> for CudaKernel {
    fn prepare(&mut self, db: &[u16], rows: usize, cols: usize) {
        self.try_prepare(db, rows, cols)
            .expect("CUDA preparation failed");
    }
    fn try_prepare(&mut self, db: &[u16], rows: usize, cols: usize) -> Result<(), KernelError> {
        self.stream.context().bind_to_thread().map_err(error)?;
        // A failed replacement must not leave the old snapshot usable.
        *self
            .prepared
            .get_mut()
            .map_err(|_| error("state lock poisoned"))? = None;
        if rows.checked_mul(cols) != Some(db.len()) {
            return Err(error("database shape mismatch"));
        }
        if rows > isize::MAX as usize / 8 {
            return Err(error("query allocation size overflow"));
        }
        let tiles = rows.div_ceil(4096);
        let blocks = tiles
            .checked_mul(cols)
            .ok_or_else(|| error("tile count overflow"))?;
        if blocks > i32::MAX as usize || cols > i32::MAX as usize {
            return Err(error("CUDA grid is too large"));
        }
        let state = Prepared {
            db: self.stream.memcpy_stod(db).map_err(error)?,
            query: self.stream.alloc_zeros(rows).map_err(error)?,
            partial: self.stream.alloc_zeros(blocks).map_err(error)?,
            out: self.stream.alloc_zeros(cols).map_err(error)?,
            rows,
            cols,
            tiles,
        };
        self.stream.synchronize().map_err(error)?;
        *self
            .prepared
            .get_mut()
            .map_err(|_| error("state lock poisoned"))? = Some(state);
        Ok(())
    }
    fn multiply_query(
        &self,
        rlwe: &RlweParams,
        db: &[u16],
        rows: usize,
        cols: usize,
        query: &[u64],
        max: u64,
        out: &mut [u64],
    ) {
        self.try_multiply_query(rlwe, db, rows, cols, query, max, out)
            .expect("CUDA evaluation failed");
    }
    fn try_multiply_query(
        &self,
        rlwe: &RlweParams,
        db: &[u16],
        rows: usize,
        cols: usize,
        query: &[u64],
        _max: u64,
        out: &mut [u64],
    ) -> Result<(), KernelError> {
        self.evaluate(rlwe, db, rows, cols, query, out, false)
            .map(|_| ())
    }
}
impl CudaKernel {
    /// Evaluate and return synchronized device kernel time in milliseconds.
    /// Host wall time additionally includes transfers, lock waiting, and event overhead.
    #[allow(clippy::too_many_arguments)]
    pub fn multiply_query_timed(
        &self,
        rlwe: &RlweParams,
        db: &[u16],
        rows: usize,
        cols: usize,
        query: &[u64],
        out: &mut [u64],
    ) -> Result<f32, KernelError> {
        self.evaluate(rlwe, db, rows, cols, query, out, true)
    }
    #[allow(clippy::too_many_arguments)]
    fn evaluate(
        &self,
        rlwe: &RlweParams,
        db: &[u16],
        rows: usize,
        cols: usize,
        query: &[u64],
        out: &mut [u64],
        timed: bool,
    ) -> Result<f32, KernelError> {
        if rlwe.q == 0
            || rows.checked_mul(cols) != Some(db.len())
            || query.len() != rows
            || out.len() != cols
        {
            return Err(error("invalid modulus or matrix/vector shape"));
        }
        let mut guard = self
            .prepared
            .lock()
            .map_err(|_| error("state lock poisoned"))?;
        let s = guard
            .as_mut()
            .ok_or_else(|| error("database is not prepared"))?;
        if (s.rows, s.cols) != (rows, cols) {
            return Err(error("prepared database shape mismatch"));
        }
        if rows == 0 || cols == 0 {
            out.fill(0);
            return Ok(0.0);
        }
        // CUDA current contexts are thread-local, including on HTTP/Rayon workers.
        self.stream.context().bind_to_thread().map_err(error)?;
        self.stream
            .memcpy_htod(query, &mut s.query)
            .map_err(error)?;
        let start = if timed {
            Some(self.stream.record_event(None).map_err(error)?)
        } else {
            None
        };
        let (r, c, t) = (rows as u64, cols as u64, s.tiles as u64);
        let mut args = self.stream.launch_builder(&self.tile);
        args.arg(&s.db)
            .arg(&s.query)
            .arg(&mut s.partial)
            .arg(&r)
            .arg(&t)
            .arg(&rlwe.q);
        // SAFETY: validated shapes and grid; mutex retains allocations through
        // synchronization. Each kernel bounds every access to these buffers.
        unsafe {
            args.launch(LaunchConfig {
                grid_dim: ((cols * s.tiles) as u32, 1, 1),
                block_dim: (256, 1, 1),
                shared_mem_bytes: 0,
            })
        }
        .map_err(error)?;
        let mut args = self.stream.launch_builder(&self.reduce);
        args.arg(&s.partial)
            .arg(&mut s.out)
            .arg(&c)
            .arg(&t)
            .arg(&rlwe.q);
        // SAFETY: same allocations and bounds; reduce_tiles checks column count.
        unsafe {
            args.launch(LaunchConfig {
                grid_dim: (cols.div_ceil(256) as u32, 1, 1),
                block_dim: (256, 1, 1),
                shared_mem_bytes: 0,
            })
        }
        .map_err(error)?;
        let end = if timed {
            Some(self.stream.record_event(None).map_err(error)?)
        } else {
            None
        };
        self.stream.memcpy_dtoh(&s.out, out).map_err(error)?;
        self.stream.synchronize().map_err(error)?;
        match (start, end) {
            (Some(a), Some(b)) => a.elapsed_ms(&b).map_err(error),
            _ => Ok(0.0),
        }
    }
}
