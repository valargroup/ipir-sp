// Exact unsigned arithmetic for every nonzero modulus, including q > 2^63.
__device__ unsigned long long add_mod(unsigned long long a, unsigned long long b,
                                      unsigned long long q) {
    return a >= q - b ? a - (q - b) : a + b;
}
extern "C" __global__ void tile_products(const unsigned short *db,
    const unsigned long long *query, unsigned long long *partial,
    unsigned long long rows, unsigned long long tiles, unsigned long long q) {
    __shared__ unsigned long long lo[256], hi[256];
    unsigned int t = threadIdx.x;
    unsigned long long tile = blockIdx.x % tiles, col = blockIdx.x / tiles;
    unsigned long long end = (tile + 1) * 4096;
    if (end > rows) end = rows;
    unsigned long long a = 0, b = 0;
    // At most 4096 * (2^32-1) * (2^16-1) per block: no u64 overflow.
    for (unsigned long long r = tile * 4096 + t; r < end; r += 256) {
        unsigned long long x = query[r], v = db[col * rows + r];
        a += v * (unsigned int)x;
        b += v * (x >> 32);
    }
    lo[t] = a; hi[t] = b;
    __syncthreads();
    for (unsigned int stride = 128; stride; stride >>= 1) {
        if (t < stride) { lo[t] += lo[t + stride]; hi[t] += hi[t + stride]; }
        __syncthreads();
    }
    if (t == 0) {
        a = lo[0] % q; b = hi[0] % q;
        for (unsigned int i = 0; i < 32; ++i) b = add_mod(b, b, q);
        partial[blockIdx.x] = add_mod(a, b, q);
    }
}
extern "C" __global__ void reduce_tiles(const unsigned long long *partial,
    unsigned long long *out, unsigned long long cols, unsigned long long tiles,
    unsigned long long q) {
    unsigned long long col = (unsigned long long)blockIdx.x * blockDim.x + threadIdx.x;
    if (col >= cols) return;
    unsigned long long value = 0;
    for (unsigned long long t = 0; t < tiles; ++t)
        value = add_mod(value, partial[col * tiles + t], q);
    out[col] = value;
}
