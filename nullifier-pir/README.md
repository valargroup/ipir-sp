# nullifier-pir

`nullifier-pir` serves PIR queries over fixed-width 32-byte nullifier snapshots.
The default snapshot shape is the 3317500 file:

```bash
cargo run -p nullifier-pir -- download \
  --url https://vote.fra1.cdn.digitaloceanspaces.com/snapshots/3317500/nullifiers.bin \
  --output data/nullifiers.bin
```

Start the local `ipir-sp` backend:

```bash
cargo run --release -p nullifier-pir -- serve \
  --snapshot-path data/nullifiers.bin \
  --backend local-ipir \
  --host 127.0.0.1 \
  --port 8080
```

The server exposes:

- `GET /health`
- `GET /meta`
- `POST /query` with backend-native query bytes

To compile the YPIR SimplePIR artifact backend pinned at commit `4f7ef3d`:

```bash
cargo check -p nullifier-pir --features ypir-artifact
```

## Packing Shape

The snapshot length is `1,597,627,296` bytes, or `49,925,853` nullifiers. The
crate packs `1,792` nullifiers into one SimplePIR item, i.e. sixteen RLWE output
blocks (`instances`) per row:

```text
1792 nullifiers * 32 bytes * 8 bits = 458,752 bits
32768 coefficients * 14 bits        = 458,752 bits
```

The full snapshot therefore maps to `27,861` logical PIR items and pads to
`28,672` SimplePIR rows (a whole number of `poly_len = 2048` blocks, not a power
of two).

### Why sixteen instances

Upload scales with the row count and download with the column count, while
their product is fixed by the dataset. One instance per row left the database at
`524,288 x 2,048` — a 256:1 skew that put 3.5 MB of first-dimension query on the
wire against a 12 KB response.

Four instances were as far as this could go while online packing and offline
preprocessing each cost a fixed amount per output block. Once the fused collapse
and the NTT-domain aggregate cut those per-block costs, the balance moved. With
a 42-bit query coefficient per row up and 20 bits per column down, total wire is
minimized near 21 instances, but the curve is flat from 16 to 28 while packing
work, offline work and the resident `digits_ntt` cache all grow linearly in the
block count. Sixteen sits at the near-flat end:

| | 1 instance | 4 instances | 16 instances |
|---|---:|---:|---:|
| rows x cols | 524,288 x 2,048 | 112,640 x 8,192 | 28,672 x 32,768 |
| upload | 3,768,320 B | 886,784 B | 236,544 B |
| download | 12,288 B | 49,152 B | 81,920 B |
| **total wire** | **3,780,608 B** | **935,936 B** | **318,464 B** |

The matrix-vector work is essentially unchanged — the product of the dimensions
is fixed — and at `28,672` rows a whole column now fits inside one
delayed-reduction window, so the kernel sweeps the database in a single pass.
The cost is sixteen InspiRING preprocessing blocks instead of four.

## Resource Notes

The local `ipir-sp` path stores the SimplePIR database in memory after encoding.
For the full snapshot this is roughly `28,672 * 32,768 * sizeof(u16)`, about
1.8 GiB before preprocessing and Actix overhead. The sixteen `digits_ntt`
caches add roughly 1.5 GiB on top. Preprocessing also allocates
InspiRING packing caches, so use a large-memory host for the full snapshot.
