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
crate packs `448` nullifiers into one SimplePIR item, i.e. four RLWE output
blocks (`instances`) per row:

```text
448 nullifiers * 32 bytes * 8 bits = 114,688 bits
8192 coefficients * 14 bits        = 114,688 bits
```

The full snapshot therefore maps to `111,442` logical PIR items and pads to
`112,640` SimplePIR rows (a whole number of `poly_len = 2048` blocks, not a
power of two).

### Why four instances

Upload scales with the row count and download with the column count, while
their product is fixed by the dataset. One instance per row left the database at
`524,288 x 2,048` — a 256:1 skew that put 3.5 MB of first-dimension query on the
wire against a 12 KB response. Four instances rebalance it:

| | 1 instance | 4 instances |
|---|---:|---:|
| rows x cols | 524,288 x 2,048 | 112,640 x 8,192 |
| upload | 3,768,320 B | 886,784 B |
| download | 12,288 B | 49,152 B |
| **total wire** | **3,780,608 B** | **935,936 B** |

The matrix-vector work is unchanged (slightly lower, since dropping the
power-of-two row padding removes 15% of the database), and `pack_intermediate_blocks`
now has four blocks to spread across cores instead of one. The cost is four
InspiRING preprocessing blocks instead of one.

## Resource Notes

The local `ipir-sp` path stores the SimplePIR database in memory after encoding.
For the full snapshot this is roughly `112,640 * 8192 * sizeof(u16)`, about
1.8 GiB before preprocessing and Actix overhead. Preprocessing also allocates
InspiRING packing caches, so use a large-memory host for the full snapshot.
