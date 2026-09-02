# Nullifier Fixture Notes

The full snapshot downloaded from:

```text
https://vote.fra1.cdn.digitaloceanspaces.com/snapshots/3317500/nullifiers.bin
```

Local files used for the end-to-end check:

- Full snapshot: `data/nullifiers.bin`
- 100 MiB fixture: `data/nullifiers-small-100mb.bin`

The 100 MiB fixture is the first `104,857,600` bytes of the full snapshot, so
every fixture nullifier also exists in the full set.

Known existing nullifier:

```text
b3cdb97715d5e3dd624fc87906b9d13b4e4ec6a63989d989936f2504f0a1f706
```

It is record `0` in both files, which maps to PIR row `0`, offset `0`.

Known existing nullifier from the middle of the 100 MiB fixture:

```text
4b4f13ad02a04d16e6efa83730751f53eead7dbf019e1632d937b8c8631d393e
```

It is record `1,638,400` in both files, byte offset `52,428,800` in the
snapshot prefix. At `1,792` nullifiers per PIR row it maps to PIR row `914`,
offset `512`.

The mapping moves whenever `SIMPLEPIR_INSTANCES_PER_ITEM` changes, since it is
just `record / nullifiers_per_row` and `record % nullifiers_per_row`. Earlier
packings put this record at row `14,628` offset `64` (112 per row) and row
`3,657` offset `64` (448 per row).

Known absent nullifier checked against both the 100 MiB fixture and the full
snapshot:

```text
0000000000000000000000000000000000000000000000000000000000000000
```
