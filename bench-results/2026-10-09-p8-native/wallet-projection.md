| Table | Variant | Blocks | Packing MB | Database MB | Published KB | Count |
|---|---|---|---|---|---|---|
| enhance-domain | p16 two-digit (today) | 6 | 170.1 | 805.3 | 89.1 | per domain |
| enhance-domain | p8 two-digit, u8 DB | 11 | 311.8 | 738.2 | 123.9 | per domain |
| enhance-domain | p8 two-digit, u16 DB | 11 | 311.8 | 1476.4 | 123.9 | per domain |
| enhance-domain | p8 one-digit, u8 DB | 11 | 369.5 | 738.2 | 123.9 | per domain |
| status | p16 two-digit (today) | 3 | 85.0 | 100.7 | 44.6 | 1 |
| status | p8 two-digit, u8 DB | 5 | 141.7 | 83.9 | 56.4 | 1 |
| status | p8 two-digit, u16 DB | 5 | 141.7 | 167.8 | 56.4 | 1 |
| status | p8 one-digit, u8 DB | 5 | 167.9 | 83.9 | 56.4 | 1 |
| transparent-archive-directory | p16 two-digit (today) | 1 | 28.3 | 134.2 | 14.9 | 82 |
| transparent-archive-directory | p8 two-digit, u8 DB | 2 | 56.7 | 134.2 | 22.6 | 82 |
| transparent-archive-directory | p8 two-digit, u16 DB | 2 | 56.7 | 268.4 | 22.6 | 82 |
| transparent-archive-directory | p8 one-digit, u8 DB | 2 | 67.2 | 134.2 | 22.6 | 82 |
| transparent-archive-pages | p16 two-digit (today) | 1 | 28.3 | 268.4 | 14.9 | 82 |
| transparent-archive-pages | p8 two-digit, u8 DB | 2 | 56.7 | 268.4 | 22.6 | 82 |
| transparent-archive-pages | p8 two-digit, u16 DB | 2 | 56.7 | 536.9 | 22.6 | 82 |
| transparent-archive-pages | p8 one-digit, u8 DB | 2 | 67.2 | 268.4 | 22.6 | 82 |
| transparent-recent-directory | p16 two-digit (today) | 1 | 28.3 | 16.8 | 14.9 | 9 |
| transparent-recent-directory | p8 two-digit, u8 DB | 2 | 56.7 | 16.8 | 22.6 | 9 |
| transparent-recent-directory | p8 two-digit, u16 DB | 2 | 56.7 | 33.6 | 22.6 | 9 |
| transparent-recent-directory | p8 one-digit, u8 DB | 2 | 67.2 | 16.8 | 22.6 | 9 |
| transparent-recent-pages | p16 two-digit (today) | 1 | 28.3 | 33.6 | 14.9 | 9 |
| transparent-recent-pages | p8 two-digit, u8 DB | 2 | 56.7 | 33.6 | 22.6 | 9 |
| transparent-recent-pages | p8 two-digit, u16 DB | 2 | 56.7 | 67.1 | 22.6 | 9 |
| transparent-recent-pages | p8 one-digit, u8 DB | 2 | 67.2 | 33.6 | 22.6 | 9 |
| txid-display | p16 two-digit (today) | 1 | 28.3 | 8.4 | 14.9 | 426 |
| txid-display | p8 two-digit, u8 DB | 2 | 56.7 | 8.4 | 22.6 | 426 |
| txid-display | p8 two-digit, u16 DB | 2 | 56.7 | 16.8 | 22.6 | 426 |
| txid-display | p8 one-digit, u8 DB | 2 | 67.2 | 8.4 | 22.6 | 426 |

| Host | Variant | Packing + DB GB | Change vs today GB | Budget note |
|---|---|---|---|---|
| enhance-router | p16 two-digit (today) | 0.98 | +0.00 | 4 vCPU Xeon Platinum 8168; memory gate failing (enhance/docs/qualification.md) |
| enhance-router | p8 two-digit, u8 DB | 1.05 | +0.07 | 4 vCPU Xeon Platinum 8168; memory gate failing (enhance/docs/qualification.md) |
| enhance-router | p8 two-digit, u16 DB | 1.79 | +0.81 | 4 vCPU Xeon Platinum 8168; memory gate failing (enhance/docs/qualification.md) |
| enhance-router | p8 one-digit, u8 DB | 1.11 | +0.13 | 4 vCPU Xeon Platinum 8168; memory gate failing (enhance/docs/qualification.md) |
| status-p4000 | p16 two-digit (today) | 0.19 | +0.00 | dedicated P4000 GPU host; router CPU + CUDA worker (enhance/docs/architecture_status.md) |
| status-p4000 | p8 two-digit, u8 DB | 0.23 | +0.04 | dedicated P4000 GPU host; router CPU + CUDA worker (enhance/docs/architecture_status.md) |
| status-p4000 | p8 two-digit, u16 DB | 0.31 | +0.12 | dedicated P4000 GPU host; router CPU + CUDA worker (enhance/docs/architecture_status.md) |
| status-p4000 | p8 one-digit, u8 DB | 0.25 | +0.07 | dedicated P4000 GPU host; router CPU + CUDA worker (enhance/docs/architecture_status.md) |
| transparent-archive | p16 two-digit (today) | 37.67 | +0.00 | m-8vcpu-64gb, 48 GiB RAM cache, 56 GiB MemoryMax |
| transparent-archive | p8 two-digit, u8 DB | 42.31 | +4.65 | m-8vcpu-64gb, 48 GiB RAM cache, 56 GiB MemoryMax |
| transparent-archive | p8 two-digit, u16 DB | 75.33 | +37.67 | m-8vcpu-64gb, 48 GiB RAM cache, 56 GiB MemoryMax |
| transparent-archive | p8 one-digit, u8 DB | 44.03 | +6.37 | m-8vcpu-64gb, 48 GiB RAM cache, 56 GiB MemoryMax |
| transparent-recent | p16 two-digit (today) | 0.96 | +0.00 | s-4vcpu-8gb, 5 GiB RAM cache, 176.1 MiB reserved per shard (transparent/docs/status.md:31-36) |
| transparent-recent | p8 two-digit, u8 DB | 1.47 | +0.51 | s-4vcpu-8gb, 5 GiB RAM cache, 176.1 MiB reserved per shard (transparent/docs/status.md:31-36) |
| transparent-recent | p8 two-digit, u16 DB | 1.93 | +0.96 | s-4vcpu-8gb, 5 GiB RAM cache, 176.1 MiB reserved per shard (transparent/docs/status.md:31-36) |
| transparent-recent | p8 one-digit, u8 DB | 1.66 | +0.70 | s-4vcpu-8gb, 5 GiB RAM cache, 176.1 MiB reserved per shard (transparent/docs/status.md:31-36) |
| txid-display | p16 two-digit (today) | 15.65 | +0.00 | m-8vcpu-64gb, 24 GiB cache, 72.05 MiB reserved and 40.05 MiB built per runtime (transparent/docs/deployment.md:3268-3271) |
| txid-display | p8 two-digit, u8 DB | 27.72 | +12.07 | m-8vcpu-64gb, 24 GiB cache, 72.05 MiB reserved and 40.05 MiB built per runtime (transparent/docs/deployment.md:3268-3271) |
| txid-display | p8 two-digit, u16 DB | 31.30 | +15.65 | m-8vcpu-64gb, 24 GiB cache, 72.05 MiB reserved and 40.05 MiB built per runtime (transparent/docs/deployment.md:3268-3271) |
| txid-display | p8 one-digit, u8 DB | 32.19 | +16.54 | m-8vcpu-64gb, 24 GiB cache, 72.05 MiB reserved and 40.05 MiB built per runtime (transparent/docs/deployment.md:3268-3271) |

Per-block packing sources: p16 two-digit (today): raw-xeon/b49 (28.3 MB), p8 two-digit, u8 DB: raw-xeon/p2 (28.3 MB), p8 two-digit, u16 DB: raw-xeon/p2w (28.3 MB), p8 one-digit, u8 DB: raw-xeon/p1 (33.6 MB)
