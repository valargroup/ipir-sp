"""Project packing and database memory of p = 2^8 profiles onto wallet-pir hosts.

ESTIMATES. Per-block packing bytes come from the measured runs in aggregate.json
(coefficient bytes / blocks); the database is rows x padded row bytes in the
chosen storage width. Context tables, allocator overhead and request transients
are not included. Host budgets and table counts are cited in
wallet-inventory.json; unconfirmed counts are reported per table.
"""
import json
import math
from pathlib import Path

root = Path(__file__).resolve().parent
D = 2048
inventory = json.loads((root / 'wallet-inventory.json').read_text())
agg = json.loads((root / 'aggregate.json').read_text()) if (root / 'aggregate.json').exists() else {'runs': {}}


def per_block(run, default):
    r = agg['runs'].get(run)
    if not r:
        return default, 'analytic'
    blocks = r['setup']['cols'] // D
    return r['setup']['coeff_bytes'] / blocks, run


# Analytic fallbacks (two masks retained per block, no leftover in two-mask mode):
# packed27 two-digit = d*2d*27/8 + 8 + 2*d*8; i32 two-digit = i64 one-digit = d*2d*4 + 2*d*8.
PACKED27_2 = D * 2 * D * 27 // 8 + 8 + 2 * D * 8
WIDE = D * 2 * D * 4 + 2 * D * 8
variants = {
    'p16 two-digit (today)': dict(p_bits=16, entry=2, mask=29, block=per_block('raw-xeon/b49', PACKED27_2)),
    'p8 two-digit, u8 DB': dict(p_bits=8, entry=1, mask=22, block=per_block('raw-xeon/p2', PACKED27_2)),
    'p8 two-digit, u16 DB': dict(p_bits=8, entry=2, mask=22, block=per_block('raw-xeon/p2w', PACKED27_2)),
    'p8 one-digit, u8 DB': dict(p_bits=8, entry=1, mask=22, block=per_block('raw-xeon/p1', WIDE)),
}


def table_bytes(t, v):
    width = D * v['p_bits'] // 8  # plaintext bytes per block per row
    blocks = math.ceil(t['row_bytes'] / width)
    packing = blocks * v['block'][0]
    database = t['rows'] * blocks * D * v['entry']
    published = 36 + blocks * 2 * D * v['mask'] // 8
    return blocks, packing, database, published


def main():
    hosts = {}
    rows = ['| Table | Variant | Blocks | Packing MB | Database MB | Published KB | Count |', '|' + '---|' * 7]
    for t in inventory['tables']:
        count = t['count'] or 1
        for name, v in variants.items():
            blocks, packing, database, published = table_bytes(t, v)
            rows.append(f"| {t['name']} | {name} | {blocks} | {packing / 1e6:.1f} | {database / 1e6:.1f} | "
                        f"{published / 1e3:.1f} | {t['count'] if t['count'] else 'per domain'} |")
            hosts.setdefault(t['host'], {}).setdefault(name, 0)
            hosts[t['host']][name] += count * (packing + database)
    rows += ['', '| Host | Variant | Packing + DB GB | Change vs today GB | Budget note |', '|---|---|---|---|---|']
    for host, totals in hosts.items():
        today = totals['p16 two-digit (today)']
        for name, total in totals.items():
            rows.append(f"| {host} | {name} | {total / 1e9:.2f} | {(total - today) / 1e9:+.2f} | "
                        f"{inventory['hosts'][host]['note']} |")
    rows += ['', 'Per-block packing sources: ' + ', '.join(f"{n}: {v['block'][1]} ({v['block'][0] / 1e6:.1f} MB)"
                                                          for n, v in variants.items())]
    text = '\n'.join(rows) + '\n'
    (root / 'wallet-projection.md').write_text(text)
    print(text)


if __name__ == '__main__':
    main()
