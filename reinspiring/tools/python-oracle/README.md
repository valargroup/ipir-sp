# `reinspiring-oracle`

Tiny-parameter Python reference for **Algorithm 2 (`ReinspiRING`)** from
ePrint 2026/1934. See [`../../SPEC.md`](../../SPEC.md).

```bash
cd reinspiring/tools/python-oracle
uv sync
uv run pytest -v
```

Presets: `ORACLE_TINY` (`d=8`, odd `q=12289`) and `ORACLE_EVEN_TINY`
(`d=8`, `q=2^16`) for the Appendix D.1 smoke path.
