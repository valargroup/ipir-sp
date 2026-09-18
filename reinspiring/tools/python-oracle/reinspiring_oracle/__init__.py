"""ReinspiRING reference oracle (eprint 2026/1934, Algorithm 2)."""

from reinspiring_oracle.compile import compile_naive, negacyclic_matrix, signed_perm_apply
from reinspiring_oracle.pack import pack, preprocess
from reinspiring_oracle.params import ORACLE_EVEN_TINY, ORACLE_TINY, ReinspiringParams

__all__ = [
    "ORACLE_EVEN_TINY",
    "ORACLE_TINY",
    "ReinspiringParams",
    "compile_naive",
    "negacyclic_matrix",
    "pack",
    "preprocess",
    "signed_perm_apply",
]
