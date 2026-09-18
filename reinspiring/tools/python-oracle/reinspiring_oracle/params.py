"""Parameter presets for the ReinspiRING oracle."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ReinspiringParams:
    """Cyclotomic parameters for Compile + Pack at tiny sizes."""

    d: int
    q: int
    p: int
    z: int
    ell: int
    """Gadget base and length; used only to size limb stacks in tests."""

    def __post_init__(self) -> None:
        if self.d <= 0 or (self.d & (self.d - 1)) != 0:
            raise ValueError(f"d must be a positive power of 2, got {self.d}")
        if self.q <= 1:
            raise ValueError(f"q must be > 1, got {self.q}")
        if self.p <= 1:
            raise ValueError(f"p must be > 1, got {self.p}")
        if self.z <= 1:
            raise ValueError(f"z must be > 1, got {self.z}")
        if self.ell <= 0:
            raise ValueError(f"ell must be positive, got {self.ell}")
        if self.z**self.ell < self.q and self.q % 2 == 1:
            raise ValueError(f"gadget too short: z**ell < q")

    @property
    def is_odd_q(self) -> bool:
        return self.q % 2 == 1

    @property
    def delta(self) -> int:
        return self.q // self.p


# Matches inspiring ORACLE_TINY — byte-equal path.
ORACLE_TINY = ReinspiringParams(d=8, q=12289, p=4, z=8, ell=5)

# Power-of-two modulus for Appendix D.1 smoke (Compile itself is modulus-agnostic).
ORACLE_EVEN_TINY = ReinspiringParams(d=8, q=1 << 16, p=4, z=1 << 4, ell=4)
