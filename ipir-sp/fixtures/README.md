# Packing vectors

These are deterministic arithmetic regression fixtures, not production key
material or security-approved parameter profiles.

The degree-16, 56-bit fixture was regenerated against main `611a292` during the
ReinspiRING refresh. Main's exact signed top-digit decomposition changes the
public collapse trace and hence both ciphertext rows; the former PR #17 vector
was stale. The tiny fixture did not change. Both backend outputs are compared
against the committed rows and against one another.

The native profile additionally has an independent Python integer/schoolbook
oracle invoked by `reinspiring` unit tests. It does not reuse the Rust FFT,
CRT reconstruction, or compiled matrix path.
