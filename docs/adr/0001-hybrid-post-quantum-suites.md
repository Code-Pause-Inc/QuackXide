# 0001. Hybrid post-quantum cryptographic suites

* Status: Accepted
* Date: 2026-09-30

## Context

QuackXide stores sensitive data as ciphertext for long periods. Ciphertext
captured today can be decrypted later by an adversary with a large quantum
computer ("harvest now, decrypt later"). The current suites are classical:
X25519 key encapsulation for HPKE envelopes and enrollment keys, and RS256
(HS256 in development) for token signatures.

Post-quantum algorithms are standardized (FIPS 203 ML-KEM, FIPS 204
ML-DSA) but younger than the classical algorithms, so relying on them alone
trades one risk for another.

## Decision

Adopt hybrid suites, combining a classical and a post-quantum algorithm so
that breaking the result requires breaking both:

* Key encapsulation: X25519 + ML-KEM-768.
* Signatures: Ed25519 + ML-DSA-65.
* Bulk encryption: AES-256-GCM (unchanged).

Implementations come from established libraries only. The suites change at
the existing seams (`TenantKem`, the `JwtVerifier` construction site, the
browser crypto core) with a new frame version alongside `HPK1`. A reader
configured for the hybrid suite refuses classical-only envelopes and
signatures unless an explicit, logged migration mode is enabled.

## Consequences

* Envelopes and signatures grow (ML-KEM-768 ciphertexts are about 1 KB;
  ML-DSA-65 signatures about 3.3 KB). Benchmarks must track the cost.
* Browser support for ML-KEM and ML-DSA in Web Crypto is incomplete; the
  browser path may need a vetted WebAssembly implementation behind the
  existing crypto-core seam, which must keep private keys non-extractable
  or document where it cannot.
* Existing classical ciphertext needs a migration path: re-seal under the
  new frame version, with the migration mode audited and time-limited.
* Tokens change format; the RS256 verifier remains only as long as
  migration requires.
