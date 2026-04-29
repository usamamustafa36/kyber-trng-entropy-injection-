# Audit: Entropy Dependencies in `kyber-py` Reference Implementation

This audit traces every place randomness enters ML-KEM (Kyber) operations in
the [`kyber-py`](https://github.com/GiacomoPope/kyber-py) reference and
identifies the deterministic single point of failure that motivates this
project.

## Scope

ML-KEM as standardised in **NIST FIPS 203** (August 2024). Two algorithm
variants in scope:

- `kyber-py`'s pure-Python reference (calls `os.urandom`)
- The original NIST submission package's `Reference_Implementation` (calls
  AES-CTR_DRBG seeded by `randombytes_init`)

## Where randomness is consumed

### Key generation `KeyGen()`

| Symbol | Size | Purpose | Source |
|---|---|---|---|
| `d` | 32 B | seed for `K_PKE.KeyGen` (matrix A, secret s, error e) | `os.urandom(32)` |
| `z` | 32 B | implicit-rejection seed bound into `dk` | `os.urandom(32)` |

`d` derives ALL of:
- The expansion of matrix `A ∈ R_q^{k×k}` via SHAKE-128 with seed `ρ`
- The secret `s ∈ R_q^k` via centred-binomial sampling with PRF seed `σ`
- The error `e ∈ R_q^k` via centred-binomial sampling with PRF seed `σ`

If `d` is recovered, the entire keypair is recoverable. `d` ⊥ `z` security
analysis: leakage of either reveals everything bound to it.

### Encapsulation `Encaps(pk)`

| Symbol | Size | Purpose | Source |
|---|---|---|---|
| `m` | 32 B | random message → hashed with `pk` to derive shared secret + coins | `os.urandom(32)` |

`m` is the only entropy consumed by encapsulation. It is used twice:

1. `(K, r) = G(m || H(pk))` — derives shared secret `K` and encryption
   randomness `r`
2. `r` seeds the `K_PKE.Enc` operation (matrix-vector products + error)

If `m` is recovered, `K` is recoverable, breaking the session.

### Decapsulation `Decaps(c, dk)`

No fresh entropy consumed. Decapsulation re-encrypts and constant-time-compares.

## The deterministic single point of failure

Both `os.urandom` (Linux: `getrandom(2)`) and AES-CTR_DRBG (NIST submission
default) are **deterministic** functions of their seed:

- `os.urandom` ← Linux kernel CSPRNG, seeded from `/dev/urandom`'s pool
- AES-CTR_DRBG ← `randombytes_init(seed, personalisation, security_level)`

Both have well-documented failure modes:

1. **Boot-time low entropy** — embedded systems often reseed `/dev/urandom`
   from a small pool collected before any user activity. Devices that are
   imaged from a master have been observed with predictable initial entropy.
2. **Virtualisation / cloning** — VM snapshots and live-migration copy the
   DRBG state. After clone, both children produce identical "random" output
   until reseeded.
3. **Side-channel state recovery** — power, EM, and timing attacks against
   AES-CTR_DRBG are documented in the literature.
4. **Implementation bugs** — Debian OpenSSL 2008 (CVE-2008-0166) reduced PID
   to 32k possible seeds. ANY single bug in any layer of the entropy stack
   compromises every key produced for the lifetime of the device.

For Kyber specifically: a single `d`, `z`, or `m` recovery is sufficient. The
attacker does not need to break the lattice problem.

## Where entropy is mixed in vs. directly used

| Location | Mixed? | Notes |
|---|---|---|
| `d` → `(ρ, σ) = G(d ‖ k)` | hashed once via SHA3-512 | hash does not add entropy |
| `σ` → PRF-256 expansion to many CBD samples | one-way expansion | does not add entropy |
| `m` → `(K, r) = G(m ‖ H(pk))` | hashed once via SHA3-512 | does not add entropy |
| AES-CTR_DRBG output → `d`, `z`, `m` | counter-mode block expansion | does not add entropy |

**There is no entropy mixing along the chain. The bits at the output are
exactly as good as the bits at the seed.** This is by design — Kyber is
a deterministic function of its inputs.

## Mitigation strategy implemented in this repo

1. Replace `os.urandom` with a hardware ring-oscillator TRNG (firmware:
   `firmware/trng_sam3x8e.ino`).
2. Subject TRNG output to NIST SP 800-90B continuous health tests (RCT + APT)
   in firmware AND on the host.
3. **Improvement over the baseline thesis:** offer a hybrid mode (`HybridDRBG`)
   that XORs TRNG output with a HMAC-DRBG reseeded from the TRNG. Defense in
   depth: even if the hardware fails or is compromised, the DRBG path
   maintains cryptographic strength as long as the seed at boot was sound.
4. Validate the entropy stream with NIST SP 800-22 monobit, block frequency,
   runs, longest-run, and cumulative-sums tests in pure Python. Shell out to
   `ent` and `dieharder` when available for deeper validation.
5. Maintain an audit log of every byte source consumed by every Kyber
   operation, attributable per-call.

## Test vectors referenced

- NIST FIPS 203 Appendix A (intermediate values for ML-KEM-768/1024)
- `kyber-py` test suite (KAT vectors lifted from the NIST submission)

After TRNG injection, KAT replay is **not expected to match** — the inputs
are now hardware-derived and not deterministic. Replay testing requires a
KAT-mode override that disables the TRNG and seeds AES-CTR_DRBG from the KAT
seed file. This mode is included in the shim but flagged for testing only.
