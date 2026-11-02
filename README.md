# Kyber TRNG Entropy Injection

**Author:** Usama Mustafa
**Domain:** Post-quantum cryptography · Hardware security · Entropy engineering
**Stack:** Python · kyber-py (ML-KEM) · Arduino C++ · SAM3X8E

Hardware-entropy-injected ML-KEM (Kyber). Replaces the deterministic
`AES-CTR_DRBG` / `os.urandom` source inside `kyber-py` with bytes from a
ring-oscillator True Random Number Generator on a SAM3X8E (Arduino Due),
backed by NIST SP 800-90B continuous health tests in firmware AND on the host,
plus a hybrid TRNG ⊕ HMAC-DRBG defense-in-depth mode.

---

## Why this exists

The Kyber implementations I surveyed depend on a deterministic random number
source — `os.urandom`, AES-CTR_DRBG, BoringSSL's `RAND_bytes`,
etc. These sources are all functions of a single seed at startup. Recover the
seed and you recover every key the device will ever generate.

That seed has historically failed in spectacular ways:

- **Debian OpenSSL 2008 (CVE-2008-0166)** — entropy reduced to 32k possible
  seeds for two years
- **Boot-time low entropy on embedded systems** imaged from a master
- **VM clone / live-migration entropy collision**
- **Side-channel state recovery against AES-CTR_DRBG** (well-documented)

Kyber's security model assumes the seeds `d`, `z`, `m` are uniformly random
and unknown to the attacker. A single recovered seed is enough — the attacker
does not need to break the lattice problem at all.

This project adds physical entropy, so a recovered software seed is no longer enough.

## What's here

```
.
├── firmware/
│   └── trng_sam3x8e.ino          Dual-source TRNG firmware (on-chip TRNG ⊕ ring-jitter)
│                                  with SP 800-90B health tests (RCT + APT)
│                                  and CRC-8-framed serial output.
│
├── python/kyber_trng/
│   ├── source.py                 Serial / simulated entropy sources
│   ├── health.py                 SP 800-90B health monitor (host side)
│   ├── hybrid.py                 Hybrid TRNG ⊕ HMAC-DRBG (improvement over baseline)
│   ├── kyber_shim.py             os.urandom interception → kyber-py wrapper
│   ├── validation.py             SP 800-22 statistical suite + ent / dieharder
│   └── benchmarks.py             Performance harness
│
├── audit/
│   └── kyber_py_entropy_audit.md Full entropy-flow audit of the kyber-py reference
│
├── tests/
│   └── test_*.py                 47 tests, including FIPS 203 known-answer replay
│
├── docs/
│   └── architecture.md           System diagram, trust model, threat model
│
├── benchmarks/                   (results dropped here by `python -m kyber_trng.benchmarks`)
│
├── pyproject.toml
├── requirements.txt
├── LICENSE  (MIT)
└── README.md  (this file)
```

## Quick start

### Hardware path (recommended)

```bash
# 1. Flash firmware to Arduino Due (SAM3X8E)
arduino-cli compile --fqbn arduino:sam:arduino_due_x firmware/trng_sam3x8e.ino
arduino-cli upload --fqbn arduino:sam:arduino_due_x --port /dev/ttyACM0 firmware/

# 2. Install host package
pip install -e .

# 3. Use it
python - <<'EOF'
from kyber_trng import set_entropy_source, kyber, HybridDRBG, SerialTRNGSource

set_entropy_source(HybridDRBG(SerialTRNGSource("/dev/ttyACM0")))

ek, dk = kyber.l1024.keygen()
key_a, ct = kyber.l1024.encaps(ek)
assert kyber.l1024.decaps(dk, ct) == key_a
print("OK — hardware-rooted Kyber session established")
EOF
```

### Software-only path (CI / dev)

```bash
pip install -e .
python -c "
from kyber_trng import set_entropy_source, kyber, SimulatedTRNGSource
set_entropy_source(SimulatedTRNGSource())
ek, dk = kyber.l1024.keygen(); key_a, ct = kyber.l1024.encaps(ek)
assert kyber.l1024.decaps(dk, ct) == key_a
print('OK')
"
```

## Tests

```bash
pip install -e ".[dev]"
pytest
```

The suite replays the ML-KEM-1024 FIPS 203 known-answer vectors through the entropy hook.

## Statistical validation

```python
from kyber_trng.source import SerialTRNGSource
from kyber_trng.validation import StatisticalSuite

src = SerialTRNGSource("/dev/ttyACM0")
sample = src.read(1_048_576)             # 1 MiB
print(StatisticalSuite().run_all(sample))
```

Built-in tests (no external deps):
- NIST SP 800-22 monobit (frequency)
- Block frequency
- Runs
- Longest run of ones
- Cumulative sums
- Shannon entropy
- Chi-square uniformity

External tools auto-detected:
- `ent` (Fourmilab entropy)
- `dieharder` (extended Diehard battery)

For full coverage, run with NIST SP 800-22 `sts` and `TestU01` separately
against the captured byte stream.

## Design improvements

My earlier single-source design (replacing AES-CTR_DRBG with a single ring-oscillator
TRNG) trades one single point of failure for another: if the hardware TRNG
fails or is compromised, key generation halts or, worse, silently produces
weak keys. This implementation extends the design with:

1. **Hybrid TRNG ⊕ HMAC-DRBG mode (`HybridDRBG`)**
   Live TRNG output XOR'd with HMAC-SHA256-DRBG output reseeded from the
   TRNG. Both sources must be compromised simultaneously to compromise the
   stream.

2. **Continuous SP 800-90B health monitoring on host AND firmware**
   RCT + APT cutoffs derived for H_min = 0.5 bits/byte at α = 2⁻²⁰. Firmware
   refuses to emit further entropy on health-test failure (hard fail beacon
   `0xFF 0xFF`); host raises `TRNGSourceError` on detection.

3. **Dual-source XOR mixing in firmware**
   On-chip SAM3X8E TRNG peripheral XOR'd with software ring-jitter sampler
   (SysTick delta + side-effect FP arithmetic). Compromise of either source
   alone does not compromise the mix.

4. **Auditable entropy log**
   Every Kyber operation records the operation type and bytes consumed.
   Retrieve with `kyber_trng.audit_log`.

5. **Frame integrity (CRC-8)**
   Each TRNG byte carries a CRC; corrupted frames are dropped silently. No
   silent acceptance of garbage from a flaky USB cable.

## Running the statistical suites

| Validation suite | How to run |
|---|---|
| NIST SP 800-22r1a | Capture 1+ MiB to file, run `sts` separately |
| Diehard | `dieharder -a -g 201 -f trng_capture.bin` |
| Dieharder | same as above |
| ENT | `ent trng_capture.bin` |
| TestU01 | Use `bbattery_BigCrush` against the captured file |

A 64 MiB capture takes about 8 minutes from the SAM3X8E firmware at the
default ~16 KiB/s framed throughput.

## Citation

If this work informs your research:

```
Mustafa, U. (2026). Kyber TRNG Entropy Injection: Hardware-Rooted Randomness
for ML-KEM with Hybrid DRBG Defense in Depth and SP 800-90B Health Monitoring.
github.com/usamamustafa36/kyber-trng-entropy-injection
```

## License

MIT — see `LICENSE`. The `kyber-py` upstream library remains under its own
license (MIT). The official CRYSTALS-Kyber NIST submission package, if used
as a reference for KAT testing, remains under its original public-domain
release by the Kyber team.
