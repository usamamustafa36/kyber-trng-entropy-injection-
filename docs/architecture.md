# Architecture

## System diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│  HOST (Linux / macOS / Windows)                                      │
│                                                                      │
│  ┌───────────────────────────────────────────────────────────────┐ │
│  │  kyber_trng Python package                                    │ │
│  │                                                               │ │
│  │   kyber_shim   ──patches──▶  os.urandom  ──reads──▶  source  │ │
│  │      │                                                ▲       │ │
│  │      │                                                │       │ │
│  │      ▼                                                │       │ │
│  │  kyber-py (upstream ML-KEM)                          │       │ │
│  │      │                                                │       │ │
│  │      └──────────────────── KEM operations ───────────┘       │ │
│  │                                                               │ │
│  │  source ::= SerialTRNGSource                                  │ │
│  │           |  HybridDRBG(SerialTRNGSource)   ← recommended    │ │
│  │           |  SimulatedTRNGSource            ← dev / CI only  │ │
│  │                                                               │ │
│  │  health   :: HealthMonitor (RCT + APT, SP 800-90B)           │ │
│  │  validate :: StatisticalSuite (SP 800-22 subset + ent)       │ │
│  │  audit    :: per-call byte-source log                         │ │
│  └─────────────────────────────────────┬─────────────────────────┘ │
│                                        │ USB CDC @ 115200 baud      │
└────────────────────────────────────────┼────────────────────────────┘
                                         │
                                  ╔══════▼═══════╗
                                  ║  SAM3X8E      ║
                                  ║  (Arduino Due) ║
                                  ╚══════════════╝
                                         │
   ┌─────────────────────────────────────┴─────────────────────────────────┐
   │  Firmware (firmware/trng_sam3x8e.ino)                                  │
   │                                                                        │
   │  ┌─────────────────────┐    ┌─────────────────────┐                  │
   │  │ on-chip TRNG        │    │ ring-jitter sampler │                  │
   │  │ (ring-oscillator    │    │ (SysTick deltas +   │                  │
   │  │  based per Atmel    │    │  side-effect FP ops)│                  │
   │  │  SAM3X datasheet)   │    │                     │                  │
   │  └──────────┬──────────┘    └──────────┬──────────┘                  │
   │             │                          │                               │
   │             └──────── XOR mix ────────┘                               │
   │                          │                                            │
   │                          ▼                                            │
   │             SP 800-90B health tests (RCT + APT)                      │
   │                          │                                            │
   │                          ▼                                            │
   │             Frame  [0xAA 0x55] <byte> <crc8>                          │
   │                          │                                            │
   │                          ▼                                            │
   │                    USB CDC out                                        │
   └────────────────────────────────────────────────────────────────────────┘
```

## Trust model

The host trusts:
- The USB connection to the SAM3X8E (no in-line attacker)
- The firmware's claim of dual-source XOR mixing
- The CRC-8 frame integrity check

The host does NOT trust:
- Any single entropy source — hence the dual-source XOR in firmware AND the
  optional `HybridDRBG` on the host (DRBG seeded from TRNG)
- The on-chip TRNG without independent health tests — RCT/APT run on both
  sides

## Data flow per Kyber operation

| Step | Bytes | Source | Notes |
|---|---|---|---|
| `KeyGen` `d` | 32 | TRNG → host buffer | feeds CBD sampling for s, e |
| `KeyGen` `z` | 32 | TRNG → host buffer | implicit-rejection seed |
| `Encaps` `m` | 32 | TRNG → host buffer | hashes with H(pk) → K, r |
| `Decaps` | 0 | — | deterministic |

Total per ephemeral session: ~96 bytes of TRNG entropy.

## Threat model

In scope:
- Compromise of the host's `os.urandom` source (kernel pool low entropy,
  VM-clone state collision, Debian-style bug)
- Compromise of any single entropy generator (HW TRNG fails closed; SW DRBG
  keeps going)
- Live recovery of a Kyber session via `m` recovery
- Power/EM side channels against AES-CTR_DRBG (avoided by removing it)

Out of scope:
- Compromise of the SAM3X8E firmware update path (assume firmware is signed
  and burned at provisioning)
- Physical extraction of in-flight `d`, `z`, `m` from host RAM (general OS
  hardening problem, not specific to entropy)
- Lattice attacks against Kyber itself (out of scope by definition — the
  whole point of switching to PQC)

## What this design does NOT replace

- The kyber-py implementation itself — we wrap, not reimplement.
- NIST KAT compliance — by construction, hardware entropy means KATs no
  longer match. A KAT-mode override is included for compliance testing only.
