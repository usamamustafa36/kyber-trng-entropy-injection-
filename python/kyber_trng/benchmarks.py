"""
Performance comparison: stock kyber-py (os.urandom) vs TRNG-injected variants.

Measures:
  * Key generation latency
  * Encapsulation latency
  * Decapsulation latency (sanity — entropy-independent)
  * Effective throughput of the entropy source

Run:
    python -m kyber_trng.benchmarks
"""

from __future__ import annotations

import argparse
import statistics
import time
from contextlib import contextmanager
from typing import Callable, List, Tuple

from .source import SimulatedTRNGSource, TRNGSource
from .hybrid import HybridDRBG
from .kyber_shim import set_entropy_source, keygen, encaps, decaps


@contextmanager
def timer():
    t = [time.perf_counter()]
    yield t
    t.append(time.perf_counter())


def time_call(fn: Callable, runs: int) -> Tuple[float, float, float]:
    samples: List[float] = []
    for _ in range(runs):
        t0 = time.perf_counter()
        fn()
        samples.append(time.perf_counter() - t0)
    return (statistics.mean(samples) * 1e3,
            statistics.median(samples) * 1e3,
            statistics.stdev(samples) * 1e3 if len(samples) > 1 else 0.0)


def benchmark(label: str, runs: int = 20) -> None:
    pk_holder = [None]; sk_holder = [None]; ct_holder = [None]; ss_holder = [None]

    def kg():
        pk, sk = keygen(); pk_holder[0], sk_holder[0] = pk, sk

    def en():
        ct, ss = encaps(pk_holder[0]); ct_holder[0], ss_holder[0] = ct, ss

    def de():
        decaps(ct_holder[0], sk_holder[0])

    print(f"\n--- {label} ({runs} runs each) ---")
    kg()  # warmup
    print(f"  keygen   : mean={time_call(kg, runs)[0]:7.2f} ms  median={time_call(kg, runs)[1]:7.2f} ms")
    en()
    print(f"  encaps   : mean={time_call(en, runs)[0]:7.2f} ms  median={time_call(en, runs)[1]:7.2f} ms")
    de()
    print(f"  decaps   : mean={time_call(de, runs)[0]:7.2f} ms  median={time_call(de, runs)[1]:7.2f} ms")


def entropy_throughput(src: TRNGSource, label: str, total: int = 1 << 16) -> None:
    t0 = time.perf_counter()
    src.read(total)
    dt = time.perf_counter() - t0
    print(f"  {label:20s}  {total:>8} B in {dt*1000:7.2f} ms  "
          f"=  {total / dt / 1024:8.1f} KiB/s")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", help="serial port for hardware TRNG (e.g. /dev/ttyACM0)")
    parser.add_argument("--runs", type=int, default=20)
    args = parser.parse_args()

    print("=" * 60)
    print("kyber-trng-entropy-injection :: benchmark suite")
    print("=" * 60)

    print("\nEntropy throughput")
    sim = SimulatedTRNGSource()
    entropy_throughput(sim, "simulated", 1 << 16)

    if args.port:
        from .source import SerialTRNGSource
        ser = SerialTRNGSource(args.port)
        entropy_throughput(ser, "serial-TRNG", 1 << 14)
        ser.close()

    # Variant 1: simulated TRNG only (replaces os.urandom)
    set_entropy_source(SimulatedTRNGSource())
    benchmark("Simulated TRNG (drop-in)", args.runs)

    # Variant 2: hybrid DRBG (TRNG XOR HMAC-DRBG) — recommended
    set_entropy_source(HybridDRBG(SimulatedTRNGSource()))
    benchmark("Hybrid TRNG ⊕ HMAC-DRBG", args.runs)

    if args.port:
        from .source import SerialTRNGSource
        set_entropy_source(SerialTRNGSource(args.port))
        benchmark("Hardware TRNG (SAM3X8E)", args.runs)


if __name__ == "__main__":
    main()
