"""Measure the cost of QuMail's key exchange against classical alternatives.

The original benchmark needed liboqs and timed a whole keygen+encaps+decaps
cycle as one number, which hides where the cost actually is. This version
times each operation separately, using only the libraries QuMail already
depends on, and reports percentiles rather than a mean -- key exchange timings
are right-skewed, so a mean overstates the typical case.

Note on interpretation: kyber-py is a pure-Python reference implementation
chosen for portability and auditability. Its absolute numbers are far slower
than a C implementation such as liboqs; the *shape* of the comparison holds,
the magnitudes do not. Do not quote these as ML-KEM's real-world cost.

    python tools/benchmark.py --runs 100 --out performance_results.json
"""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import sys
import time
from typing import Callable, Dict, List

from cryptography.hazmat.primitives.asymmetric import ec, x25519
from kyber_py.ml_kem import ML_KEM_768

sys.path.insert(0, ".")
from qumail.crypto.kem import decapsulate, encapsulate, generate_keypair  # noqa: E402


def _time(operation: Callable[[], object], runs: int) -> List[float]:
    """Run `operation` `runs` times, returning per-call milliseconds."""
    operation()  # warm up: first call pays import and allocation costs
    timings = []
    for _ in range(runs):
        start = time.perf_counter()
        operation()
        timings.append((time.perf_counter() - start) * 1000.0)
    return timings


def _summary(timings: List[float]) -> Dict[str, float]:
    ordered = sorted(timings)
    return {
        "runs": len(ordered),
        "min_ms": ordered[0],
        "median_ms": statistics.median(ordered),
        "p95_ms": ordered[min(len(ordered) - 1, int(len(ordered) * 0.95))],
        "max_ms": ordered[-1],
        "stdev_ms": statistics.stdev(ordered) if len(ordered) > 1 else 0.0,
    }


def benchmark(runs: int) -> Dict[str, Dict[str, Dict[str, float]]]:
    results: Dict[str, Dict[str, Dict[str, float]]] = {}

    # --- ML-KEM-768: the post-quantum half ---
    ek, dk = ML_KEM_768.keygen()
    _, mlkem_ct = ML_KEM_768.encaps(ek)
    results["ML-KEM-768"] = {
        "keygen": _summary(_time(ML_KEM_768.keygen, runs)),
        "encapsulate": _summary(_time(lambda: ML_KEM_768.encaps(ek), runs)),
        "decapsulate": _summary(_time(lambda: ML_KEM_768.decaps(dk, mlkem_ct), runs)),
    }

    # --- X25519: the classical half ---
    x_priv = x25519.X25519PrivateKey.generate()
    x_peer = x25519.X25519PrivateKey.generate().public_key()
    results["X25519"] = {
        "keygen": _summary(_time(x25519.X25519PrivateKey.generate, runs)),
        "exchange": _summary(_time(lambda: x_priv.exchange(x_peer), runs)),
    }

    # --- ECDH P-384: what a classical-only design would use ---
    ec_priv = ec.generate_private_key(ec.SECP384R1())
    ec_peer = ec.generate_private_key(ec.SECP384R1()).public_key()
    results["ECDH-P384"] = {
        "keygen": _summary(_time(lambda: ec.generate_private_key(ec.SECP384R1()), runs)),
        "exchange": _summary(_time(lambda: ec_priv.exchange(ec.ECDH(), ec_peer), runs)),
    }

    # --- The hybrid actually shipped ---
    hybrid_pub, hybrid_priv = generate_keypair()
    hybrid_ct, _ = encapsulate(hybrid_pub, b"benchmark")
    results["QuMail hybrid"] = {
        "keygen": _summary(_time(generate_keypair, runs)),
        "encapsulate": _summary(
            _time(lambda: encapsulate(hybrid_pub, b"benchmark"), runs)
        ),
        "decapsulate": _summary(
            _time(
                lambda: decapsulate(hybrid_priv, hybrid_pub, hybrid_ct, b"benchmark"),
                runs,
            )
        ),
    }

    return results


SIZES = {
    "ML-KEM-768": {"public_key": 1184, "private_key": 2400, "ciphertext": 1088},
    "X25519": {"public_key": 32, "private_key": 32, "ciphertext": 32},
    "ECDH-P384": {"public_key": 97, "private_key": 48, "ciphertext": 97},
    "QuMail hybrid": {"public_key": 1216, "private_key": 2432, "ciphertext": 1120},
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", type=int, default=100, help="iterations per operation")
    parser.add_argument("--out", default="performance_results.json")
    args = parser.parse_args()

    if args.runs < 2:
        print("--runs must be at least 2", file=sys.stderr)
        return 2

    print("Benchmarking %d runs per operation..." % args.runs)
    results = benchmark(args.runs)

    payload = {
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "processor": platform.processor() or "unknown",
        },
        "note": (
            "kyber-py is a pure-Python implementation; ML-KEM timings are far "
            "slower than an optimised C library and are not representative of "
            "ML-KEM's real cost."
        ),
        "sizes_bytes": SIZES,
        "results": results,
    }

    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)

    print("\n%-16s %-14s %10s %10s" % ("ALGORITHM", "OPERATION", "MEDIAN", "P95"))
    print("-" * 54)
    for algorithm, operations in results.items():
        for operation, stats in operations.items():
            print(
                "%-16s %-14s %9.3fms %9.3fms"
                % (algorithm, operation, stats["median_ms"], stats["p95_ms"])
            )

    print("\nWrote %s" % args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
