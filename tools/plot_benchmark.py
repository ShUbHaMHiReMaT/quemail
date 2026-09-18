"""Plot the output of tools/benchmark.py.

    python tools/benchmark.py --runs 100
    python tools/plot_benchmark.py

Requires matplotlib (pip install -r requirements-dev.txt).
"""

from __future__ import annotations

import argparse
import json
import sys


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", default="performance_results.json")
    parser.add_argument("--out", default="performance_comparison.png")
    args = parser.parse_args()

    try:
        import matplotlib

        matplotlib.use("Agg")  # no display needed on a server
        import matplotlib.pyplot as plt
    except ImportError:
        print(
            "matplotlib is not installed. pip install -r requirements-dev.txt",
            file=sys.stderr,
        )
        return 1

    try:
        with open(args.results, encoding="utf-8") as handle:
            payload = json.load(handle)
    except FileNotFoundError:
        print("%s not found. Run tools/benchmark.py first." % args.results, file=sys.stderr)
        return 1

    results = payload["results"]
    sizes = payload.get("sizes_bytes", {})

    figure, (left, right) = plt.subplots(1, 2, figsize=(14, 6))

    # --- median latency per algorithm, summed across its operations ---
    algorithms = list(results)
    totals = [
        sum(op["median_ms"] for op in operations.values())
        for operations in results.values()
    ]
    bars = left.bar(algorithms, totals, color=["#4c72b0", "#dd8452", "#55a868", "#c44e52"])
    left.set_title("Full key exchange: median latency")
    left.set_ylabel("milliseconds (lower is better)")
    left.set_yscale("log")
    left.tick_params(axis="x", rotation=20)
    left.grid(True, axis="y", linestyle="--", alpha=0.4)
    for bar, value in zip(bars, totals):
        left.annotate(
            "%.2f ms" % value,
            (bar.get_x() + bar.get_width() / 2, value),
            ha="center", va="bottom", fontsize=9,
        )

    # --- wire cost: what each scheme adds to every message ---
    labels = [a for a in algorithms if a in sizes]
    public = [sizes[a]["public_key"] for a in labels]
    ciphertext = [sizes[a]["ciphertext"] for a in labels]
    positions = range(len(labels))

    right.bar([p - 0.2 for p in positions], public, width=0.4, label="public key")
    right.bar([p + 0.2 for p in positions], ciphertext, width=0.4, label="ciphertext")
    right.set_xticks(list(positions))
    right.set_xticklabels(labels, rotation=20)
    right.set_title("Wire cost per message")
    right.set_ylabel("bytes")
    right.legend()
    right.grid(True, axis="y", linestyle="--", alpha=0.4)

    figure.suptitle(
        "QuMail key exchange: post-quantum hybrid vs. classical", fontsize=13
    )
    figure.text(
        0.5, 0.01, payload.get("note", ""), ha="center", fontsize=8, style="italic"
    )
    figure.tight_layout(rect=(0, 0.04, 1, 0.95))
    figure.savefig(args.out, dpi=150)

    print("Wrote %s" % args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
