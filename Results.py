# Results.py
import json
import matplotlib.pyplot as plt
import numpy as np

def plot_results():
    """Loads benchmark results and plots them."""
    with open("performance_results.json", "r") as f:
        results = json.load(f)

    kyber_latencies = [r['latency_ms'] for r in results['kyber']]
    ecdh_latencies = [r['latency_ms'] for r in results['ecdh']]
    
    kyber_cpu = [r['cpu_percent'] for r in results['kyber'] if r['cpu_percent'] >= 0]
    ecdh_cpu = [r['cpu_percent'] for r in results['ecdh'] if r['cpu_percent'] >= 0]


    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))

    # Latency Plot
    ax1.boxplot([kyber_latencies, ecdh_latencies], labels=['Kyber768', 'ECDH (SECP384R1)'])
    ax1.set_title('Key Exchange Latency Comparison')
    ax1.set_ylabel('Latency (ms)')
    ax1.grid(True, linestyle='--', alpha=0.6)

    # CPU Usage Plot
    ax2.boxplot([kyber_cpu, ecdh_cpu], labels=['Kyber768', 'ECDH (SECP384R1)'])
    ax2.set_title('Key Exchange CPU Usage Comparison')
    ax2.set_ylabel('CPU Usage (%)')
    ax2.grid(True, linestyle='--', alpha=0.6)

    avg_kyber_lat = np.mean(kyber_latencies)
    avg_ecdh_lat = np.mean(ecdh_latencies)
    avg_kyber_cpu = np.mean(kyber_cpu)
    avg_ecdh_cpu = np.mean(ecdh_cpu)

    print("\n--- Average Performance ---")
    print(f"Kyber768 Latency: {avg_kyber_lat:.4f} ms")
    print(f"ECDH Latency:     {avg_ecdh_lat:.4f} ms")
    print(f"Kyber768 CPU:     {avg_kyber_cpu:.4f} %")
    print(f"ECDH CPU:         {avg_ecdh_cpu:.4f} %")
    print("---------------------------\n")


    plt.suptitle('Performance Comparison: Kyber vs. ECDH Key Exchange')
    plt.tight_layout(rect=[0, 0.03, 1, 0.95])
    plt.savefig('performance_comparison.png')
    print("Plot saved to performance_comparison.png")
    plt.show()


if __name__ == "__main__":
    plot_results()