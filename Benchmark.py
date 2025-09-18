# Benchmark.py
import time
import psutil
import oqs
import json
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

def benchmark_kyber():
    """Benchmarks the Kyber768 key exchange."""
    kem_name = "Kyber768"
    
    cpu_usage_start = psutil.cpu_percent(interval=None)
    start_time = time.perf_counter()

    with oqs.KeyEncapsulation(kem_name) as client_kem:
        with oqs.KeyEncapsulation(kem_name) as server_kem:
            public_key = server_kem.generate_keypair()
            ciphertext, shared_secret_client = client_kem.encap_secret(public_key)
            shared_secret_server = server_kem.decap_secret(ciphertext)

    end_time = time.perf_counter()
    cpu_usage_end = psutil.cpu_percent(interval=None)
    
    assert shared_secret_client == shared_secret_server

    return {
        "latency_ms": (end_time - start_time) * 1000,
        "cpu_percent": cpu_usage_end - cpu_usage_start
    }

def benchmark_ecdh():
    """Benchmarks the ECDH key exchange using the SECP384R1 curve."""
    
    cpu_usage_start = psutil.cpu_percent(interval=None)
    start_time = time.perf_counter()

    server_private_key = ec.generate_private_key(ec.SECP384R1())
    server_public_key = server_private_key.public_key()
    client_private_key = ec.generate_private_key(ec.SECP384R1())
    client_public_key = client_private_key.public_key()
    shared_key_server = server_private_key.exchange(ec.ECDH(), client_public_key)
    shared_key_client = client_private_key.exchange(ec.ECDH(), server_public_key)
    
    end_time = time.perf_counter()
    cpu_usage_end = psutil.cpu_percent(interval=None)

    assert shared_key_client == shared_key_server
    
    return {
        "latency_ms": (end_time - start_time) * 1000,
        "cpu_percent": cpu_usage_end - cpu_usage_start
    }

def main():
    """Runs the benchmarks and saves the results."""
    num_runs = 100
    kyber_results = []
    ecdh_results = []

    print(f"Running {num_runs} iterations for each key exchange mechanism...")

    for i in range(num_runs):
        kyber_results.append(benchmark_kyber())
        ecdh_results.append(benchmark_ecdh())
        print(f"  ... completed iteration {i+1}/{num_runs}", end='\r')

    print("\nBenchmark complete.")

    results = {
        "kyber": kyber_results,
        "ecdh": ecdh_results
    }

    with open("performance_results.json", "w") as f:
        json.dump(results, f, indent=2)
    
    print("Results saved to performance_results.json")

if __name__ == "__main__":
    main()