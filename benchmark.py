"""
Benchmark script for Pangfish library
"""

import time
import os
import sys
import argparse
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from pangfish import Twofish, MultiPowerRSA, HybridCryptosystem

def benchmark_twofish(rounds=1000, key_size=256, data_size=1024):
    """Benchmark Twofish performance"""
    print(f"Benchmarking Twofish with {rounds} rounds...")
    
    # Generate key and data
    key = os.urandom(key_size // 8)
    data = os.urandom(data_size)
    
    # Create cipher
    cipher = Twofish(key)
    
    # Time encryption (ECB mode)
    start_time = time.time()
    for _ in range(rounds):
        encrypted = cipher.encrypt(data, mode='ecb')
    encryption_time = (time.time() - start_time) * 1000 / rounds  # ms per operation
    
    # Time decryption (ECB mode)
    start_time = time.time()
    for _ in range(rounds):
        decrypted = cipher.decrypt(encrypted, mode='ecb')
    decryption_time = (time.time() - start_time) * 1000 / rounds  # ms per operation
    
    # Time encryption (CBC mode)
    iv = os.urandom(16)
    start_time = time.time()
    for _ in range(rounds):
        encrypted_cbc = cipher.encrypt(data, mode='cbc', iv=iv)
    encryption_time_cbc = (time.time() - start_time) * 1000 / rounds  # ms per operation
    
    # Time decryption (CBC mode)
    start_time = time.time()
    for _ in range(rounds):
        decrypted_cbc = cipher.decrypt(encrypted_cbc, mode='cbc', iv=iv)
    decryption_time_cbc = (time.time() - start_time) * 1000 / rounds  # ms per operation
    
    return {
        'algorithm': 'Twofish',
        'mode_ecb_encryption_ms': encryption_time,
        'mode_ecb_decryption_ms': decryption_time,
        'mode_cbc_encryption_ms': encryption_time_cbc,
        'mode_cbc_decryption_ms': decryption_time_cbc,
        'data_size_bytes': data_size,
        'key_size_bits': key_size
    }

def benchmark_multipowerrsa(rounds=10, key_sizes=[1024, 2048], b_values=[2, 3]):
    """Benchmark Multi-Power RSA performance"""
    print(f"Benchmarking Multi-Power RSA with {rounds} rounds...")
    
    results = []
    
    for key_size in key_sizes:
        for b in b_values:
            print(f"  Testing key size {key_size} bits, b={b}...")
            
            # Generate test data
            test_data = 12345678  # Small integer
            
            # Key generation time
            start_time = time.time()
            rsa = MultiPowerRSA(key_size=key_size, b=b)
            public_key, private_key = rsa.generate_keys()
            key_gen_time = (time.time() - start_time) * 1000  # ms
            
            # Encrypt and decrypt small data multiple times
            encrypt_times = []
            decrypt_times = []
            
            for _ in range(rounds):
                # Encryption time
                start_time = time.time()
                ciphertext = rsa.encrypt(test_data, public_key)
                encrypt_times.append((time.time() - start_time) * 1000)  # ms
                
                # Decryption time
                start_time = time.time()
                plaintext = rsa.decrypt(ciphertext, private_key)
                decrypt_times.append((time.time() - start_time) * 1000)  # ms
            
            results.append({
                'algorithm': f'Multi-Power RSA (b={b})',
                'key_size_bits': key_size,
                'b_value': b,
                'key_generation_ms': key_gen_time,
                'encryption_ms': np.mean(encrypt_times),
                'decryption_ms': np.mean(decrypt_times),
                'encryption_std': np.std(encrypt_times),
                'decryption_std': np.std(decrypt_times)
            })
    
    return results

def benchmark_hybrid(rounds=10, rsa_key_size=2048, b=3, data_sizes=[1024, 10240, 102400]):
    """
    Benchmark Hybrid Cryptosystem performance
    
    Args:
        rounds (int): Number of encryption/decryption rounds
        rsa_key_size (int): RSA key size in bits
        b (int): Multi-Power RSA parameter
        data_sizes (list): List of data sizes to test
    
    Returns:
        list: Performance benchmarking results
    """
    print(f"Benchmarking Hybrid Cryptosystem with {rounds} rounds...")
    
    results = []
    
    for data_size in data_sizes:
        print(f"  Testing with data size {data_size} bytes...")
        
        # Generate test data
        test_data = os.urandom(data_size)
        
        # Initialize cryptosystem
        crypto = HybridCryptosystem()
        public_key, private_key = crypto.generate_keys(rsa_key_size=rsa_key_size, b=b)
        
        # Encrypt and decrypt data multiple times
        encrypt_times = []
        decrypt_times = []
        
        for _ in range(rounds):
            # Encryption time
            start_time = time.time()
            encrypted_data = crypto.encrypt(test_data, public_key=public_key)
            encrypt_time = (time.time() - start_time) * 1000  # ms
            encrypt_times.append(encrypt_time)
            
            # Serialization (part of real-world usage)
            serialized = HybridCryptosystem.serialize_encrypted_data(encrypted_data)
            deserialized = HybridCryptosystem.deserialize_encrypted_data(serialized)
            
            # Decryption time
            start_time = time.time()
            decrypted = crypto.decrypt(deserialized, private_key=private_key)
            decrypt_time = (time.time() - start_time) * 1000  # ms
            decrypt_times.append(decrypt_time)
            
            # Verify correctness
            if len(decrypted) != len(test_data):
                print(f"Length mismatch: original {len(test_data)}, decrypted {len(decrypted)}")
                print(f"Decrypted data first 10 bytes: {decrypted[:10]}")
                print(f"Original data first 10 bytes: {test_data[:10]}")
            
            assert decrypted == test_data, "Decryption failed!"
        
        results.append({
            'algorithm': 'Hybrid (Twofish+MPRSA)',
            'data_size_bytes': data_size,
            'rsa_key_size_bits': rsa_key_size,
            'b_value': b,
            'encryption_ms': np.mean(encrypt_times),
            'decryption_ms': np.mean(decrypt_times),
            'encryption_std': np.std(encrypt_times),
            'decryption_std': np.std(decrypt_times)
        })
    
    return results

def plot_results(twofish_results, rsa_results, hybrid_results, output_dir='.'):
    """Plot benchmark results"""
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    # Prepare DataFrame for Twofish results
    twofish_df = pd.DataFrame([twofish_results])
    
    # Plot Twofish ECB vs CBC
    plt.figure(figsize=(10, 6))
    
    # Create bar data
    labels = ['ECB Encryption', 'ECB Decryption', 'CBC Encryption', 'CBC Decryption']
    values = [
        twofish_df['mode_ecb_encryption_ms'].values[0],
        twofish_df['mode_ecb_decryption_ms'].values[0],
        twofish_df['mode_cbc_encryption_ms'].values[0],
        twofish_df['mode_cbc_decryption_ms'].values[0]
    ]
    
    plt.bar(labels, values, color=['blue', 'lightblue', 'green', 'lightgreen'])
    plt.ylabel('Time (ms)')
    plt.title(f'Twofish Performance: ECB vs CBC Mode ({twofish_df["data_size_bytes"].values[0]} bytes)')
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    
    for i, v in enumerate(values):
        plt.text(i, v + 0.1, f'{v:.2f}', ha='center')
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'twofish_ecb_vs_cbc.png'))
    
    # Prepare DataFrame for Multi-Power RSA results
    rsa_df = pd.DataFrame(rsa_results)
    
    # Plot RSA key generation time by key size and b value
    plt.figure(figsize=(10, 6))
    
    key_sizes = sorted(rsa_df['key_size_bits'].unique())
    b_values = sorted(rsa_df['b_value'].unique())
    
    bar_width = 0.35
    index = np.arange(len(key_sizes))
    
    for i, b in enumerate(b_values):
        b_data = rsa_df[rsa_df['b_value'] == b]
        values = [b_data[b_data['key_size_bits'] == ks]['key_generation_ms'].values[0] for ks in key_sizes]
        plt.bar(index + i*bar_width, values, bar_width, label=f'b={b}')
    
    plt.xlabel('Key Size (bits)')
    plt.ylabel('Time (ms)')
    plt.title('Multi-Power RSA Key Generation Time')
    plt.xticks(index + bar_width/2, key_sizes)
    plt.legend()
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'mprsa_key_generation.png'))
    
    # Plot RSA encryption/decryption time by key size and b value
    plt.figure(figsize=(12, 8))
    
    for i, key_size in enumerate(key_sizes):
        plt.subplot(1, len(key_sizes), i+1)
        
        ks_data = rsa_df[rsa_df['key_size_bits'] == key_size]
        x = np.arange(len(b_values))
        width = 0.35
        
        enc_values = [ks_data[ks_data['b_value'] == b]['encryption_ms'].values[0] for b in b_values]
        dec_values = [ks_data[ks_data['b_value'] == b]['decryption_ms'].values[0] for b in b_values]
        
        plt.bar(x - width/2, enc_values, width, label='Encryption')
        plt.bar(x + width/2, dec_values, width, label='Decryption')
        
        plt.xlabel('b value')
        plt.ylabel('Time (ms)')
        plt.title(f'Key Size: {key_size} bits')
        plt.xticks(x, b_values)
        plt.legend()
        plt.grid(axis='y', linestyle='--', alpha=0.7)
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'mprsa_encryption_decryption.png'))
    
    # Prepare DataFrame for Hybrid Cryptosystem results
    hybrid_df = pd.DataFrame(hybrid_results)
    
    # Plot Hybrid encryption/decryption time by data size
    plt.figure(figsize=(10, 6))
    
    data_sizes = sorted(hybrid_df['data_size_bytes'].unique())
    x = np.arange(len(data_sizes))
    width = 0.35
    
    enc_values = [hybrid_df[hybrid_df['data_size_bytes'] == ds]['encryption_ms'].values[0] for ds in data_sizes]
    dec_values = [hybrid_df[hybrid_df['data_size_bytes'] == ds]['decryption_ms'].values[0] for ds in data_sizes]
    
    plt.bar(x - width/2, enc_values, width, label='Encryption')
    plt.bar(x + width/2, dec_values, width, label='Decryption')
    
    plt.xlabel('Data Size (bytes)')
    plt.ylabel('Time (ms)')
    plt.title(f'Hybrid Cryptosystem Performance (RSA {hybrid_df["rsa_key_size_bits"].values[0]} bits, b={hybrid_df["b_value"].values[0]})')
    plt.xticks(x, data_sizes)
    plt.legend()
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'hybrid_performance.png'))
    
    # Create performance report
    report = pd.concat([
        twofish_df,
        rsa_df,
        hybrid_df
    ])
    
    report.to_csv(os.path.join(output_dir, 'performance_report.csv'), index=False)
    
    print(f"Results saved to {output_dir}")

def main():
    parser = argparse.ArgumentParser(description='Benchmark Pangfish library')
    parser.add_argument('--twofish', action='store_true', help='Run Twofish benchmark')
    parser.add_argument('--mprsa', action='store_true', help='Run Multi-Power RSA benchmark')
    parser.add_argument('--hybrid', action='store_true', help='Run Hybrid Cryptosystem benchmark')
    parser.add_argument('--all', action='store_true', help='Run all benchmarks')
    parser.add_argument('--output', default='benchmark_results', help='Output directory for results')
    
    args = parser.parse_args()
    
    if not (args.twofish or args.mprsa or args.hybrid or args.all):
        parser.print_help()
        return
    
    twofish_results = None
    rsa_results = None
    hybrid_results = None
    
    if args.twofish or args.all:
        twofish_results = benchmark_twofish()
    
    if args.mprsa or args.all:
        rsa_results = benchmark_multipowerrsa()
    
    if args.hybrid or args.all:
        hybrid_results = benchmark_hybrid()
    
    # Plot results if we have data
    if twofish_results or rsa_results or hybrid_results:
        plot_results(
            twofish_results if twofish_results else None,
            rsa_results if rsa_results else [],
            hybrid_results if hybrid_results else [],
            args.output
        )

if __name__ == "__main__":
    main()