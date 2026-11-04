"""
Master Benchmark: Post-Quantum Cryptography & Crypto-Agility (NIST FIPS 203).

Benchmarks ML-KEM-768 (Kyber) and Hybrid KEM against Classical RSA-2048, RSA-4096, and ECDH P-256.
Evaluates key sizes, ciphertext sizes, execution latencies, and network MTU fragmentation risk.
"""

import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import time
import numpy as np
import matplotlib.pyplot as plt
from src.pqc_algorithms import MLKEM768, ClassicalRSA, ClassicalECDH, HybridPQC

def benchmark_suite(n_trials: int = 15):
    print("=" * 80)
    print("POST-QUANTUM CRYPTO-AGILITY BENCHMARK (NIST FIPS 203 AUDIT)")
    print(f"Running {n_trials} iterations per algorithm...")
    print("=" * 80)

    results = {}

    # -------------------------------------------------------------
    # 1. Classical RSA-2048
    # -------------------------------------------------------------
    print("Benchmarking RSA-2048...")
    rsa2048 = ClassicalRSA(key_size=2048)
    t_keygen, t_encaps, t_decaps = [], [], []
    for _ in range(n_trials):
        t0 = time.perf_counter()
        pub, priv = rsa2048.keygen()
        t_keygen.append(time.perf_counter() - t0)

        t0 = time.perf_counter()
        ct, sec = rsa2048.encaps(pub)
        t_encaps.append(time.perf_counter() - t0)

        t0 = time.perf_counter()
        _ = rsa2048.decaps(priv, ct)
        t_decaps.append(time.perf_counter() - t0)

    results['RSA-2048'] = {
        'pk_bytes': 270,        # DER encoded SubjectPublicKeyInfo
        'ct_bytes': 256,        # 2048-bit modulus ciphertext
        't_keygen_ms': np.mean(t_keygen) * 1000.0,
        't_encaps_ms': np.mean(t_encaps) * 1000.0,
        't_decaps_ms': np.mean(t_decaps) * 1000.0,
        'quantum_safe': False,
        'standard': 'Legacy (PKCS#1)'
    }

    # -------------------------------------------------------------
    # 2. Classical RSA-4096
    # -------------------------------------------------------------
    print("Benchmarking RSA-4096...")
    rsa4096 = ClassicalRSA(key_size=4096)
    t_keygen, t_encaps, t_decaps = [], [], []
    for _ in range(max(3, n_trials // 3)):
        t0 = time.perf_counter()
        pub, priv = rsa4096.keygen()
        t_keygen.append(time.perf_counter() - t0)

        t0 = time.perf_counter()
        ct, sec = rsa4096.encaps(pub)
        t_encaps.append(time.perf_counter() - t0)

        t0 = time.perf_counter()
        _ = rsa4096.decaps(priv, ct)
        t_decaps.append(time.perf_counter() - t0)

    results['RSA-4096'] = {
        'pk_bytes': 526,
        'ct_bytes': 512,
        't_keygen_ms': np.mean(t_keygen) * 1000.0,
        't_encaps_ms': np.mean(t_encaps) * 1000.0,
        't_decaps_ms': np.mean(t_decaps) * 1000.0,
        'quantum_safe': False,
        'standard': 'Legacy (High-Sec)'
    }

    # -------------------------------------------------------------
    # 3. Classical ECDH P-256
    # -------------------------------------------------------------
    print("Benchmarking ECDH P-256...")
    ecdh = ClassicalECDH()
    t_keygen, t_encaps, t_decaps = [], [], []
    for _ in range(n_trials):
        t0 = time.perf_counter()
        pub, priv = ecdh.keygen()
        t_keygen.append(time.perf_counter() - t0)

        t0 = time.perf_counter()
        ephem_pub, ephem_priv = ecdh.keygen()
        ss_alice = ecdh.compute_shared_secret(ephem_priv, pub)
        t_encaps.append(time.perf_counter() - t0)

        t0 = time.perf_counter()
        ss_bob = ecdh.compute_shared_secret(priv, ephem_pub)
        t_decaps.append(time.perf_counter() - t0)

    results['ECDH P-256'] = {
        'pk_bytes': 65,         # Uncompressed SEC1 point
        'ct_bytes': 65,         # Ephemeral public key
        't_keygen_ms': np.mean(t_keygen) * 1000.0,
        't_encaps_ms': np.mean(t_encaps) * 1000.0,
        't_decaps_ms': np.mean(t_decaps) * 1000.0,
        'quantum_safe': False,
        'standard': 'NIST SP 800-56A'
    }

    # -------------------------------------------------------------
    # 4. Post-Quantum ML-KEM-768 (NIST FIPS 203)
    # -------------------------------------------------------------
    print("Benchmarking ML-KEM-768 (NIST FIPS 203)...")
    t_keygen, t_encaps, t_decaps = [], [], []
    for _ in range(n_trials):
        t0 = time.perf_counter()
        pk, sk = MLKEM768.keygen()
        t_keygen.append(time.perf_counter() - t0)

        t0 = time.perf_counter()
        ct, ss_a = MLKEM768.encaps(pk)
        t_encaps.append(time.perf_counter() - t0)

        t0 = time.perf_counter()
        ss_b = MLKEM768.decaps(sk, ct)
        t_decaps.append(time.perf_counter() - t0)

    results['ML-KEM-768'] = {
        'pk_bytes': MLKEM768.PUBLIC_KEY_BYTES,   # 1184 bytes
        'ct_bytes': MLKEM768.CIPHERTEXT_BYTES,   # 1088 bytes
        't_keygen_ms': np.mean(t_keygen) * 1000.0,
        't_encaps_ms': np.mean(t_encaps) * 1000.0,
        't_decaps_ms': np.mean(t_decaps) * 1000.0,
        'quantum_safe': True,
        'standard': 'NIST FIPS 203 (Kyber)'
    }

    # -------------------------------------------------------------
    # 5. Hybrid PQC (ECDH P-256 + ML-KEM-768)
    # -------------------------------------------------------------
    print("Benchmarking Hybrid PQC (X25519/ECDH + ML-KEM)...")
    t_keygen, t_encaps, t_decaps = [], [], []
    for _ in range(n_trials):
        t0 = time.perf_counter()
        hpk, hsk = HybridPQC.keygen()
        t_keygen.append(time.perf_counter() - t0)

        t0 = time.perf_counter()
        hct, hss_a = HybridPQC.encaps(hpk)
        t_encaps.append(time.perf_counter() - t0)

        t0 = time.perf_counter()
        hss_b = HybridPQC.decaps(hsk, hct)
        t_decaps.append(time.perf_counter() - t0)

    results['Hybrid PQC'] = {
        'pk_bytes': 65 + MLKEM768.PUBLIC_KEY_BYTES,     # 1249 bytes
        'ct_bytes': 65 + MLKEM768.CIPHERTEXT_BYTES,     # 1153 bytes
        't_keygen_ms': np.mean(t_keygen) * 1000.0,
        't_encaps_ms': np.mean(t_encaps) * 1000.0,
        't_decaps_ms': np.mean(t_decaps) * 1000.0,
        'quantum_safe': True,
        'standard': 'NIST Transition Std'
    }

    # -------------------------------------------------------------
    # Display Benchmark Table
    # -------------------------------------------------------------
    print("\n" + "=" * 90)
    print("EXECUTIVE AUDIT: POST-QUANTUM CRYPTO-AGILITY BENCHMARK")
    print("=" * 90)
    print(f"{'Algorithm':<15} {'Quantum-Safe':<14} {'PK Size (B)':<13} {'CT Size (B)':<13} {'KeyGen (ms)':<13} {'Encaps (ms)':<13} {'Decaps (ms)'}")
    print("-" * 90)
    for name, m in results.items():
        q_safe = "YES (Immune)" if m['quantum_safe'] else "NO (Broken)"
        print(f"{name:<15} {q_safe:<14} {m['pk_bytes']:<13} {m['ct_bytes']:<13} {m['t_keygen_ms']:<13.2f} {m['t_encaps_ms']:<13.2f} {m['t_decaps_ms']:.2f}")
    print("=" * 90)

    # -------------------------------------------------------------
    # Generate Publication Figure
    # -------------------------------------------------------------
    names = list(results.keys())
    pk_sizes = [results[n]['pk_bytes'] for n in names]
    ct_sizes = [results[n]['ct_bytes'] for n in names]
    t_encaps = [results[n]['t_encaps_ms'] for n in names]
    t_decaps = [results[n]['t_decaps_ms'] for n in names]
    q_safe = [results[n]['quantum_safe'] for n in names]

    fig, (ax1, ax2, ax3) = plt.subplots(1, 3, figsize=(16, 5))

    # --- Plot 1: Key & Ciphertext Wire Sizes (Log Scale) ---
    x = np.arange(len(names))
    width = 0.35
    ax1.bar(x - width/2, pk_sizes, width, label='Public Key', color='royalblue', edgecolor='black')
    ax1.bar(x + width/2, ct_sizes, width, label='Ciphertext', color='darkorange', edgecolor='black')
    ax1.axhline(1500, color='red', ls='--', lw=1.5, label='TCP MTU (1500 B)')
    ax1.set_yscale('log')
    ax1.set_xticks(x)
    ax1.set_xticklabels(names, rotation=25, ha='right', fontsize=9)
    ax1.set_ylabel('Size in Bytes (Log Scale)', fontsize=11)
    ax1.set_title('Payload Wire Size vs. MTU Limit', fontsize=12, fontweight='bold')
    ax1.legend(loc='upper left', fontsize=9)
    ax1.grid(True, which='both', alpha=0.3)

    # --- Plot 2: Handshake Latency ---
    ax2.bar(x - width/2, t_encaps, width, label='Encaps / Encrypt', color='seagreen', edgecolor='black')
    ax2.bar(x + width/2, t_decaps, width, label='Decaps / Decrypt', color='crimson', edgecolor='black')
    ax2.set_xticks(x)
    ax2.set_xticklabels(names, rotation=25, ha='right', fontsize=9)
    ax2.set_ylabel('Execution Latency (ms)', fontsize=11)
    ax2.set_title('Cryptographic Latency per Operation', fontsize=12, fontweight='bold')
    ax2.legend(loc='upper right', fontsize=9)
    ax2.grid(True, alpha=0.3)

    # --- Plot 3: Security & MTU Risk Matrix ---
    total_wire = [p + c for p, c in zip(pk_sizes, ct_sizes)]
    colors = ['crimson' if not qs else ('darkgreen' if tw < 1500 else 'goldenrod') 
              for qs, tw in zip(q_safe, total_wire)]
    bars = ax3.bar(names, total_wire, color=colors, edgecolor='black', alpha=0.85)
    ax3.axhline(1500, color='red', ls='--', lw=1.5, label='1500 B Fragmentation Line')
    ax3.set_xticks(range(len(names)))
    ax3.set_xticklabels(names, rotation=25, ha='right', fontsize=9)
    ax3.set_ylabel('Total Handshake Wire Bytes (PK + CT)', fontsize=11)
    ax3.set_title('Quantum Security & Network Risk', fontsize=12, fontweight='bold')
    ax3.legend(loc='upper left', fontsize=9)
    ax3.grid(True, alpha=0.3)

    for bar, qs in zip(bars, q_safe):
        label = "SAFE" if qs else "BROKEN"
        ax3.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 30, label,
                 ha='center', va='bottom', fontsize=8, fontweight='bold')

    plt.tight_layout()
    out_png = os.path.join(os.path.dirname(__file__), "fig_pqc_crypto_agility.png")
    plt.savefig(out_png, dpi=300)
    print(f"\nPublication plot saved successfully to:\n  {out_png}")

if __name__ == "__main__":
    benchmark_suite()
