"""
Master Benchmark: Post-Quantum Cryptography & Crypto-Agility (NIST FIPS 203).

Benchmarks ML-KEM-768 (C-compiled pqcrypto) and Hybrid KEM against
Classical RSA-2048, RSA-4096, and ECDH P-256 (OpenSSL C backend).
Audits key sizes, ciphertext sizes, execution latencies (in us/ms),
and real TCP socket MTU fragmentation.
"""

import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import time
import numpy as np
import matplotlib.pyplot as plt
from src.pqc_algorithms import MLKEM768, ClassicalRSA, ClassicalECDH, HybridPQC
from src.network_socket_audit import audit_tcp_transport

def benchmark_suite(n_fast: int = 100, n_slow: int = 15):
    print("=" * 85)
    print("RIGOROUS POST-QUANTUM CRYPTO-AGILITY BENCHMARK (NIST FIPS 203 AUDIT)")
    print(f"Fast algorithms (ECDH, ML-KEM): {n_fast} iterations | RSA: {n_slow} iterations")
    print("=" * 85)

    results = {}

    # 1. Classical RSA-2048
    print("Benchmarking RSA-2048 (OpenSSL)...")
    rsa2048 = ClassicalRSA(key_size=2048)
    t_keygen, t_encaps, t_decaps = [], [], []
    for _ in range(n_slow):
        t0 = time.perf_counter()
        pub, priv = rsa2048.keygen()
        t_keygen.append(time.perf_counter() - t0)

        t0 = time.perf_counter()
        ct, sec = rsa2048.encaps(pub)
        t_encaps.append(time.perf_counter() - t0)

        t0 = time.perf_counter()
        _ = rsa2048.decaps(priv, ct)
        t_decaps.append(time.perf_counter() - t0)

    # Handshake wire payload = PK (DER ~270 B) + CT (256 B) = 526 B
    net_rsa2048 = audit_tcp_transport(b"X" * 526, port=29001)

    results['RSA-2048'] = {
        'pk_bytes': 270,
        'ct_bytes': 256,
        'total_wire': 526,
        't_keygen_us': np.mean(t_keygen) * 1e6,
        't_encaps_us': np.mean(t_encaps) * 1e6,
        't_decaps_us': np.mean(t_decaps) * 1e6,
        'quantum_safe': False,
        'tcp_chunks': net_rsa2048['chunks_count'],
        'standard': 'Legacy (PKCS#1)'
    }

    # 2. Classical RSA-4096
    print("Benchmarking RSA-4096 (OpenSSL)...")
    rsa4096 = ClassicalRSA(key_size=4096)
    t_keygen, t_encaps, t_decaps = [], [], []
    for _ in range(max(3, n_slow // 3)):
        t0 = time.perf_counter()
        pub, priv = rsa4096.keygen()
        t_keygen.append(time.perf_counter() - t0)

        t0 = time.perf_counter()
        ct, sec = rsa4096.encaps(pub)
        t_encaps.append(time.perf_counter() - t0)

        t0 = time.perf_counter()
        _ = rsa4096.decaps(priv, ct)
        t_decaps.append(time.perf_counter() - t0)

    net_rsa4096 = audit_tcp_transport(b"X" * 1038, port=29002)

    results['RSA-4096'] = {
        'pk_bytes': 526,
        'ct_bytes': 512,
        'total_wire': 1038,
        't_keygen_us': np.mean(t_keygen) * 1e6,
        't_encaps_us': np.mean(t_encaps) * 1e6,
        't_decaps_us': np.mean(t_decaps) * 1e6,
        'quantum_safe': False,
        'tcp_chunks': net_rsa4096['chunks_count'],
        'standard': 'Legacy (High-Sec)'
    }

    # 3. Classical ECDH P-256
    print("Benchmarking ECDH P-256 (OpenSSL)...")
    ecdh = ClassicalECDH()
    t_keygen, t_encaps, t_decaps = [], [], []
    for _ in range(n_fast):
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

    net_ecdh = audit_tcp_transport(b"X" * 130, port=29003)

    results['ECDH P-256'] = {
        'pk_bytes': 65,
        'ct_bytes': 65,
        'total_wire': 130,
        't_keygen_us': np.mean(t_keygen) * 1e6,
        't_encaps_us': np.mean(t_encaps) * 1e6,
        't_decaps_us': np.mean(t_decaps) * 1e6,
        'quantum_safe': False,
        'tcp_chunks': net_ecdh['chunks_count'],
        'standard': 'NIST SP 800-56A'
    }

    # 4. Post-Quantum ML-KEM-768 (C-Extension)
    print("Benchmarking ML-KEM-768 (NIST FIPS 203 C-Extension)...")
    t_keygen, t_encaps, t_decaps = [], [], []
    for _ in range(n_fast):
        t0 = time.perf_counter()
        pk, sk = MLKEM768.keygen()
        t_keygen.append(time.perf_counter() - t0)

        t0 = time.perf_counter()
        ct, ss_a = MLKEM768.encaps(pk)
        t_encaps.append(time.perf_counter() - t0)

        t0 = time.perf_counter()
        ss_b = MLKEM768.decaps(sk, ct)
        t_decaps.append(time.perf_counter() - t0)

    net_mlkem = audit_tcp_transport(b"X" * 2272, port=29004)

    results['ML-KEM-768'] = {
        'pk_bytes': MLKEM768.PUBLIC_KEY_BYTES,   # 1184 bytes
        'ct_bytes': MLKEM768.CIPHERTEXT_BYTES,   # 1088 bytes
        'total_wire': 2272,
        't_keygen_us': np.mean(t_keygen) * 1e6,
        't_encaps_us': np.mean(t_encaps) * 1e6,
        't_decaps_us': np.mean(t_decaps) * 1e6,
        'quantum_safe': True,
        'tcp_chunks': net_mlkem['chunks_count'],
        'standard': 'NIST FIPS 203 (Kyber)'
    }

    # 5. Hybrid PQC (ECDH P-256 + ML-KEM-768)
    print("Benchmarking Hybrid PQC (ECDH + ML-KEM)...")
    t_keygen, t_encaps, t_decaps = [], [], []
    for _ in range(n_fast):
        t0 = time.perf_counter()
        hpk, hsk = HybridPQC.keygen()
        t_keygen.append(time.perf_counter() - t0)

        t0 = time.perf_counter()
        hct, hss_a = HybridPQC.encaps(hpk)
        t_encaps.append(time.perf_counter() - t0)

        t0 = time.perf_counter()
        hss_b = HybridPQC.decaps(hsk, hct)
        t_decaps.append(time.perf_counter() - t0)

    net_hybrid = audit_tcp_transport(b"X" * 2402, port=29005)

    results['Hybrid PQC'] = {
        'pk_bytes': 65 + MLKEM768.PUBLIC_KEY_BYTES,     # 1249 bytes
        'ct_bytes': 65 + MLKEM768.CIPHERTEXT_BYTES,     # 1153 bytes
        'total_wire': 2402,
        't_keygen_us': np.mean(t_keygen) * 1e6,
        't_encaps_us': np.mean(t_encaps) * 1e6,
        't_decaps_us': np.mean(t_decaps) * 1e6,
        'quantum_safe': True,
        'tcp_chunks': net_hybrid['chunks_count'],
        'standard': 'NIST Transition Std'
    }

    # -------------------------------------------------------------
    # Display Benchmark Table
    # -------------------------------------------------------------
    print("\n" + "=" * 98)
    print("AUDITED RESULTS: POST-QUANTUM CRYPTO-AGILITY BENCHMARK (REAL HARDWARE & STACK)")
    print("=" * 98)
    print(f"{'Algorithm':<14} {'Quantum-Safe':<14} {'Wire (B)':<10} {'TCP Chunks':<12} {'KeyGen':<14} {'Encaps':<14} {'Decaps'}")
    print("-" * 98)
    for name, m in results.items():
        q_safe = "YES (Immune)" if m['quantum_safe'] else "NO (Broken)"
        kg_str = f"{m['t_keygen_us']/1000.0:.2f} ms" if m['t_keygen_us'] > 1000 else f"{m['t_keygen_us']:.1f} us"
        en_str = f"{m['t_encaps_us']/1000.0:.2f} ms" if m['t_encaps_us'] > 1000 else f"{m['t_encaps_us']:.1f} us"
        de_str = f"{m['t_decaps_us']/1000.0:.2f} ms" if m['t_decaps_us'] > 1000 else f"{m['t_decaps_us']:.1f} us"
        print(f"{name:<14} {q_safe:<14} {m['total_wire']:<10} {m['tcp_chunks']:<12} {kg_str:<14} {en_str:<14} {de_str}")
    print("=" * 98)

    # -------------------------------------------------------------
    # Generate Publication Figure
    # -------------------------------------------------------------
    names = list(results.keys())
    pk_sizes = [results[n]['pk_bytes'] for n in names]
    ct_sizes = [results[n]['ct_bytes'] for n in names]
    t_kg_us = [results[n]['t_keygen_us'] for n in names]
    t_en_us = [results[n]['t_encaps_us'] for n in names]

    fig, (ax1, ax2, ax3) = plt.subplots(1, 3, figsize=(16, 5))

    # --- Plot 1: Key & Ciphertext Wire Sizes (Log Scale) ---
    x = np.arange(len(names))
    width = 0.35
    ax1.bar(x - width/2, pk_sizes, width, label='Public Key', color='royalblue', edgecolor='black')
    ax1.bar(x + width/2, ct_sizes, width, label='Ciphertext', color='darkorange', edgecolor='black')
    ax1.axhline(1500, color='red', ls='--', lw=1.5, label='Ethernet MTU (1500 B)')
    ax1.set_yscale('log')
    ax1.set_xticks(x)
    ax1.set_xticklabels(names, rotation=20, ha='right', fontsize=9)
    ax1.set_ylabel('Wire Size (Bytes, Log Scale)', fontsize=11)
    ax1.set_title('Payload Size vs. MTU Boundary', fontsize=12, fontweight='bold')
    ax1.legend(loc='upper left', fontsize=9)
    ax1.grid(True, which='both', ls=':', alpha=0.5)

    # --- Plot 2: KeyGen Latency (Log Scale, us) ---
    colors = ['gray', 'dimgray', 'teal', 'forestgreen', 'mediumseagreen']
    ax2.bar(names, t_kg_us, color=colors, edgecolor='black')
    ax2.set_yscale('log')
    ax2.set_xticks(range(len(names)))
    ax2.set_xticklabels(names, rotation=20, ha='right', fontsize=9)
    ax2.set_ylabel('KeyGen Latency (Microseconds, Log Scale)', fontsize=11)
    ax2.set_title('Key Generation Speed (Real C Implementations)', fontsize=12, fontweight='bold')
    ax2.grid(True, which='both', ls=':', alpha=0.5)

    # Annotate speedup
    ratio = results['RSA-2048']['t_keygen_us'] / results['ML-KEM-768']['t_keygen_us']
    ax2.annotate(f'ML-KEM is {ratio:.0f}x faster\nthan RSA-2048', 
                 xy=(3, results['ML-KEM-768']['t_keygen_us']),
                 xytext=(2.2, results['ML-KEM-768']['t_keygen_us'] * 40),
                 arrowprops=dict(arrowstyle='->', lw=1.5, color='darkgreen'),
                 fontweight='bold', fontsize=9, color='darkgreen')

    # --- Plot 3: Network Fragmentation Audit ---
    chunks = [results[n]['tcp_chunks'] for n in names]
    chunk_colors = ['navy' if c == 1 else 'crimson' for c in chunks]
    bars = ax3.bar(names, chunks, color=chunk_colors, edgecolor='black', width=0.5)
    ax3.set_yticks([1, 2, 3])
    ax3.set_yticklabels(['1 (Single Packet)', '2 (Fragmented)', '3 (Fragmented)'])
    ax3.set_xticks(range(len(names)))
    ax3.set_xticklabels(names, rotation=20, ha='right', fontsize=9)
    ax3.set_ylabel('TCP Segment Count (MSS = 1460 B)', fontsize=11)
    ax3.set_title('Real TCP Handshake Packet Fragmentation', fontsize=12, fontweight='bold')
    ax3.grid(True, ls=':', alpha=0.5)

    for bar, c in zip(bars, chunks):
        ax3.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.05, 
                 f"{c} segment" if c == 1 else f"{c} segments", 
                 ha='center', va='bottom', fontsize=9, fontweight='bold')

    plt.tight_layout()
    out_path = os.path.join(os.path.dirname(__file__), "fig_pqc_crypto_agility.png")
    plt.savefig(out_path, dpi=300)
    print(f"\nPublication figure saved to: {out_path}")

    return results

if __name__ == '__main__':
    benchmark_suite()
