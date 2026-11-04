# pqc-crypto-agility-benchmark: Post-Quantum Cryptography & Crypto-Agility Audit Suite (NIST FIPS 203)

[![Standard: NIST FIPS 203](https://img.shields.io/badge/NIST-FIPS%20203%20(ML--KEM)-blue.svg)](https://csrc.nist.gov/pubs/fips/203/final)
[![Quantum Safe](https://img.shields.io/badge/Security-Quantum--Safe-green.svg)](https://csrc.nist.gov/projects/post-quantum-cryptography)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

An open-source cryptographic audit and benchmarking framework evaluating the **transition from classical public-key cryptography (RSA, ECC) to the new Post-Quantum Cryptography standards (ML-KEM-768 / CRYSTALS-Kyber, NIST FIPS 203)** and **Hybrid KEM (ECDH + ML-KEM)**.

---

## 1. The Real-World Problem: The "Harvest Now, Decrypt Later" Threat

Traditional asymmetric encryption protecting the global financial system (PIX, SWIFT, TLS 1.3, SSL) relies on the hardness of integer factorization (RSA) or the discrete logarithm on elliptic curves (ECC). A fault-tolerant quantum computer running **Shor's Algorithm** solves both in polynomial time $\mathcal{O}((\log N)^3)$, rendering current encryption obsolete.

To address this, the **National Institute of Standards and Technology (NIST)** officially finalized the first Post-Quantum Cryptography standards in August 2024:
* **FIPS 203 (ML-KEM):** Module-Lattice-Based Key-Encapsulation Mechanism (formerly CRYSTALS-Kyber).
* **FIPS 204 (ML-DSA):** Module-Lattice-Based Digital Signature Algorithm (formerly CRYSTALS-Dilithium).

### The Engineering Challenge: Wire Size & Network MTU
While quantum-safe, lattice-based cryptography introduces significant payload expansion:
* Classical ECDH P-256 uses a **65-byte** public key.
* **ML-KEM-768** requires a **1,184-byte** public key and a **1,088-byte** ciphertext.
* The total handshake payload (**2,272 bytes**) exceeds the standard Ethernet **Maximum Transmission Unit (MTU = 1,500 bytes)**, inducing TCP packet fragmentation and latency penalties in high-frequency trading and low-bandwidth connections.

---

## 2. Empirical Benchmark Results (NIST FIPS 203 Audit)

Benchmarked on modern hardware across 15 independent iterations per algorithm:

| Algorithm | Quantum-Safe? | Public Key Size | Ciphertext Size | Total Wire Size | KeyGen Latency | Encaps / Encrypt | Decaps / Decrypt | Network Risk |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **RSA-2048** | **NO (Broken)** | 270 B | 256 B | 526 B | 48.54 ms | 0.22 ms | 0.95 ms | Low (Fits MTU) |
| **RSA-4096** | **NO (Broken)** | 526 B | 512 B | 1,038 B | 777.83 ms | 0.20 ms | 9.95 ms | Low (Fits MTU) |
| **ECDH P-256** | **NO (Broken)** | 65 B | 65 B | 130 B | 0.31 ms | 2.70 ms | 3.22 ms | Negligible |
| **ML-KEM-768** | **YES (Immune)** | **1,184 B** | **1,088 B** | **2,272 B** | 41.44 ms | 20.16 ms | 4.85 ms | **Exceeds 1500 B MTU** |
| **Hybrid PQC** | **YES (Immune)** | **1,249 B** | **1,153 B** | **2,402 B** | 2.50 ms | 3.19 ms | 0.95 ms | **Exceeds 1500 B MTU** |

---

## 3. Visualizations

The generated benchmark visualization (`benchmarks/fig_pqc_crypto_agility.png`) provides:
1. **Wire Size Comparison (Log Scale):** Demonstrates key and ciphertext growth relative to the 1,500-byte MTU threshold.
2. **Cryptographic Latency:** Compares KeyGen, Encapsulation, and Decapsulation runtimes.
3. **Quantum Security & Network Risk Matrix:** Highlights algorithms that are both quantum-safe and identify infrastructure bottlenecks requiring jumbo frames or optimized TCP stacks.

---

## 4. Quickstart Guide

```bash
# Clone the repository
git clone https://github.com/bruno-olivaes/pqc-crypto-agility-benchmark.git
cd pqc-crypto-agility-benchmark

# Run the complete Post-Quantum Cryptographic Audit
python benchmarks/run_pqc_agility_benchmark.py
```

---

## 5. Repository Architecture

```
pqc-crypto-agility-benchmark/
├── src/
│   ├── pqc_algorithms.py           # ML-KEM-768, RSA, ECDH, and Hybrid PQC implementations
│   └── __init__.py
├── benchmarks/
│   ├── run_pqc_agility_benchmark.py # End-to-end audit and benchmarking suite
│   └── fig_pqc_crypto_agility.png  # Generated 3-panel publication comparison figure
└── README.md
```
