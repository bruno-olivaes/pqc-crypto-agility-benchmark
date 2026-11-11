# pqc-crypto-agility-benchmark: Post-Quantum Cryptography & Crypto-Agility Audit Suite (NIST FIPS 203)

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.24121695.svg)](https://doi.org/10.5281/zenodo.24121695)
[![Standard: NIST FIPS 203](https://img.shields.io/badge/NIST-FIPS%20203%20(ML--KEM)-blue.svg)](https://csrc.nist.gov/pubs/fips/203/final)
[![Paper PDF](https://img.shields.io/badge/Paper-PDF_Manuscript-red.svg)](manuscript/main.pdf)
[![Quantum Safe](https://img.shields.io/badge/Security-Quantum--Safe-green.svg)](https://csrc.nist.gov/projects/post-quantum-cryptography)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

An open-source cryptographic audit and benchmarking framework evaluating the **transition from classical public-key cryptography (RSA, ECC) to the finalized Post-Quantum Cryptography standards (ML-KEM-768 / CRYSTALS-Kyber, NIST FIPS 203)** and **Hybrid KEM (ECDH + ML-KEM)**.

Backed by production C-extensions (`pqcrypto` and OpenSSL via `cryptography`), combining an analytical **RFC 8446 (TLS 1.3) handshake flight / TCP MSS & `initcwnd` model** with a live TCP socket MSS reception buffer test (`recv(1460)`).

---

## 1. The Real-World Engineering Problem

Traditional asymmetric encryption protecting the global financial system (PIX, SWIFT, TLS 1.3) relies on the hardness of integer factorization (RSA) or the discrete logarithm on elliptic curves (ECC). A fault-tolerant quantum computer running **Shor's Algorithm** solves both in polynomial time $\mathcal{O}((\log N)^3)$, rendering classical asymmetric cryptography vulnerable to "harvest now, decrypt later" attacks.

To address this, NIST finalized the primary PQC standards in August 2024:
* **FIPS 203 (ML-KEM):** Module-Lattice-Based Key-Encapsulation Mechanism.
* **FIPS 204 (ML-DSA):** Module-Lattice-Based Digital Signature Algorithm.

### Computational Speed vs. Wire Payload & TLS 1.3 Handshake Framing
A common misconception is that lattice-based cryptography is computationally slower than classical RSA. As shown in our empirical benchmark:
* **Computational Speed:** ML-KEM-768 key generation takes **~41 microseconds** ($\mu\mathrm{s}$), making it **~740x faster than RSA-2048 key generation (~30.5 ms)** and competitive with ECDH P-256 (~16.6 $\mu\mathrm{s}$).
* **Network Wire Payload:** Classical ECDH P-256 public keys and ciphertexts require only **65 bytes** each (130 B total). In contrast, ML-KEM-768 requires a **1,184-byte public key** (`ClientHello` `KeyShare`) and a **1,088-byte ciphertext** (`ServerHello` `KeyShare`), totaling **2,272 bytes** (and **2,402 bytes** for Hybrid X25519/P-256 + ML-KEM-768).
* **TCP MSS Segmentation vs. Congestion Window (`initcwnd`):**
  * Over standard Ethernet (**MTU = 1,500 bytes**, IPv4/TCP **MSS = 1,460 bytes**), the combined KEM wire payload (2,272 B for ML-KEM-768; 2,402 B for Hybrid PQC) spans **2 TCP segments**, and a full Hybrid `ClientHello` (~269 B base + 1,249 B KeyShare = **1,518 B**) crosses the 1-MSS boundary into 2 TCP segments.
  * *Methodological Note:* On OS loopback (`127.0.0.1`), the kernel loopback interface MTU is 65,535 B; our live socket audit (`audit_tcp_transport`) uses `recv(1460)` to emulate a 1,460-byte MSS reception buffer or middlebox frame limit, while `audit_tls13_handshake_framing` computes the exact RFC 8446 TLS 1.3 flight sizes and TCP segment counts.
  * *Modern TCP Context (RFC 6928):* While multi-segment `ClientHello`/`ServerHello` flights fit comfortably inside the modern TCP initial congestion window (`initcwnd = 10` segments $\approx 14.6\text{ KB}$) without adding an extra round-trip time (RTT) on clean links, crossing the 1-MSS boundary increases head-of-line blocking sensitivity on lossy links and can trigger failures in legacy middleboxes/firewalls that enforce single-packet `ClientHello` inspection buffers.

---

## 2. Audited Empirical Benchmark Results

Benchmarked on production hardware using compiled C-extensions (`pqcrypto` and OpenSSL `cryptography.hazmat`) across 100 independent iterations for fast schemes and 15 iterations for RSA:

| Algorithm | Quantum-Safe? | Public Key | Ciphertext | Total KEM Wire | KeyGen | Encaps | Decaps | KEM Wire Segments (1460 B MSS) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **RSA-2048** | **NO (Broken)** | 270 B | 256 B | 526 B | 30.49 ms | 251.2 $\mu\mathrm{s}$ | 765.0 $\mu\mathrm{s}$ | **1 segment** (Fits single MSS) |
| **RSA-4096** | **NO (Broken)** | 526 B | 512 B | 1,038 B | 337.86 ms | 127.2 $\mu\mathrm{s}$ | 3.76 ms | **1 segment** (Fits single MSS) |
| **ECDH P-256** | **NO (Broken)** | 65 B | 65 B | 130 B | 16.6 $\mu\mathrm{s}$ | 90.3 $\mu\mathrm{s}$ | 49.0 $\mu\mathrm{s}$ | **1 segment** (Negligible wire) |
| **ML-KEM-768** | **YES (Immune)** | **1,184 B** | **1,088 B** | **2,272 B** | **41.3 $\mu\mathrm{s}$** | **46.7 $\mu\mathrm{s}$** | **63.0 $\mu\mathrm{s}$** | **2 segments** (> 1460 B MSS) |
| **Hybrid PQC** | **YES (Immune)** | **1,249 B** | **1,153 B** | **2,402 B** | **58.9 $\mu\mathrm{s}$** | **119.3 $\mu\mathrm{s}$** | **117.5 $\mu\mathrm{s}$** | **2 segments** (`ClientHello` > 1 MSS) |

---

## 3. Visual Dashboard

The benchmark suite generates a 3-panel figure (`benchmarks/fig_pqc_crypto_agility.png`):
1. **Wire Size vs. MTU Threshold (Log Scale):** Shows exact public key and ciphertext byte sizes relative to the 1,500-byte Ethernet MTU.
2. **KeyGen Latency (Log Scale, $\mu\mathrm{s}$):** Quantifies ML-KEM's ~740x computational advantage over RSA-2048.
3. **TCP MSS Segment Count:** Compares 1,460-byte MSS segment counts across classical, PQC, and hybrid schemes.

---

## 4. Quickstart & Testing

```bash
# Install dependencies (requires precompiled pqcrypto wheel or C compiler)
pip install cryptography numpy matplotlib pytest pqcrypto

# Run unit test suite
pytest tests/

# Run the master audit and regenerate benchmark figures
python benchmarks/run_pqc_agility_benchmark.py
```

---

## 5. Repository Architecture

```
pqc-crypto-agility-benchmark/
├── src/
│   ├── pqc_algorithms.py           # Production C-backed ML-KEM-768, RSA, ECDH, Hybrid PQC + Toy Reference
│   ├── network_socket_audit.py     # Analytical TLS 1.3 flight framing + TCP socket 1460-B MSS buffer audit
│   └── __init__.py
├── benchmarks/
│   ├── run_pqc_agility_benchmark.py # Master benchmark & plotting script
│   └── fig_pqc_crypto_agility.png   # Audited 3-panel comparison figure
├── tests/
│   └── test_pqc_suite.py           # Pytest unit tests for all key exchanges, TLS 1.3 framing, and socket audits
└── README.md
```

---

## License

This project is licensed under the MIT License - see the LICENSE file for details.
