"""
Post-Quantum Cryptography & Classical Algorithms Suite (NIST FIPS 203 / FIPS 204).

Implements:
1. ML-KEM-768 (Module-LWE, NIST FIPS 203): Post-Quantum Key Encapsulation via compiled C-extensions (pqcrypto).
2. ToyMLKEM768: Pure-Python educational reference implementation of Module-LWE math.
3. Classical RSA (RSA-2048 / RSA-4096): Factoring-based standard via OpenSSL.
4. Classical ECC (ECDH P-256): Elliptic Curve Diffie-Hellman via OpenSSL.
5. Hybrid KEM (ECDH + ML-KEM-768): The transition standard adopted by Google/Cloudflare/NIST.
"""

import os
import time
import hashlib
import numpy as np
from typing import Tuple, Dict, Any

# Cryptography primitives from hazmat for classical baselines (OpenSSL C backend)
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

try:
    import pqcrypto.kem.ml_kem_768 as c_mlkem
    HAS_PQCRYPTO = True
except ImportError:
    HAS_PQCRYPTO = False


# =====================================================================
# 1. NIST FIPS 203: ML-KEM-768 (Production C-Extension)
# =====================================================================
class MLKEM768:
    """
    Module-LWE Key Encapsulation Mechanism (NIST FIPS 203 standard, Kyber-768 parameter set).
    Backed by compiled C-extensions (pqcrypto) for production-grade latency auditing.
    """
    PUBLIC_KEY_BYTES = 1184
    SECRET_KEY_BYTES = 2400
    CIPHERTEXT_BYTES = 1088
    SHARED_SECRET_BYTES = 32

    @classmethod
    def keygen(cls) -> Tuple[bytes, bytes]:
        """Generates ML-KEM-768 public key (1184 bytes) and secret key (2400 bytes)."""
        if HAS_PQCRYPTO:
            return c_mlkem.keygen()
        # Fallback to educational implementation if C extension missing
        pk_dict, sk_dict = ToyMLKEM768.keygen()
        return pk_dict, sk_dict

    @classmethod
    def encaps(cls, pk) -> Tuple[bytes, bytes]:
        """Encapsulates a 32-byte shared secret against the recipient's public key."""
        if HAS_PQCRYPTO:
            return c_mlkem.encaps(pk)
        return ToyMLKEM768.encaps(pk)

    @classmethod
    def decaps(cls, sk, ct) -> bytes:
        """Decapsulates the shared secret using recipient's secret key."""
        if HAS_PQCRYPTO:
            return c_mlkem.decaps(sk, ct)
        return ToyMLKEM768.decaps(sk, ct)


# =====================================================================
# 2. EDUCATIONAL PURE-PYTHON REFERENCE: ToyMLKEM768
# =====================================================================
class ToyMLKEM768:
    """
    Pure-Python educational implementation of Module-LWE polynomial arithmetic.
    Notice: Interpreted Python polynomial convolutions are ~1000x slower than compiled C/AVX2.
    Provided solely for inspectability and algebraic demonstration.
    """
    Q = 3329
    N = 256
    K = 3
    ETA = 2

    @staticmethod
    def _sample_poly_cbd(eta: int = 2) -> np.ndarray:
        a = np.random.binomial(eta, 0.5, size=256)
        b = np.random.binomial(eta, 0.5, size=256)
        return (a - b) % 3329

    @staticmethod
    def _poly_mul_mod(p1: np.ndarray, p2: np.ndarray) -> np.ndarray:
        conv = np.convolve(p1, p2)
        res = np.zeros(256, dtype=np.int64)
        for i, val in enumerate(conv):
            if i < 256:
                res[i] = (res[i] + val) % 3329
            else:
                res[i - 256] = (res[i - 256] - val) % 3329
        return res % 3329

    @classmethod
    def keygen(cls) -> Tuple[Dict, Dict]:
        A = [[np.random.randint(0, cls.Q, size=cls.N) for _ in range(cls.K)] for _ in range(cls.K)]
        s = [cls._sample_poly_cbd(cls.ETA) for _ in range(cls.K)]
        e = [cls._sample_poly_cbd(cls.ETA) for _ in range(cls.K)]
        t = [np.zeros(cls.N, dtype=np.int64) for _ in range(cls.K)]
        for i in range(cls.K):
            acc = np.zeros(cls.N, dtype=np.int64)
            for j in range(cls.K):
                acc = (acc + cls._poly_mul_mod(A[i][j], s[j])) % cls.Q
            t[i] = (acc + e[i]) % cls.Q

        pk = {'t': t, 'A': A, 'size_bytes': 1184}
        sk = {'s': s, 'pk': pk, 'size_bytes': 2400}
        return pk, sk

    @classmethod
    def encaps(cls, pk: Dict) -> Tuple[Dict, bytes]:
        r = [cls._sample_poly_cbd(cls.ETA) for _ in range(cls.K)]
        e1 = [cls._sample_poly_cbd(cls.ETA) for _ in range(cls.K)]
        e2 = cls._sample_poly_cbd(cls.ETA)

        u = [np.zeros(cls.N, dtype=np.int64) for _ in range(cls.K)]
        for i in range(cls.K):
            acc = np.zeros(cls.N, dtype=np.int64)
            for j in range(cls.K):
                acc = (acc + cls._poly_mul_mod(pk['A'][j][i], r[j])) % cls.Q
            u[i] = (acc + e1[i]) % cls.Q

        v_acc = np.zeros(cls.N, dtype=np.int64)
        for i in range(cls.K):
            v_acc = (v_acc + cls._poly_mul_mod(pk['t'][i], r[i])) % cls.Q

        m_bytes = os.urandom(32)
        m_bits = np.unpackbits(np.frombuffer(m_bytes, dtype=np.uint8)).astype(np.int64)
        m_poly = m_bits * (cls.Q // 2)
        v = (v_acc + e2 + m_poly) % cls.Q

        shared_secret = hashlib.sha256(m_bytes).digest()
        ct = {'u': u, 'v': v, 'size_bytes': 1088}
        return ct, shared_secret

    @classmethod
    def decaps(cls, sk: Dict, ct: Dict) -> bytes:
        u = ct['u']
        v = ct['v']
        s = sk['s']

        su_acc = np.zeros(cls.N, dtype=np.int64)
        for i in range(cls.K):
            su_acc = (su_acc + cls._poly_mul_mod(s[i], u[i])) % cls.Q

        diff = (v - su_acc) % cls.Q
        recovered_bits = np.zeros(cls.N, dtype=np.uint8)
        for i in range(cls.N):
            val = diff[i]
            dist_half = min(abs(val - cls.Q // 2), abs(val - (cls.Q // 2 + cls.Q)))
            dist_zero = min(val, cls.Q - val)
            recovered_bits[i] = 1 if dist_half < dist_zero else 0

        recovered_bytes = np.packbits(recovered_bits).tobytes()
        return hashlib.sha256(recovered_bytes).digest()


# =====================================================================
# 3. CLASSICAL RSA-2048 & RSA-4096 (OpenSSL C backend)
# =====================================================================
class ClassicalRSA:
    def __init__(self, key_size: int = 2048):
        self.key_size = key_size

    def keygen(self) -> Tuple[rsa.RSAPublicKey, rsa.RSAPrivateKey]:
        priv = rsa.generate_private_key(public_exponent=65537, key_size=self.key_size)
        pub = priv.public_key()
        return pub, priv

    def encaps(self, pub: rsa.RSAPublicKey) -> Tuple[bytes, bytes]:
        sym_key = os.urandom(32)
        ciphertext = pub.encrypt(
            sym_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext, sym_key

    def decaps(self, priv: rsa.RSAPrivateKey, ciphertext: bytes) -> bytes:
        recovered = priv.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return recovered


# =====================================================================
# 4. CLASSICAL ECC (ECDH P-256) (OpenSSL C backend)
# =====================================================================
class ClassicalECDH:
    def keygen(self) -> Tuple[ec.EllipticCurvePublicKey, ec.EllipticCurvePrivateKey]:
        priv = ec.generate_private_key(ec.SECP256R1())
        pub = priv.public_key()
        return pub, priv

    def compute_shared_secret(self, priv: ec.EllipticCurvePrivateKey, peer_pub: ec.EllipticCurvePublicKey) -> bytes:
        raw_secret = priv.exchange(ec.ECDH(), peer_pub)
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"pqc-benchmark-ecdh"
        ).derive(raw_secret)


# =====================================================================
# 5. HYBRID POST-QUANTUM KEM (ECDH P-256 + ML-KEM-768)
# =====================================================================
class HybridPQC:
    """
    Dual-layer Hybrid KEM: Combines classical ECDH P-256 with Post-Quantum ML-KEM-768.
    K = HKDF(SS_ECDH || SS_MLKEM).
    """
    @classmethod
    def keygen(cls) -> Tuple[Dict, Dict]:
        ecdh = ClassicalECDH()
        ec_pub, ec_priv = ecdh.keygen()
        ml_pub, ml_priv = MLKEM768.keygen()

        pk = {
            'ec_pub': ec_pub,
            'ml_pub': ml_pub,
            'size_bytes': 65 + MLKEM768.PUBLIC_KEY_BYTES
        }
        sk = {
            'ec_priv': ec_priv,
            'ml_priv': ml_priv
        }
        return pk, sk

    @classmethod
    def encaps(cls, pk: Dict) -> Tuple[Dict, bytes]:
        ecdh = ClassicalECDH()
        ephem_pub, ephem_priv = ecdh.keygen()
        ss_ec = ecdh.compute_shared_secret(ephem_priv, pk['ec_pub'])

        ml_ct, ss_ml = MLKEM768.encaps(pk['ml_pub'])

        # Derive combined 32-byte shared secret
        combined = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"hybrid-pqc-x25519-mlkem768"
        ).derive(ss_ec + ss_ml)

        ct = {
            'ephem_pub': ephem_pub,
            'ml_ct': ml_ct,
            'size_bytes': 65 + MLKEM768.CIPHERTEXT_BYTES
        }
        return ct, combined

    @classmethod
    def decaps(cls, sk: Dict, ct: Dict) -> bytes:
        ecdh = ClassicalECDH()
        ss_ec = ecdh.compute_shared_secret(sk['ec_priv'], ct['ephem_pub'])
        ss_ml = MLKEM768.decaps(sk['ml_priv'], ct['ml_ct'])

        combined = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"hybrid-pqc-x25519-mlkem768"
        ).derive(ss_ec + ss_ml)
        return combined
