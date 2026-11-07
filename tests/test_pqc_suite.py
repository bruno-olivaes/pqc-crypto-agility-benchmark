"""
Unit tests for Post-Quantum Cryptography & Classical Suite.
"""

import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest
from src.pqc_algorithms import MLKEM768, ClassicalRSA, ClassicalECDH, HybridPQC
from src.network_socket_audit import audit_tcp_transport, audit_tls13_handshake_framing

def test_mlkem768_key_exchange():
    pk, sk = MLKEM768.keygen()
    assert len(pk) == MLKEM768.PUBLIC_KEY_BYTES
    assert len(sk) == MLKEM768.SECRET_KEY_BYTES

    ct, ss_alice = MLKEM768.encaps(pk)
    assert len(ct) == MLKEM768.CIPHERTEXT_BYTES
    assert len(ss_alice) == 32

    ss_bob = MLKEM768.decaps(sk, ct)
    assert ss_alice == ss_bob

def test_classical_rsa_key_exchange():
    rsa = ClassicalRSA(key_size=2048)
    pub, priv = rsa.keygen()
    ct, ss_alice = rsa.encaps(pub)
    ss_bob = rsa.decaps(priv, ct)
    assert ss_alice == ss_bob

def test_classical_ecdh_key_exchange():
    ecdh = ClassicalECDH()
    pub_a, priv_a = ecdh.keygen()
    pub_b, priv_b = ecdh.keygen()

    ss_a = ecdh.compute_shared_secret(priv_a, pub_b)
    ss_b = ecdh.compute_shared_secret(priv_b, pub_a)
    assert ss_a == ss_b
    assert len(ss_a) == 32

def test_hybrid_pqc_key_exchange():
    hpk, hsk = HybridPQC.keygen()
    hct, ss_alice = HybridPQC.encaps(hpk)
    ss_bob = HybridPQC.decaps(hsk, hct)
    assert ss_alice == ss_bob
    assert len(ss_alice) == 32

def test_tcp_mtu_fragmentation_audit():
    # Small payload (under 1460 MSS) -> 1 chunk
    res_small = audit_tcp_transport(b"A" * 500, port=29020)
    assert res_small['total_bytes'] == 500
    assert res_small['chunks_count'] == 1
    assert not res_small['exceeds_single_mtu']

    # Large payload (ML-KEM wire size: 2272 bytes) -> 2 chunks
    res_large = audit_tcp_transport(b"B" * 2272, port=29021)
    assert res_large['total_bytes'] == 2272
    assert res_large['chunks_count'] >= 2
    assert res_large['exceeds_single_mtu']

    # Analytical TLS 1.3 handshake flight framing audit
    tls_ecdh = audit_tls13_handshake_framing(pk_bytes=65, ct_bytes=65)
    tls_mlkem = audit_tls13_handshake_framing(pk_bytes=1184, ct_bytes=1088)
    assert tls_ecdh['client_hello_segments'] == 1
    assert tls_mlkem['client_hello_bytes'] == 269 + 1184  # 1453 B (borderline 1 MSS)
    assert tls_mlkem['total_kem_wire_segments'] == 2
    assert tls_mlkem['fits_rfc6928_initcwnd_10'] is True
