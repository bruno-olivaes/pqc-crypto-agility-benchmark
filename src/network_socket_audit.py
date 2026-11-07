"""
Network Socket & TLS 1.3 MTU Framing Audit for PQC Handshakes.

1. Measures actual TCP socket transport of cryptographic payloads with
   1460-byte user-space MSS reception (`recv(1460)`).
2. Computes exact analytical RFC 8446 (TLS 1.3) `ClientHello` and `ServerHello`
   handshake flight sizes, Ethernet TCP Maximum Segment Size (MSS = 1460 B)
   segment counts, and RFC 6928 initial congestion window (`initcwnd`) impact.
"""

import math
import socket
import threading
import time
from typing import Dict


def audit_tls13_handshake_framing(
    pk_bytes: int,
    ct_bytes: int,
    sig_bytes: int = 64,
    cert_chain_bytes: int = 2400,
    mss_bytes: int = 1460,
) -> Dict:
    """
    Analytical RFC 8446 (TLS 1.3) handshake flight framing model over IPv4/TCP
    with standard 1500-byte Ethernet MTU (MSS = 1460 bytes).

    - Flight 1 (Client -> Server): TLS Record Header (5 B) + Handshake Header (4 B)
      + ClientHello base extensions (~260 B) + KeyShare Extension (`pk_bytes`).
    - Flight 2 (Server -> Client): ServerHello base (~150 B) + KeyShare (`ct_bytes`)
      + EncryptedExtensions/Finished (~120 B) + Certificate (`cert_chain_bytes`)
      + CertificateVerify (`sig_bytes`).
    """
    client_hello_bytes = 269 + pk_bytes
    server_hello_only_bytes = 159 + ct_bytes
    server_full_flight_bytes = server_hello_only_bytes + 120 + cert_chain_bytes + sig_bytes

    client_hello_segments = math.ceil(client_hello_bytes / mss_bytes)
    server_hello_segments = math.ceil(server_hello_only_bytes / mss_bytes)
    server_flight_segments = math.ceil(server_flight_bytes := server_full_flight_bytes / mss_bytes)
    total_kem_wire_segments = math.ceil((pk_bytes + ct_bytes) / mss_bytes)

    return {
        'pk_bytes': pk_bytes,
        'ct_bytes': ct_bytes,
        'client_hello_bytes': client_hello_bytes,
        'client_hello_segments': client_hello_segments,
        'client_hello_exceeds_1_mss': client_hello_bytes > mss_bytes,
        'server_hello_only_bytes': server_hello_only_bytes,
        'server_hello_segments': server_hello_segments,
        'server_full_flight_bytes': server_full_flight_bytes,
        'server_flight_segments': math.ceil(server_full_flight_bytes / mss_bytes),
        'total_kem_wire_segments': total_kem_wire_segments,
        'exceeds_legacy_initcwnd_2': client_hello_segments > 1 or server_hello_segments > 1,
        'fits_rfc6928_initcwnd_10': math.ceil(server_full_flight_bytes / mss_bytes) <= 10,
    }


def audit_tcp_transport(payload_bytes: bytes, port: int = 28456) -> Dict:
    """
    Sends payload over a real TCP loopback socket with 1460-byte user-space
    MSS reception buffer (`recv(1460)`), tracking the number of received chunks
    and transmission time. Note: on OS loopback (MTU = 65535), kernel TCP
    segmentation does not occur at 1500 B; `recv(1460)` emulates an application
    or middlebox framing buffer bounded by standard Ethernet MSS = 1460 bytes.
    """
    received_chunks = []
    received_total = 0
    done_event = threading.Event()

    def server_thread():
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind(('127.0.0.1', port))
        server_sock.listen(1)
        done_event.set()

        conn, _ = server_sock.accept()
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        nonlocal received_total
        while True:
            # 1460 bytes emulates standard Maximum Segment Size (MSS) for Ethernet MTU = 1500
            chunk = conn.recv(1460)
            if not chunk:
                break
            received_chunks.append(len(chunk))
            received_total += len(chunk)
        conn.close()
        server_sock.close()

    srv = threading.Thread(target=server_thread, daemon=True)
    srv.start()
    done_event.wait(timeout=2.0)

    # Client socket
    client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_sock.connect(('127.0.0.1', port))
    client_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    t0 = time.perf_counter()
    client_sock.sendall(payload_bytes)
    client_sock.shutdown(socket.SHUT_WR)
    srv.join(timeout=2.0)
    client_sock.close()
    t1 = time.perf_counter()

    transfer_time_us = (t1 - t0) * 1e6

    return {
        'total_bytes': received_total,
        'chunks_count': len(received_chunks),
        'chunk_sizes': received_chunks,
        'transfer_time_us': transfer_time_us,
        'exceeds_single_mtu': received_total > 1460
    }
