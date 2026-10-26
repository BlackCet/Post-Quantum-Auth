import json
import socket
import ssl
import time
from typing import Any


def create_client_context(ca_file: str, cert_file: str, key_file: str) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile=ca_file)
    context.load_cert_chain(certfile=cert_file, keyfile=key_file)
    context.set_alpn_protocols(["http/1.1"])
    return context


def _flush(
    sock: socket.socket,
    outgoing: ssl.MemoryBIO,
    counters: dict[str, int],
    phase: str,
) -> None:
    while outgoing.pending:
        encrypted = outgoing.read()
        sock.sendall(encrypted)
        key = f"{phase}_bytes_sent"
        counters[key] += len(encrypted)


def _receive(
    sock: socket.socket,
    incoming: ssl.MemoryBIO,
    counters: dict[str, int],
    phase: str,
) -> None:
    encrypted = sock.recv(65536)
    if not encrypted:
        raise ConnectionError("Gateway closed the connection before completing TLS/HTTP.")
    incoming.write(encrypted)
    key = f"{phase}_bytes_received"
    counters[key] += len(encrypted)


def _read_http_response(
    tls_socket: ssl.SSLObject,
    sock: socket.socket,
    incoming: ssl.MemoryBIO,
    outgoing: ssl.MemoryBIO,
    counters: dict[str, int],
) -> tuple[int, bytes, bytes]:
    response = bytearray()
    expected_length: int | None = None

    while expected_length is None or len(response) < expected_length:
        try:
            chunk = tls_socket.read(65536)
        except ssl.SSLWantReadError:
            _flush(sock, outgoing, counters, "application")
            _receive(sock, incoming, counters, "application")
            continue
        except ssl.SSLWantWriteError:
            _flush(sock, outgoing, counters, "application")
            continue

        if not chunk:
            raise ConnectionError("Gateway returned an empty TLS application response.")
        response.extend(chunk)

        header_end = response.find(b"\r\n\r\n")
        if header_end >= 0 and expected_length is None:
            headers = bytes(response[:header_end]).split(b"\r\n")
            status_fields = headers[0].split()
            if len(status_fields) < 2:
                raise ValueError("Gateway returned an invalid HTTP status line.")
            status_code = int(status_fields[1])
            parsed_headers = {}
            for line in headers[1:]:
                if b":" in line:
                    name, value = line.split(b":", 1)
                    parsed_headers[name.strip().lower()] = value.strip()
            content_length = parsed_headers.get(b"content-length")
            if content_length is None:
                raise ValueError("Gateway response did not include Content-Length.")
            expected_length = header_end + 4 + int(content_length)

    header_end = response.find(b"\r\n\r\n")
    body = bytes(response[header_end + 4:expected_length])
    headers = bytes(response[:header_end])
    return status_code, headers, body


def perform_tls_post(
    *,
    host: str,
    port: int,
    server_name: str,
    path: str,
    payload: bytes,
    context: ssl.SSLContext,
    session: ssl.SSLSession | None = None,
    timeout_seconds: float = 30,
) -> dict[str, Any]:
    counters = {
        "handshake_bytes_sent": 0,
        "handshake_bytes_received": 0,
        "application_bytes_sent": 0,
        "application_bytes_received": 0,
    }
    connect_started = time.perf_counter()
    sock = socket.create_connection((host, port), timeout=timeout_seconds)
    connect_ms = (time.perf_counter() - connect_started) * 1000
    sock.settimeout(timeout_seconds)

    incoming = ssl.MemoryBIO()
    outgoing = ssl.MemoryBIO()
    tls_socket = context.wrap_bio(
        incoming,
        outgoing,
        server_side=False,
        server_hostname=server_name,
        session=session,
    )

    handshake_started = time.perf_counter()
    try:
        while True:
            try:
                tls_socket.do_handshake()
                _flush(sock, outgoing, counters, "handshake")
                break
            except ssl.SSLWantReadError:
                _flush(sock, outgoing, counters, "handshake")
                _receive(sock, incoming, counters, "handshake")
            except ssl.SSLWantWriteError:
                _flush(sock, outgoing, counters, "handshake")
        handshake_ms = (time.perf_counter() - handshake_started) * 1000

        request_bytes = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {server_name}\r\n"
            f"Content-Type: {'application/json' if path.endswith('/pqc') else 'application/octet-stream'}\r\n"
            f"Content-Length: {len(payload)}\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii") + payload
        request_started = time.perf_counter()
        view = memoryview(request_bytes)
        while view:
            try:
                written = tls_socket.write(view)
                view = view[written:]
                _flush(sock, outgoing, counters, "application")
            except ssl.SSLWantWriteError:
                _flush(sock, outgoing, counters, "application")
            except ssl.SSLWantReadError:
                _flush(sock, outgoing, counters, "application")
                _receive(sock, incoming, counters, "application")

        status_code, response_headers, response_body = _read_http_response(
            tls_socket,
            sock,
            incoming,
            outgoing,
            counters,
        )
        request_rtt_ms = (time.perf_counter() - request_started) * 1000
        _flush(sock, outgoing, counters, "application")

        parsed_headers = {}
        for line in response_headers.split(b"\r\n")[1:]:
            if b":" in line:
                name, value = line.split(b":", 1)
                parsed_headers[name.strip().lower()] = value.strip()

        result = {
            **counters,
            "tcp_connect_ms": connect_ms,
            "handshake_ms": handshake_ms,
            "request_rtt_ms": request_rtt_ms,
            "status_code": status_code,
            "session_reused": tls_socket.session_reused,
            "session": tls_socket.session,
            "tls_version": tls_socket.version(),
            "cipher": tls_socket.cipher()[0] if tls_socket.cipher() else None,
            "response_body": response_body,
            "response_json": json.loads(response_body),
            "gateway_instance": parsed_headers.get(b"x-gateway-instance", b"").decode(),
            "gateway_cpu_time_ms": float(parsed_headers.get(b"x-gateway-cpu-time-ms", b"0")),
            "gateway_memory_rss_bytes": int(
                parsed_headers.get(b"x-gateway-memory-rss-bytes", b"0")
            ),
            "gateway_processing_time_ms": float(
                parsed_headers.get(b"x-gateway-processing-time-ms", b"0")
            ),
            "http_request_bytes": len(request_bytes),
            "http_response_bytes": len(response_headers) + 4 + len(response_body),
        }
        return result
    finally:
        sock.close()
