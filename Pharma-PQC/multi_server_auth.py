"""Post-quantum mutual-authentication prototype for server-to-server links."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import math
import secrets
import statistics
import threading
import time
import urllib.request
from dataclasses import dataclass
from typing import Any

import oqs
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from flask import Flask, jsonify, request
from werkzeug.serving import BaseWSGIServer, make_server


PROTOCOL = "pqa-multiserver-v1"
PENDING_TTL_SECONDS = 120
MAX_PENDING_HANDSHAKES = 4096


class AuthenticationError(ValueError):
    """Raised when a peer or handshake message fails authentication."""


@dataclass(frozen=True)
class PeerIdentity:
    peer_id: str
    signing_public_key: bytes
    signing_secret_key: bytes


@dataclass(frozen=True)
class AuthenticatedSession:
    local_peer_id: str
    remote_peer_id: str
    session_id: str
    session_key: bytes


@dataclass
class PendingHandshake:
    peer_id: str
    hello: dict[str, Any]
    challenge: dict[str, Any]
    kem_secret_key: bytes
    shared_secret_to_initiator: bytes
    created_at: float


def create_identity(peer_id: str) -> PeerIdentity:
    if not peer_id or len(peer_id) > 128:
        raise ValueError("peer_id must contain 1 to 128 characters")
    with oqs.Signature("ML-DSA-65") as signer:
        public_key = signer.generate_keypair()
        secret_key = signer.export_secret_key()
    return PeerIdentity(peer_id, public_key, secret_key)


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sign(identity: PeerIdentity, value: Any) -> str:
    with oqs.Signature("ML-DSA-65", secret_key=identity.signing_secret_key) as signer:
        return signer.sign(_canonical_bytes(value)).hex()


def _verify(public_key: bytes, value: Any, signature_hex: str) -> bool:
    if not isinstance(signature_hex, str):
        raise AuthenticationError("signature must be a hexadecimal string")
    try:
        signature = bytes.fromhex(signature_hex)
    except ValueError as exc:
        raise AuthenticationError("signature is not valid hexadecimal") from exc
    with oqs.Signature("ML-DSA-65") as verifier:
        return verifier.verify(_canonical_bytes(value), signature, public_key)


def _decode_hex(value: Any, field: str, expected_size: int | None = None) -> bytes:
    if not isinstance(value, str):
        raise AuthenticationError(f"{field} must be a hexadecimal string")
    try:
        decoded = bytes.fromhex(value)
    except ValueError as exc:
        raise AuthenticationError(f"{field} is not valid hexadecimal") from exc
    if expected_size is not None and len(decoded) != expected_size:
        raise AuthenticationError(f"{field} has an invalid length")
    return decoded


def _post_json(url: str, body: dict[str, Any], timeout: float) -> dict[str, Any]:
    request_body = _canonical_bytes(body)
    http_request = urllib.request.Request(
        url,
        data=request_body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(http_request, timeout=timeout) as response:
        parsed = json.loads(response.read())
    if not isinstance(parsed, dict):
        raise AuthenticationError("peer response must be a JSON object")
    return parsed


def _http_round_trip_ms(base_url: str, timeout: float = 10) -> float:
    started_at = time.perf_counter()
    with urllib.request.urlopen(
        f"{base_url.rstrip('/')}/health",
        timeout=timeout,
    ) as response:
        health = json.loads(response.read())
    elapsed_ms = (time.perf_counter() - started_at) * 1000
    if not isinstance(health, dict) or health.get("status") != "ok":
        raise AuthenticationError("peer health check returned an invalid response")
    return elapsed_ms


def _latency_summary(samples: list[float]) -> tuple[float, float]:
    if not samples:
        raise ValueError("latency summary requires at least one sample")
    ordered = sorted(samples)
    p95_index = max(0, math.ceil(0.95 * len(ordered)) - 1)
    return statistics.median(ordered), ordered[p95_index]


def _signed_fields(message: dict[str, Any], signature_field: str = "signature") -> dict[str, Any]:
    return {key: value for key, value in message.items() if key != signature_field}


def _transcript(
    hello: dict[str, Any],
    challenge: dict[str, Any],
    finish: dict[str, Any],
) -> dict[str, Any]:
    return {
        "protocol": PROTOCOL,
        "hello": hello,
        "challenge": challenge,
        "finish": finish,
    }


def _derive_session_key(
    shared_secret_to_initiator: bytes,
    shared_secret_to_responder: bytes,
    transcript: dict[str, Any],
) -> tuple[bytes, bytes]:
    transcript_hash = hashlib.sha256(_canonical_bytes(transcript)).digest()
    session_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=transcript_hash,
        info=PROTOCOL.encode("ascii"),
    ).derive(shared_secret_to_initiator + shared_secret_to_responder)
    return session_key, transcript_hash


class PeerAuthService:
    def __init__(self, identity: PeerIdentity, trusted_peers: dict[str, bytes]):
        if identity.peer_id not in trusted_peers:
            raise ValueError("the trust directory must include the service identity")
        if trusted_peers[identity.peer_id] != identity.signing_public_key:
            raise ValueError("the service identity does not match its trust-directory key")
        self.identity = identity
        self.trusted_peers = dict(trusted_peers)
        self.pending: dict[str, PendingHandshake] = {}
        self.sessions: dict[str, AuthenticatedSession] = {}
        self._lock = threading.Lock()

    def start_handshake(self, hello: dict[str, Any]) -> dict[str, Any]:
        expected_fields = {
            "protocol",
            "peer_id",
            "target_id",
            "nonce_i",
            "kem_pk_i",
            "signature",
        }
        if set(hello) != expected_fields or hello["protocol"] != PROTOCOL:
            raise AuthenticationError("unsupported or malformed hello message")
        if not isinstance(hello["peer_id"], str) or not isinstance(hello["target_id"], str):
            raise AuthenticationError("peer identifiers must be strings")
        if hello["target_id"] != self.identity.peer_id:
            raise AuthenticationError("hello targets a different peer")
        peer_id = hello["peer_id"]
        if peer_id == self.identity.peer_id:
            raise AuthenticationError("a peer cannot authenticate to itself")
        public_key = self.trusted_peers.get(peer_id)
        if public_key is None:
            raise AuthenticationError("initiator is not trusted")

        nonce_i = _decode_hex(hello["nonce_i"], "nonce_i", 32)
        kem_pk_i = _decode_hex(hello["kem_pk_i"], "kem_pk_i")
        if not _verify(public_key, _signed_fields(hello), hello["signature"]):
            raise AuthenticationError("initiator signature verification failed")

        with oqs.KeyEncapsulation("ML-KEM-768") as kem:
            if len(kem_pk_i) != kem.length_public_key:
                raise AuthenticationError("initiator ML-KEM public key has an invalid length")
            kem_pk_r = kem.generate_keypair()
            kem_sk_r = kem.export_secret_key()
            ct_to_i, shared_secret_to_initiator = kem.encap_secret(kem_pk_i)

        challenge = {
            "protocol": PROTOCOL,
            "peer_id": self.identity.peer_id,
            "target_id": peer_id,
            "session_id": secrets.token_hex(32),
            "nonce_i": nonce_i.hex(),
            "nonce_r": secrets.token_hex(32),
            "kem_pk_r": kem_pk_r.hex(),
            "ct_to_i": ct_to_i.hex(),
        }
        challenge["signature"] = _sign(
            self.identity,
            {
                "purpose": "challenge",
                "hello": hello,
                "challenge": challenge,
            },
        )
        session_id = challenge["session_id"]
        now = time.monotonic()
        with self._lock:
            self._expire_pending(now)
            if len(self.pending) >= MAX_PENDING_HANDSHAKES:
                raise AuthenticationError("too many pending handshakes")
            self.pending[session_id] = PendingHandshake(
                peer_id=peer_id,
                hello=hello,
                challenge=_signed_fields(challenge),
                kem_secret_key=kem_sk_r,
                shared_secret_to_initiator=shared_secret_to_initiator,
                created_at=now,
            )
        return challenge

    def finish_handshake(self, finish: dict[str, Any]) -> dict[str, Any]:
        if set(finish) != {
            "session_id",
            "ct_to_r",
            "signature",
            "client_finished",
        }:
            raise AuthenticationError("malformed finish message")
        session_id = finish["session_id"]
        if not isinstance(session_id, str):
            raise AuthenticationError("session_id must be a string")
        finish_unsigned = {
            key: value
            for key, value in finish.items()
            if key not in {"signature", "client_finished"}
        }

        with self._lock:
            self._expire_pending(time.monotonic())
            pending = self.pending.get(session_id)
        if pending is None:
            raise AuthenticationError("handshake is missing, expired, or already used")

        public_key = self.trusted_peers[pending.peer_id]
        transcript_fields = _transcript(
            pending.hello,
            pending.challenge,
            finish_unsigned,
        )
        signed_finish = {
            "purpose": "finish",
            **transcript_fields,
        }
        if not _verify(public_key, signed_finish, finish["signature"]):
            raise AuthenticationError("initiator finish signature verification failed")

        ct_to_r = _decode_hex(finish["ct_to_r"], "ct_to_r")
        with oqs.KeyEncapsulation("ML-KEM-768", secret_key=pending.kem_secret_key) as kem:
            if len(ct_to_r) != kem.length_ciphertext:
                raise AuthenticationError("ML-KEM ciphertext has an invalid length")
            shared_secret_to_responder = kem.decap_secret(ct_to_r)

        session_key, transcript_hash = _derive_session_key(
            pending.shared_secret_to_initiator,
            shared_secret_to_responder,
            transcript_fields,
        )
        expected_client_finished = hmac.new(
            session_key,
            b"client-finished:" + transcript_hash,
            hashlib.sha256,
        ).hexdigest()
        client_finished = finish["client_finished"]
        if not isinstance(client_finished, str) or not hmac.compare_digest(
            client_finished,
            expected_client_finished,
        ):
            raise AuthenticationError("initiator key confirmation failed")
        server_finished = hmac.new(
            session_key,
            b"server-finished:" + transcript_hash,
            hashlib.sha256,
        ).hexdigest()
        with self._lock:
            if self.pending.pop(session_id, None) is None:
                raise AuthenticationError("handshake was already completed")
            self.sessions[session_id] = AuthenticatedSession(
                local_peer_id=self.identity.peer_id,
                remote_peer_id=pending.peer_id,
                session_id=session_id,
                session_key=session_key,
            )
        return {
            "protocol": PROTOCOL,
            "status": "authenticated",
            "peer_id": self.identity.peer_id,
            "target_id": pending.peer_id,
            "session_id": session_id,
            "server_finished": server_finished,
        }

    def _expire_pending(self, now: float) -> None:
        expired = [
            session_id
            for session_id, pending in self.pending.items()
            if now - pending.created_at > PENDING_TTL_SECONDS
        ]
        for session_id in expired:
            del self.pending[session_id]


def create_peer_app(service: PeerAuthService) -> Flask:
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 1_048_576

    @app.errorhandler(AuthenticationError)
    def handle_authentication_error(error: AuthenticationError):
        return jsonify({"error": str(error)}), 401

    @app.get("/health")
    def health():
        return jsonify({"status": "ok", "peer_id": service.identity.peer_id})

    @app.post("/auth/hello")
    def auth_hello():
        body = request.get_json()
        if not isinstance(body, dict):
            raise AuthenticationError("hello body must be a JSON object")
        return jsonify(service.start_handshake(body))

    @app.post("/auth/finish")
    def auth_finish():
        body = request.get_json()
        if not isinstance(body, dict):
            raise AuthenticationError("finish body must be a JSON object")
        return jsonify(service.finish_handshake(body))

    return app


def authenticate_peer(
    base_url: str,
    identity: PeerIdentity,
    remote_peer_id: str,
    remote_signing_public_key: bytes,
    timeout: float = 10,
) -> AuthenticatedSession:
    with oqs.KeyEncapsulation("ML-KEM-768") as kem:
        kem_pk_i = kem.generate_keypair()
        kem_sk_i = kem.export_secret_key()

    hello = {
        "protocol": PROTOCOL,
        "peer_id": identity.peer_id,
        "target_id": remote_peer_id,
        "nonce_i": secrets.token_hex(32),
        "kem_pk_i": kem_pk_i.hex(),
    }
    hello["signature"] = _sign(identity, hello)

    challenge = _post_json(
        f"{base_url.rstrip('/')}/auth/hello",
        hello,
        timeout,
    )
    if not isinstance(challenge, dict) or set(challenge) != {
        "protocol",
        "peer_id",
        "target_id",
        "session_id",
        "nonce_i",
        "nonce_r",
        "kem_pk_r",
        "ct_to_i",
        "signature",
    }:
        raise AuthenticationError("malformed challenge message")
    challenge_unsigned = _signed_fields(challenge)
    if (
        challenge["protocol"] != PROTOCOL
        or challenge["peer_id"] != remote_peer_id
        or challenge["target_id"] != identity.peer_id
        or challenge["nonce_i"] != hello["nonce_i"]
    ):
        raise AuthenticationError("challenge does not match the requested peer or nonce")
    challenge_signature = challenge.pop("signature")
    if not _verify(
        remote_signing_public_key,
        {"purpose": "challenge", "hello": hello, "challenge": challenge_unsigned},
        challenge_signature,
    ):
        raise AuthenticationError("responder signature verification failed")

    ct_to_i = _decode_hex(challenge["ct_to_i"], "ct_to_i")
    with oqs.KeyEncapsulation("ML-KEM-768", secret_key=kem_sk_i) as kem:
        if len(ct_to_i) != kem.length_ciphertext:
            raise AuthenticationError("responder ML-KEM ciphertext has an invalid length")
        shared_secret_to_initiator = kem.decap_secret(ct_to_i)
    kem_pk_r = _decode_hex(challenge["kem_pk_r"], "kem_pk_r")
    with oqs.KeyEncapsulation("ML-KEM-768") as kem:
        if len(kem_pk_r) != kem.length_public_key:
            raise AuthenticationError("responder ML-KEM public key has an invalid length")
        ct_to_r, shared_secret_to_responder = kem.encap_secret(kem_pk_r)

    finish_unsigned = {
        "session_id": challenge["session_id"],
        "ct_to_r": ct_to_r.hex(),
    }
    transcript_fields = _transcript(hello, challenge_unsigned, finish_unsigned)
    session_key, transcript_hash = _derive_session_key(
        shared_secret_to_initiator,
        shared_secret_to_responder,
        transcript_fields,
    )
    finish = {
        **finish_unsigned,
        "signature": _sign(
            identity,
            {"purpose": "finish", **transcript_fields},
        ),
        "client_finished": hmac.new(
            session_key,
            b"client-finished:" + transcript_hash,
            hashlib.sha256,
        ).hexdigest(),
    }
    response = _post_json(
        f"{base_url.rstrip('/')}/auth/finish",
        finish,
        timeout,
    )
    if not isinstance(response, dict) or response.get("protocol") != PROTOCOL:
        raise AuthenticationError("malformed authentication response")
    if (
        response.get("status") != "authenticated"
        or response.get("peer_id") != remote_peer_id
        or response.get("target_id") != identity.peer_id
        or response.get("session_id") != challenge["session_id"]
    ):
        raise AuthenticationError("responder did not confirm this handshake")

    expected_finished = hmac.new(
        session_key,
        b"server-finished:" + transcript_hash,
        hashlib.sha256,
    ).hexdigest()
    server_finished = response.get("server_finished")
    if not isinstance(server_finished, str) or not hmac.compare_digest(
        server_finished,
        expected_finished,
    ):
        raise AuthenticationError("responder key confirmation failed")

    return AuthenticatedSession(
        local_peer_id=identity.peer_id,
        remote_peer_id=remote_peer_id,
        session_id=challenge["session_id"],
        session_key=session_key,
    )


def _start_local_server(app: Flask) -> tuple[BaseWSGIServer, threading.Thread, str]:
    server = make_server("127.0.0.1", 0, app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, f"http://127.0.0.1:{server.server_port}"


def run_demo() -> None:
    identities = {
        peer_id: create_identity(peer_id)
        for peer_id in ("hospital-1", "gateway-1", "pharma-1")
    }
    trust_directory = {
        peer_id: identity.signing_public_key
        for peer_id, identity in identities.items()
    }
    services = {
        peer_id: PeerAuthService(identity, trust_directory)
        for peer_id, identity in identities.items()
    }
    servers = [
        _start_local_server(create_peer_app(service))
        for service in services.values()
    ]
    urls = dict(zip(services, (server[2] for server in servers)))

    try:
        for initiator_id, responder_id in (
            ("hospital-1", "gateway-1"),
            ("gateway-1", "pharma-1"),
            ("pharma-1", "hospital-1"),
        ):
            session = authenticate_peer(
                urls[responder_id],
                identities[initiator_id],
                responder_id,
                identities[responder_id].signing_public_key,
            )
            responder_session = services[responder_id].sessions[session.session_id]
            if not hmac.compare_digest(session.session_key, responder_session.session_key):
                raise RuntimeError("peers derived different session keys")
            print(
                f"Authenticated {initiator_id} <-> {responder_id}; "
                f"session {session.session_id[:12]}…"
            )
    finally:
        for server, thread, _ in servers:
            server.shutdown()
            thread.join(timeout=5)
            server.server_close()


def run_benchmark(runs: int) -> None:
    if runs < 1:
        raise ValueError("runs must be at least 1")

    identities = {
        peer_id: create_identity(peer_id)
        for peer_id in ("hospital-1", "gateway-1", "pharma-1")
    }
    trust_directory = {
        peer_id: identity.signing_public_key
        for peer_id, identity in identities.items()
    }
    services = {
        peer_id: PeerAuthService(identity, trust_directory)
        for peer_id, identity in identities.items()
    }
    servers = [
        _start_local_server(create_peer_app(service))
        for service in services.values()
    ]
    urls = dict(zip(services, (server[2] for server in servers)))
    peer_pairs = (
        ("hospital-1", "gateway-1"),
        ("gateway-1", "pharma-1"),
        ("pharma-1", "hospital-1"),
    )

    try:
        print(f"Loopback benchmark: {runs} measured samples per peer pair")
        print(
            f"{'Peer pair':<32} {'HTTP RTT median/p95 (ms)':<27} "
            f"{'Handshake median/p95 (ms)':<29}"
        )
        for initiator_id, responder_id in peer_pairs:
            initiator = identities[initiator_id]
            responder = identities[responder_id]
            responder_url = urls[responder_id]

            _http_round_trip_ms(responder_url)
            authenticate_peer(
                responder_url,
                initiator,
                responder_id,
                responder.signing_public_key,
            )

            rtt_samples = [
                _http_round_trip_ms(responder_url)
                for _ in range(runs)
            ]
            handshake_samples = []
            for _ in range(runs):
                started_at = time.perf_counter()
                authenticate_peer(
                    responder_url,
                    initiator,
                    responder_id,
                    responder.signing_public_key,
                )
                handshake_samples.append((time.perf_counter() - started_at) * 1000)

            rtt_median, rtt_p95 = _latency_summary(rtt_samples)
            handshake_median, handshake_p95 = _latency_summary(handshake_samples)
            print(
                f"{initiator_id} -> {responder_id:<20} "
                f"{rtt_median:8.2f} / {rtt_p95:8.2f}          "
                f"{handshake_median:8.2f} / {handshake_p95:8.2f}"
            )
        print(
            "HTTP RTT is loopback request/response time; "
            "handshake time includes crypto."
        )
    finally:
        for server, thread, _ in servers:
            server.shutdown()
            thread.join(timeout=5)
            server.server_close()


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return parsed


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command",
        choices=("demo", "benchmark"),
        nargs="?",
        default="demo",
        help="run a local peer demo or benchmark",
    )
    parser.add_argument(
        "--runs",
        type=_positive_int,
        default=20,
        help="measured benchmark samples per peer pair (default: 20)",
    )
    args = parser.parse_args()
    if args.command == "benchmark":
        run_benchmark(args.runs)
    else:
        run_demo()


if __name__ == "__main__":
    main()
