from __future__ import annotations

import hashlib
import json
import secrets
import threading
import time
from typing import Any

PROTOCOL_VERSION = 2
NONCE_BYTES = 16
MAX_CLOCK_SKEW_SECONDS = 300

_sequence_lock = threading.Lock()
_last_sequence = 0


def next_sequence_number() -> int:
    global _last_sequence
    with _sequence_lock:
        _last_sequence = max(time.time_ns(), _last_sequence + 1)
        return _last_sequence


def packet_auth_fields() -> dict[str, int | str]:
    return {
        "protocol_version": PROTOCOL_VERSION,
        "nonce": secrets.token_hex(NONCE_BYTES),
        "timestamp": int(time.time()),
        "sequence": next_sequence_number(),
    }


def signature_digest(packet: dict[str, Any]) -> bytes:
    metadata = packet.get("metadata")
    if not isinstance(metadata, dict):
        raise ValueError("Expected metadata to be a JSON object.")
    if packet.get("protocol_version") != PROTOCOL_VERSION:
        raise ValueError("Unsupported authenticated packet version.")

    nonce = packet.get("nonce")
    if not isinstance(nonce, str):
        raise ValueError("Expected nonce to be a hexadecimal string.")
    try:
        nonce_bytes = bytes.fromhex(nonce)
    except ValueError as exc:
        raise ValueError("Nonce must be valid hexadecimal.") from exc
    if len(nonce_bytes) != NONCE_BYTES:
        raise ValueError(f"Nonce must be exactly {NONCE_BYTES} bytes.")
    if nonce != nonce_bytes.hex():
        raise ValueError("Nonce must use canonical lowercase hexadecimal.")

    timestamp = packet.get("timestamp")
    sequence = packet.get("sequence")
    if (
        isinstance(timestamp, bool)
        or not isinstance(timestamp, int)
        or timestamp < 0
        or timestamp >= 2**64
    ):
        raise ValueError("Timestamp must be an integer Unix timestamp.")
    if (
        isinstance(sequence, bool)
        or not isinstance(sequence, int)
        or sequence < 1
        or sequence >= 2**64
    ):
        raise ValueError("Sequence must be a positive integer.")

    ciphertext_hex = packet.get("ciphertext")
    if not isinstance(ciphertext_hex, str):
        raise ValueError("Expected ciphertext to be a hexadecimal string.")
    try:
        ciphertext = bytes.fromhex(ciphertext_hex)
    except ValueError as exc:
        raise ValueError("Ciphertext must be valid hexadecimal.") from exc

    canonical_metadata = json.dumps(
        metadata,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    message = (
        b"PQC-PACKET-V2\x00"
        + canonical_metadata
        + b"\x00"
        + timestamp.to_bytes(8, "big", signed=False)
        + sequence.to_bytes(8, "big", signed=False)
        + nonce_bytes
        + ciphertext
    )
    return hashlib.sha256(message).digest()


def timestamp_is_fresh(timestamp: int, *, now: int | None = None) -> bool:
    current_time = int(time.time()) if now is None else now
    return abs(current_time - timestamp) <= MAX_CLOCK_SKEW_SECONDS
