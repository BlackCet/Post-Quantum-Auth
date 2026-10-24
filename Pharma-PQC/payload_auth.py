"""Canonical packet authentication helpers for the v2 file-transfer demo."""

from __future__ import annotations

import hashlib
import json
from typing import Any

import oqs


def authenticated_packet_fields(payload: dict[str, Any]) -> dict[str, Any]:
    metadata = payload.get("metadata")
    timestamp = payload.get("timestamp")
    sequence_num = payload.get("sequence_num")
    if not isinstance(metadata, dict):
        raise ValueError("metadata must be an object")
    if not isinstance(timestamp, int) or isinstance(timestamp, bool):
        raise ValueError("timestamp must be an integer")
    if (
        not isinstance(sequence_num, int)
        or isinstance(sequence_num, bool)
        or sequence_num < 1
    ):
        raise ValueError("sequence_num must be a positive integer")

    source_id = metadata.get("source_id")
    if not isinstance(source_id, str) or not source_id:
        raise ValueError("metadata.source_id must be a non-empty string")

    encoded_fields = {}
    for name in ("ct_kem", "aes_nonce", "ct_aes"):
        value = payload.get(name)
        if not isinstance(value, str):
            raise ValueError(f"{name} must be a hexadecimal string")
        try:
            encoded_fields[name] = bytes.fromhex(value).hex()
        except ValueError as exc:
            raise ValueError(f"{name} is not valid hexadecimal") from exc

    return {
        "metadata": metadata,
        "timestamp": timestamp,
        "sequence_num": sequence_num,
        **encoded_fields,
    }


def packet_digest(payload: dict[str, Any]) -> bytes:
    canonical_packet = json.dumps(
        authenticated_packet_fields(payload),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical_packet).digest()


def verify_packet_signature(payload: dict[str, Any], hospital_pk: bytes) -> bool:
    signature_hex = payload.get("sigma")
    if not isinstance(signature_hex, str):
        raise ValueError("sigma must be a hexadecimal string")
    try:
        signature = bytes.fromhex(signature_hex)
    except ValueError as exc:
        raise ValueError("sigma is not valid hexadecimal") from exc

    with oqs.Signature("ML-DSA-65") as verifier:
        return verifier.verify(packet_digest(payload), signature, hospital_pk)
