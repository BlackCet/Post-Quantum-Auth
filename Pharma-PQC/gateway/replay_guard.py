"""In-memory replay protection for authenticated v2 packets."""

from __future__ import annotations

import threading
import time
from typing import Any

from payload_auth import authenticated_packet_fields, verify_packet_signature


class ReplayGuard:
    def __init__(
        self,
        max_age_seconds: int = 300,
        max_future_skew_seconds: int = 30,
    ):
        if max_age_seconds < 1 or max_future_skew_seconds < 0:
            raise ValueError("invalid replay-guard time bounds")
        self.max_age_seconds = max_age_seconds
        self.max_future_skew_seconds = max_future_skew_seconds
        self._highest_sequence_by_source: dict[str, int] = {}
        self._lock = threading.Lock()

    def accept(
        self,
        payload: dict[str, Any],
        hospital_pk: bytes,
        now: float | None = None,
    ) -> bool:
        fields = authenticated_packet_fields(payload)
        if not verify_packet_signature(payload, hospital_pk):
            raise ValueError("Gateway REJECT: packet signature is invalid.")

        current_time = time.time() if now is None else now
        age = current_time - fields["timestamp"]
        if age > self.max_age_seconds:
            raise ValueError("Gateway REJECT: packet timestamp expired.")
        if age < -self.max_future_skew_seconds:
            raise ValueError("Gateway REJECT: packet timestamp is in the future.")

        source_id = fields["metadata"]["source_id"]
        sequence_num = fields["sequence_num"]
        with self._lock:
            highest_sequence = self._highest_sequence_by_source.get(source_id, 0)
            if sequence_num <= highest_sequence:
                raise ValueError(
                    "Gateway REJECT: duplicate or out-of-order sequence number."
                )
            self._highest_sequence_by_source[source_id] = sequence_num
        return True
