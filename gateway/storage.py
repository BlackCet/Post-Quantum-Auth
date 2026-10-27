import json
import os
import hashlib
import threading
import time
from typing import Any

import redis


class InMemoryPacketStore:
    def __init__(self) -> None:
        self._packets: list[dict[str, Any]] = []
        self._replay_lock = threading.Lock()
        self._last_sequences: dict[str, int] = {}
        self._seen_nonces: dict[tuple[str, str], int] = {}

    def append(self, packet: dict[str, Any]) -> int:
        self._packets.append(packet)
        return len(self._packets) - 1

    def get_all(self) -> list[dict[str, Any]]:
        return list(self._packets)

    def ping(self) -> bool:
        return True

    def accept_packet(self, source: str, sequence: int, nonce: str, expires_at: int) -> str:
        now = int(time.time())
        source_nonce = (source, nonce)
        with self._replay_lock:
            self._seen_nonces = {
                key: expiry for key, expiry in self._seen_nonces.items() if expiry > now
            }
            if source_nonce in self._seen_nonces:
                return "replay"
            if sequence <= self._last_sequences.get(source, 0):
                return "out_of_order"
            self._last_sequences[source] = sequence
            self._seen_nonces[source_nonce] = expires_at
            return "accepted"


class RedisPacketStore:
    def __init__(self, url: str) -> None:
        self._client = redis.Redis.from_url(url, decode_responses=True)
        self._key = "pharma-pqc:packets"

    def append(self, packet: dict[str, Any]) -> int:
        size = self._client.rpush(self._key, json.dumps(packet))
        return size - 1

    def get_all(self) -> list[dict[str, Any]]:
        return [
            json.loads(raw)
            for raw in self._client.lrange(self._key, 0, -1)
        ]

    def ping(self) -> bool:
        return self._client.ping()

    def accept_packet(self, source: str, sequence: int, nonce: str, expires_at: int) -> str:
        source_id = hashlib.sha256(source.encode("utf-8")).hexdigest()
        sequence_key = f"pharma-pqc:replay:sequence:{source_id}"
        nonce_key = f"pharma-pqc:replay:nonce:{source_id}:{nonce}"
        result = self._client.eval(
            """
            if redis.call('EXISTS', KEYS[2]) == 1 then
                return 'replay'
            end
            local incoming = ARGV[1]
            local previous = redis.call('GET', KEYS[1]) or '0'
            if string.len(incoming) < string.len(previous)
                or (string.len(incoming) == string.len(previous) and incoming <= previous) then
                return 'out_of_order'
            end
            redis.call('SET', KEYS[1], ARGV[1])
            redis.call('SET', KEYS[2], '1', 'EXAT', ARGV[2])
            return 'accepted'
            """,
            2,
            sequence_key,
            nonce_key,
            sequence,
            expires_at,
        )
        return str(result)


def create_packet_store() -> InMemoryPacketStore | RedisPacketStore:
    redis_url = os.environ.get("REDIS_URL")
    if redis_url:
        return RedisPacketStore(redis_url)
    return InMemoryPacketStore()
