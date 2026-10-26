import json
import os
from typing import Any

import redis


class InMemoryPacketStore:
    def __init__(self) -> None:
        self._packets: list[dict[str, Any]] = []

    def append(self, packet: dict[str, Any]) -> int:
        self._packets.append(packet)
        return len(self._packets) - 1

    def get_all(self) -> list[dict[str, Any]]:
        return list(self._packets)

    def ping(self) -> bool:
        return True


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


def create_packet_store() -> InMemoryPacketStore | RedisPacketStore:
    redis_url = os.environ.get("REDIS_URL")
    if redis_url:
        return RedisPacketStore(redis_url)
    return InMemoryPacketStore()
