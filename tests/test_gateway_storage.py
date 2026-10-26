import unittest
from unittest.mock import patch

from gateway.storage import InMemoryPacketStore, RedisPacketStore


class FakeRedis:
    def __init__(self):
        self.lists = {}

    def rpush(self, key, value):
        self.lists.setdefault(key, []).append(value)
        return len(self.lists[key])

    def lrange(self, key, start, stop):
        return self.lists.get(key, [])[start:]

    def ping(self):
        return True


class PacketStoreTests(unittest.TestCase):
    def test_memory_store_returns_stable_packet_order(self):
        store = InMemoryPacketStore()
        first = {"id": 1}
        second = {"id": 2}

        self.assertEqual(store.append(first), 0)
        self.assertEqual(store.append(second), 1)
        self.assertEqual(store.get_all(), [first, second])
        self.assertTrue(store.ping())

    def test_redis_stores_are_shared_between_gateway_instances(self):
        client = FakeRedis()
        with patch("gateway.storage.redis.Redis.from_url", return_value=client):
            first_gateway = RedisPacketStore("redis://redis:6379/0")
            second_gateway = RedisPacketStore("redis://redis:6379/0")

        packet = {"session_key": "demo", "status": "received"}
        self.assertEqual(first_gateway.append(packet), 0)
        self.assertEqual(second_gateway.get_all(), [packet])
        self.assertTrue(second_gateway.ping())


if __name__ == "__main__":
    unittest.main()
