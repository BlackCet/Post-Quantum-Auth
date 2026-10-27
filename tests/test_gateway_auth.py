import copy
import unittest
from unittest.mock import patch

from crypto_backend import IMPROVED
from gateway import server
from gateway.storage import InMemoryPacketStore
from packet_auth import packet_auth_fields, signature_digest


class ImprovedGatewayAuthenticationTests(unittest.TestCase):
    def setUp(self):
        self.client = server.app.test_client()
        self.packet_store = InMemoryPacketStore()
        self.patches = [
            patch("builtins.print"),
            patch.object(server, "PQC_IMPLEMENTATION", IMPROVED),
            patch.object(server, "PHARMA_PK", b"test-public-key"),
            patch.object(server, "SERVER_DK", b"test-secret-key"),
            patch.object(server, "packet_store", self.packet_store),
            patch(
                "gateway.server.verify",
                side_effect=lambda implementation, public_key, message, signature:
                    message == signature,
            ),
            patch(
                "gateway.server.decapsulate",
                return_value=b"test-shared-secret",
            ),
        ]
        for patched in self.patches:
            patched.start()
            self.addCleanup(patched.stop)

    def make_packet(self, sequence):
        packet = {
            "kem_ct": "aabb",
            "ciphertext": "ccdd",
            "metadata": {"source": "hospital_A", "filename": "report.txt"},
            **packet_auth_fields(),
        }
        packet["sequence"] = sequence
        packet["signature"] = signature_digest(packet).hex()
        return packet

    def test_accepts_signed_packet_and_rejects_replay(self):
        packet = self.make_packet(100)

        first = self.client.post("/send", json=packet)
        replay = self.client.post("/send", json=packet)

        self.assertEqual(first.status_code, 200)
        self.assertEqual(replay.status_code, 409)
        self.assertIn(b"replay", replay.data)

    def test_rejects_modified_metadata_before_storing_packet(self):
        packet = self.make_packet(101)
        tampered = copy.deepcopy(packet)
        tampered["metadata"]["filename"] = "changed.txt"

        response = self.client.post("/send", json=tampered)

        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.packet_store.get_all(), [])


if __name__ == "__main__":
    unittest.main()
