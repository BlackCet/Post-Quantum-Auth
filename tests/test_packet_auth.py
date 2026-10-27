import copy
import unittest

from packet_auth import (
    packet_auth_fields,
    signature_digest,
    timestamp_is_fresh,
)


class PacketAuthenticationTests(unittest.TestCase):
    def setUp(self):
        self.packet = {
            "ciphertext": "aabbcc",
            "metadata": {
                "source": "hospital_A",
                "filename": "report.csv",
                "sha256": "abc123",
            },
            **packet_auth_fields(),
        }

    def test_digest_is_stable_for_canonical_metadata(self):
        reordered = copy.deepcopy(self.packet)
        reordered["metadata"] = dict(reversed(list(reordered["metadata"].items())))

        self.assertEqual(signature_digest(self.packet), signature_digest(reordered))

    def test_digest_binds_ciphertext_and_metadata(self):
        changed_metadata = copy.deepcopy(self.packet)
        changed_metadata["metadata"]["source"] = "attacker"
        changed_ciphertext = copy.deepcopy(self.packet)
        changed_ciphertext["ciphertext"] = "aabbcd"

        self.assertNotEqual(signature_digest(self.packet), signature_digest(changed_metadata))
        self.assertNotEqual(signature_digest(self.packet), signature_digest(changed_ciphertext))

    def test_rejects_invalid_nonce_and_sequence(self):
        invalid_nonce = copy.deepcopy(self.packet)
        invalid_nonce["nonce"] = "00"
        noncanonical_nonce = copy.deepcopy(self.packet)
        noncanonical_nonce["nonce"] = self.packet["nonce"].upper()
        invalid_sequence = copy.deepcopy(self.packet)
        invalid_sequence["sequence"] = 0
        invalid_timestamp = copy.deepcopy(self.packet)
        invalid_timestamp["timestamp"] = -1

        with self.assertRaisesRegex(ValueError, "Nonce must be exactly"):
            signature_digest(invalid_nonce)
        with self.assertRaisesRegex(ValueError, "canonical lowercase"):
            signature_digest(noncanonical_nonce)
        with self.assertRaisesRegex(ValueError, "Sequence must be a positive"):
            signature_digest(invalid_sequence)
        with self.assertRaisesRegex(ValueError, "Timestamp must be"):
            signature_digest(invalid_timestamp)

    def test_timestamp_freshness_uses_configured_skew(self):
        self.assertTrue(timestamp_is_fresh(1000, now=1000))
        self.assertFalse(timestamp_is_fresh(1000, now=2000))


if __name__ == "__main__":
    unittest.main()
