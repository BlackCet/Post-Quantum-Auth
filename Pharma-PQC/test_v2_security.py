import copy
import os
import tempfile
import unittest

import oqs

from gateway.replay_guard import ReplayGuard
from hospital.sender_v2 import hospital_sender_v2
from pharma.receiver_v2 import pharma_receiver_v2


class V2PacketSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with oqs.KeyEncapsulation("ML-KEM-768") as kem:
            cls.gateway_pk = kem.generate_keypair()
            cls.gateway_sk = kem.export_secret_key()
        with oqs.Signature("ML-DSA-65") as signer:
            cls.hospital_pk = signer.generate_keypair()
            cls.hospital_sk = signer.export_secret_key()

    def setUp(self):
        with tempfile.NamedTemporaryFile(delete=False) as test_file:
            test_file.write(b"authenticated test report")
            self.file_path = test_file.name
        self.payload = hospital_sender_v2(
            self.file_path,
            self.gateway_pk,
            self.hospital_sk,
            sequence_num=1,
        )

    def tearDown(self):
        os.unlink(self.file_path)

    def test_authentic_packet_is_accepted_and_decrypted(self):
        guard = ReplayGuard()
        self.assertTrue(guard.accept(self.payload, self.hospital_pk))
        self.assertEqual(
            pharma_receiver_v2(self.payload, self.gateway_sk, self.hospital_pk),
            b"authenticated test report",
        )

    def test_metadata_timestamp_sequence_and_ciphertext_are_signed(self):
        mutations = (
            (
                "metadata",
                lambda payload: payload["metadata"].update(filename="fake"),
            ),
            (
                "timestamp",
                lambda payload: payload.update(timestamp=payload["timestamp"] + 1),
            ),
            (
                "sequence_num",
                lambda payload: payload.update(sequence_num=payload["sequence_num"] + 1),
            ),
            (
                "ct_kem",
                lambda payload: payload.update(
                    ct_kem=("00" if payload["ct_kem"][:2] != "00" else "01")
                    + payload["ct_kem"][2:]
                ),
            ),
            (
                "ct_aes",
                lambda payload: payload.update(
                    ct_aes=("00" if payload["ct_aes"][:2] != "00" else "01")
                    + payload["ct_aes"][2:]
                ),
            ),
        )
        for field, mutate in mutations:
            with self.subTest(field=field):
                altered = copy.deepcopy(self.payload)
                mutate(altered)
                with self.assertRaisesRegex(ValueError, "signature"):
                    pharma_receiver_v2(altered, self.gateway_sk, self.hospital_pk)

    def test_duplicate_and_out_of_order_sequences_are_rejected(self):
        guard = ReplayGuard()
        guard.accept(self.payload, self.hospital_pk)
        with self.assertRaisesRegex(ValueError, "sequence number"):
            guard.accept(self.payload, self.hospital_pk)

        next_payload = hospital_sender_v2(
            self.file_path,
            self.gateway_pk,
            self.hospital_sk,
            sequence_num=2,
        )
        guard.accept(next_payload, self.hospital_pk)
        with self.assertRaisesRegex(ValueError, "sequence number"):
            guard.accept(self.payload, self.hospital_pk)

    def test_stale_and_future_timestamps_are_rejected(self):
        guard = ReplayGuard(max_age_seconds=300, max_future_skew_seconds=30)
        with self.assertRaisesRegex(ValueError, "expired"):
            guard.accept(
                self.payload,
                self.hospital_pk,
                now=self.payload["timestamp"] + 301,
            )
        with self.assertRaisesRegex(ValueError, "future"):
            guard.accept(
                self.payload,
                self.hospital_pk,
                now=self.payload["timestamp"] - 31,
            )

        self.assertTrue(
            guard.accept(
                self.payload,
                self.hospital_pk,
                now=self.payload["timestamp"],
            )
        )

    def test_sender_rejects_nonpositive_sequence_number(self):
        for sequence_num in (0, -1, True):
            with self.subTest(sequence_num=sequence_num):
                with self.assertRaisesRegex(ValueError, "positive integer"):
                    hospital_sender_v2(
                        self.file_path,
                        self.gateway_pk,
                        self.hospital_sk,
                        sequence_num=sequence_num,
                    )


if __name__ == "__main__":
    unittest.main()
