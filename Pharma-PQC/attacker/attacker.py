# Pharma-PQC/attacker/attacker.py

import copy

class Attacker:
    @staticmethod
    def tamper_ciphertext(payload: dict) -> dict:
        """Modifies a single byte in ct_aes to simulate in-transit data corruption."""
        tampered = copy.deepcopy(payload)
        ct_bytes = bytearray.fromhex(tampered["ct_aes"])
        if len(ct_bytes) > 0:
            ct_bytes[0] ^= 0xFF  # Flip bits of the first byte
        tampered["ct_aes"] = ct_bytes.hex()
        return tampered

    @staticmethod
    def truncate_payload(payload: dict, cut_bytes: int = 64) -> dict:
        """Truncates the ciphertext to trigger AES-GCM/ML-DSA integrity faults."""
        tampered = copy.deepcopy(payload)
        ct_bytes = bytes.fromhex(tampered["ct_aes"])
        tampered["ct_aes"] = ct_bytes[:-cut_bytes].hex()
        return tampered

    @staticmethod
    def tamper_metadata(payload: dict, spoofed_name: str = "malicious_report.exe") -> dict:
        """Modifies metadata fields. Baseline should FAIL to detect this!"""
        tampered = copy.deepcopy(payload)
        tampered["metadata"]["filename"] = spoofed_name
        return tampered