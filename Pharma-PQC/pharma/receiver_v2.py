# Pharma-PQC/pharma/receiver_v2.py

import oqs
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from payload_auth import authenticated_packet_fields, verify_packet_signature


def pharma_receiver_v2(payload, gateway_sk, hospital_pk):
    fields = authenticated_packet_fields(payload)
    if not verify_packet_signature(payload, hospital_pk):
        raise ValueError("V2 signature verification failed; packet was altered.")

    # 3. Native C ML-KEM Decapsulation
    with oqs.KeyEncapsulation("ML-KEM-768", secret_key=gateway_sk) as kem:
        ss = kem.decap_secret(bytes.fromhex(fields["ct_kem"]))

    # 4. Derive AES key and Decrypt
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"")
    k_aes = hkdf.derive(ss)

    aesgcm = AESGCM(k_aes)
    original_bytes = aesgcm.decrypt(
        bytes.fromhex(fields["aes_nonce"]),
        bytes.fromhex(fields["ct_aes"]),
        None,
    )

    return original_bytes