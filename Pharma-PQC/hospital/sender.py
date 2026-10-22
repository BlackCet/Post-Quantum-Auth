#
import os
from kyber_py.ml_kem import ML_KEM_768
from dilithium_py.ml_dsa import ML_DSA_65
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def hospital_sender(file_path, gateway_pk, hospital_sk):
    # Read input file as a raw byte stream
    with open(file_path, "rb") as f:
        file_bytes = f.read()
    
    # ML-KEM Key Encapsulation using gateway's public key
    ss, ct_kem = ML_KEM_768.encaps(gateway_pk)
    
    # Derive 256-bit AES key using HKDF-SHA-256
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"")
    k_aes = hkdf.derive(ss)
    
    # Encrypt file using AES-256-GCM
    aesgcm = AESGCM(k_aes)
    nonce = os.urandom(12)
    ct_aes = aesgcm.encrypt(nonce, file_bytes, None)
    
    # Sign the ciphertext using ML-DSA-65
    sigma = ML_DSA_65.sign(hospital_sk, ct_aes)
    
    # Construct structured payload (metadata is unsigned in baseline)
    payload = {
        "metadata": {"filename": os.path.basename(file_path), "format": "raw"},
        "ct_kem": ct_kem.hex(),
        "nonce": nonce.hex(),
        "ct_aes": ct_aes.hex(),
        "sigma": sigma.hex()
    }
    return payload