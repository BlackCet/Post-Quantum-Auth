from kyber_py.ml_kem import ML_KEM_768
from dilithium_py.ml_dsa import ML_DSA_65
import json


# ML-KEM (Hospital <-> Gateway)
ek, dk = ML_KEM_768.keygen()
print("=== ML-KEM-768 KEYS (copy these) ===")
print("SERVER_EK (public, for hospital.py):", ek.hex())
print("SERVER_DK (private, only gateway needs it):", dk.hex())

# ML-DSA (Hospital signs, Pharma verifies)
pk, sk = ML_DSA_65.keygen()
print("\n=== ML-DSA-65 KEYS (copy these) ===")
print("HOSPITAL_SK (private, for hospital.py):", sk.hex())
print("PHARMA_PK (public, for pharma.py):", pk.hex())

# Save for easy copy-paste
with open("keys.json", "w") as f:
    json.dump({
        "server_ek": ek.hex(),
        "server_dk": dk.hex(),
        "hospital_sk": sk.hex(),
        "pharma_pk": pk.hex()
    }, f, indent=2)
print("\n✅ keys.json created. Copy values into the .py files.")