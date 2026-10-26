import requests

GATEWAY_URL = "http://127.0.0.1:5001"   # ← CHANGE TO GATEWAY IP

data = requests.get(f"{GATEWAY_URL}/logs").json()
if not data:
    print("No packets to tamper")
    exit()

tampered = data[-1].copy()
ct = bytearray.fromhex(tampered["ciphertext"])
ct[25] ^= 0x01
tampered["ciphertext"] = ct.hex()
tampered["metadata"]["source"] = "attacker"

requests.post(f"{GATEWAY_URL}/send", json=tampered)
print("🧨 Attacker tampered with last packet and re-sent")