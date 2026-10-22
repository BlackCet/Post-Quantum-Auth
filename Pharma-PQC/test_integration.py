import requests
import os
from dilithium_py.ml_dsa import ML_DSA_65
from hospital.sender import hospital_sender
from pharma.receiver import pharma_receiver

def run_integration_test():
    print("1. Fetching Gateway Keys...")
    res = requests.get("http://localhost:5000/test_keys").json()
    gateway_pk = bytes.fromhex(res["gateway_pk"])
    gateway_sk = bytes.fromhex(res["gateway_sk"])

    print("2. Generating Hospital Keys...")
    hospital_pk, hospital_sk = ML_DSA_65.keygen()

    print("3. Creating dummy dataset and running Hospital Sender...")
    os.makedirs("Pharma-PQC/data_generation", exist_ok=True)
    file_path = "Pharma-PQC/data_generation/dataset_1MB.txt"
    with open(file_path, "wb") as f:
        f.write(os.urandom(1024 * 1024)) # 1MB random bytes

    # Your previously created sender module
    payload = hospital_sender(file_path, gateway_pk, hospital_sk)

    print("4. Sending payload to Gateway Server...")
    response = requests.post("http://localhost:5000/forward", json=payload)
    
    if response.status_code == 200:
        forwarded_payload = response.json()["payload_forwarded"]
        print("5. Running Pharma Receiver on forwarded payload...")
        try:
            # Your previously created receiver module
            decrypted_bytes = pharma_receiver(forwarded_payload, gateway_sk, hospital_pk)
            print(f"Success! Decrypted data length: {len(decrypted_bytes)} bytes")
        except Exception as e:
            print(f"Receiver failed: {e}")
    else:
        print(f"Gateway Error: {response.status_code}")

if __name__ == "__main__":
    run_integration_test()