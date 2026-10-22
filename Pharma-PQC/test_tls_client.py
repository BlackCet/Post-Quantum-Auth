import ssl
import urllib.request
import json
import oqs
from hospital.sender_v2 import hospital_sender_v2

def run_tls_transmission():
    # 1. Generate Gateway keys using the native C library (matching the server)
    with oqs.KeyEncapsulation('ML-KEM-768') as kem:
        gateway_pk = kem.generate_keypair()
    
    # 2. Generate Hospital keys using the native C library
    with oqs.Signature('ML-DSA-65') as signer:
        hospital_pk = signer.generate_keypair()
        hospital_sk = signer.export_secret_key()

    # 3. Generate the improved V2 payload
    payload = hospital_sender_v2("data_generation/dataset_1MB.txt", gateway_pk, hospital_sk)

    # 4. Configure TLS 1.3 client context to trust your ML-DSA certificate
    client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_context.load_verify_locations("/mnt/d/PQA/Pharma-PQC/server_ecdsa.crt")

    # 5. Send payload over the post-quantum TLS connection
    req = urllib.request.Request("https://localhost:5000/forward", method="POST")
    req.add_header('Content-Type', 'application/json')
    req_data = json.dumps(payload).encode('utf-8')

    with urllib.request.urlopen(req, data=req_data, context=client_context) as response:
        print("Server Response:", response.read().decode())

if __name__ == "__main__":
    run_tls_transmission()