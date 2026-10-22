from flask import Flask, request, jsonify
from kyber_py.ml_kem import ML_KEM_768
import ssl

app = Flask(__name__)

# Generate Gateway keys on startup for testing
gateway_pk, gateway_sk = ML_KEM_768.keygen()

@app.route('/test_keys', methods=['GET'])
def get_keys():
    return jsonify({
        "gateway_pk": gateway_pk.hex(), 
        "gateway_sk": gateway_sk.hex()
    })

@app.route('/forward', methods=['POST'])
def gateway_receive():
    payload = request.json
    ct_kem = bytes.fromhex(payload["ct_kem"])
    
    # ML-KEM Decapsulation
    ss = ML_KEM_768.decaps(gateway_sk, ct_kem) 
    
    print(f"Received file: {payload['metadata']['filename']}")
    print(f"Recovered Session Key: {ss.hex()}")
    
    return jsonify({"status": "forwarded", "payload_forwarded": payload})

if __name__ == '__main__':
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile="/mnt/d/PQA/Pharma-PQC/server_ecdsa.crt", keyfile="/mnt/d/PQA/Pharma-PQC/server_ecdsa.key")
    context.minimum_version = ssl.TLSVersion.TLSv1_3 
    app.run(port=5000, ssl_context=context)