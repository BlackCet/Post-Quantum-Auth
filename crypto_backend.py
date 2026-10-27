from __future__ import annotations

from typing import Any


BASELINE = "baseline"
IMPROVED = "improved"


def _oqs_module():
    try:
        import oqs
    except ImportError as exc:
        raise RuntimeError(
            "The improved implementation requires liboqs-python and native liboqs. "
            "Build the Docker image or install the native dependency first."
        ) from exc
    return oqs


def key_fields(keys: dict[str, Any], implementation: str) -> tuple[bytes, bytes, bytes, bytes]:
    if implementation == BASELINE:
        fields = ("server_ek", "server_dk", "hospital_sk", "pharma_pk")
    elif implementation == IMPROVED:
        _oqs_module()
        fields = (
            "oqs_server_ek",
            "oqs_server_dk",
            "oqs_hospital_sk",
            "oqs_pharma_pk",
        )
    else:
        raise ValueError(f"Unknown PQC implementation: {implementation!r}")

    missing = [field for field in fields if field not in keys]
    if missing:
        raise RuntimeError(
            f"Missing {implementation} key material in keys.json: {', '.join(missing)}. "
            "Run keygen.py with the matching implementation."
        )
    return tuple(bytes.fromhex(keys[field]) for field in fields)


def keygen(
    implementation: str,
) -> tuple[tuple[bytes, bytes], tuple[bytes, bytes]]:
    return kem_keygen(implementation), signature_keygen(implementation)


def kem_keygen(implementation: str) -> tuple[bytes, bytes]:
    if implementation == BASELINE:
        from kyber_py.ml_kem import ML_KEM_768

        return ML_KEM_768.keygen()
    if implementation == IMPROVED:
        oqs = _oqs_module()
        _require_mechanisms(oqs)
        with oqs.KeyEncapsulation("ML-KEM-768") as kem:
            public_key = kem.generate_keypair()
            secret_key = kem.export_secret_key()
        return public_key, secret_key
    raise ValueError(f"Unknown PQC implementation: {implementation!r}")


def signature_keygen(implementation: str) -> tuple[bytes, bytes]:
    if implementation == BASELINE:
        from dilithium_py.ml_dsa import ML_DSA_65

        return ML_DSA_65.keygen()
    if implementation == IMPROVED:
        oqs = _oqs_module()
        _require_mechanisms(oqs)
        with oqs.Signature("ML-DSA-65") as signer:
            public_key = signer.generate_keypair()
            secret_key = signer.export_secret_key()
        return public_key, secret_key
    raise ValueError(f"Unknown PQC implementation: {implementation!r}")


def _require_mechanisms(oqs) -> None:
    if "ML-KEM-768" not in oqs.get_enabled_kem_mechanisms():
        raise RuntimeError("Native liboqs does not provide ML-KEM-768.")
    if "ML-DSA-65" not in oqs.get_enabled_sig_mechanisms():
        raise RuntimeError("Native liboqs does not provide ML-DSA-65.")


def encapsulate(implementation: str, public_key: bytes) -> tuple[bytes, bytes]:
    if implementation == BASELINE:
        from kyber_py.ml_kem import ML_KEM_768

        return ML_KEM_768.encaps(public_key)
    oqs = _oqs_module()
    _require_mechanisms(oqs)
    with oqs.KeyEncapsulation("ML-KEM-768") as kem:
        ciphertext, shared_secret = kem.encap_secret(public_key)
    return shared_secret, ciphertext


def decapsulate(
    implementation: str,
    secret_key: bytes,
    ciphertext: bytes,
) -> bytes:
    if implementation == BASELINE:
        from kyber_py.ml_kem import ML_KEM_768

        return ML_KEM_768.decaps(secret_key, ciphertext)
    oqs = _oqs_module()
    _require_mechanisms(oqs)
    with oqs.KeyEncapsulation("ML-KEM-768", secret_key=secret_key) as kem:
        return kem.decap_secret(ciphertext)


def sign(implementation: str, secret_key: bytes, message: bytes) -> bytes:
    if implementation == BASELINE:
        from dilithium_py.ml_dsa import ML_DSA_65

        return ML_DSA_65.sign(secret_key, message)
    oqs = _oqs_module()
    _require_mechanisms(oqs)
    with oqs.Signature("ML-DSA-65", secret_key=secret_key) as signer:
        return signer.sign(message)


def verify(
    implementation: str,
    public_key: bytes,
    message: bytes,
    signature: bytes,
) -> bool:
    if implementation == BASELINE:
        from dilithium_py.ml_dsa import ML_DSA_65

        return ML_DSA_65.verify(public_key, message, signature)
    oqs = _oqs_module()
    _require_mechanisms(oqs)
    with oqs.Signature("ML-DSA-65") as verifier:
        return verifier.verify(message, signature, public_key)
