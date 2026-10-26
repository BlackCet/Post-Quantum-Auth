import os
import requests


def configure_gateway_session(session: requests.Session, gateway_url: str) -> None:
    if gateway_url.lower().startswith("https://"):
        ca_file = os.environ.get("GATEWAY_CA_FILE")
        client_certificate = os.environ.get("GATEWAY_CLIENT_CERT_FILE")
        client_private_key = os.environ.get("GATEWAY_CLIENT_KEY_FILE")
        if not ca_file or not client_certificate or not client_private_key:
            missing = [
                name
                for name, path in (
                    ("CA certificate", ca_file),
                    ("client certificate", client_certificate),
                    ("client private key", client_private_key),
                )
                if not path
            ]
            raise RuntimeError(
                "HTTPS requires configured " + ", ".join(missing) + "."
            )
        session.verify = ca_file
        session.cert = (client_certificate, client_private_key)
    elif any(
        os.environ.get(name)
        for name in (
            "GATEWAY_CA_FILE",
            "GATEWAY_CLIENT_CERT_FILE",
            "GATEWAY_CLIENT_KEY_FILE",
        )
    ):
        raise RuntimeError(
            "TLS certificate settings are present, but GATEWAY_URL is not HTTPS."
        )
