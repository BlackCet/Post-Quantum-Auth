import json
import secrets
import threading
import unittest
import urllib.error
import urllib.request

from werkzeug.serving import make_server

from multi_server_auth import (
    AuthenticationError,
    PeerAuthService,
    _latency_summary,
    _post_json,
    _sign,
    authenticate_peer,
    create_identity,
    create_peer_app,
)


class MultiServerAuthenticationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.identities = {
            peer_id: create_identity(peer_id)
            for peer_id in ("hospital-test", "gateway-test", "untrusted-test")
        }
        cls.trusted = {
            peer_id: cls.identities[peer_id].signing_public_key
            for peer_id in ("hospital-test", "gateway-test")
        }
        cls.services = {
            peer_id: PeerAuthService(cls.identities[peer_id], cls.trusted)
            for peer_id in cls.trusted
        }
        cls.servers = {}
        for peer_id, service in cls.services.items():
            server = make_server("127.0.0.1", 0, create_peer_app(service), threaded=True)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            cls.servers[peer_id] = (
                server,
                thread,
                f"http://127.0.0.1:{server.server_port}",
            )

    @classmethod
    def tearDownClass(cls):
        for server, thread, _ in cls.servers.values():
            server.shutdown()
            thread.join(timeout=5)
            server.server_close()

    def test_two_trusted_servers_derive_the_same_session_key(self):
        initiator = self.identities["hospital-test"]
        responder = self.identities["gateway-test"]
        session = authenticate_peer(
            self.servers["gateway-test"][2],
            initiator,
            responder.peer_id,
            responder.signing_public_key,
        )
        remote_session = self.services["gateway-test"].sessions[session.session_id]
        self.assertEqual(session.local_peer_id, initiator.peer_id)
        self.assertEqual(remote_session.remote_peer_id, initiator.peer_id)
        self.assertEqual(session.session_key, remote_session.session_key)

        with self.assertRaises(AuthenticationError):
            self.services["gateway-test"].finish_handshake(
                {
                    "session_id": session.session_id,
                    "ct_to_r": "",
                    "signature": "",
                }
            )

    def test_untrusted_peer_is_rejected(self):
        rogue = self.identities["untrusted-test"]
        trusted_responder = self.identities["hospital-test"]
        with self.assertRaises(urllib.error.HTTPError) as error:
            authenticate_peer(
                self.servers["hospital-test"][2],
                rogue,
                trusted_responder.peer_id,
                trusted_responder.signing_public_key,
            )
        self.assertEqual(error.exception.code, 401)
        error.exception.close()

    def test_health_endpoint_identifies_the_peer(self):
        url = f"{self.servers['gateway-test'][2]}/health"
        with urllib.request.urlopen(url, timeout=5) as response:
            health = json.loads(response.read())
        self.assertEqual(
            health,
            {"status": "ok", "peer_id": "gateway-test"},
        )

    def test_latency_summary_reports_median_and_nearest_rank_p95(self):
        self.assertEqual(_latency_summary([5.0, 1.0, 3.0, 4.0, 2.0]), (3.0, 5.0))

    def test_modified_hello_is_rejected(self):
        initiator = self.identities["hospital-test"]
        hello = {
            "protocol": "pqa-multiserver-v1",
            "peer_id": initiator.peer_id,
            "target_id": "gateway-test",
            "nonce_i": secrets.token_hex(32),
            "kem_pk_i": "00",
        }
        hello["signature"] = _sign(initiator, hello)
        hello["nonce_i"] = secrets.token_hex(32)

        with self.assertRaises(urllib.error.HTTPError) as error:
            _post_json(
                f"{self.servers['gateway-test'][2]}/auth/hello",
                hello,
                timeout=5,
            )
        self.assertEqual(error.exception.code, 401)
        error.exception.close()


if __name__ == "__main__":
    unittest.main()
