import base64
import hashlib
import hmac
import json
import unittest
from unittest.mock import Mock, patch

import requests

import install_wireguard as router


def response(status, headers=None):
    result = requests.Response()
    result.status_code = status
    result.headers.update(headers or {})
    return result


def challenge(data):
    return response(401, {"X-NDM-Data": base64.b64encode(json.dumps(data).encode()).decode()})


class RouterAuthTests(unittest.TestCase):
    def setUp(self):
        self.settings = patch.multiple(router, ROUTER_URL="https://router.test",
                                       USERNAME="admin", PASSWORD="test-password")
        self.settings.start()
        self.addCleanup(self.settings.stop)
        self.session = Mock()

    def test_existing_session_needs_no_post(self):
        self.session.get.return_value = response(200)
        router.login(self.session)
        self.session.post.assert_not_called()

    def test_legacy_ndw2(self):
        self.session.get.return_value = response(401, {"X-NDM-Realm": "Router", "X-NDM-Challenge": "token"})
        self.session.post.return_value = response(200)
        router.login(self.session)
        digest = hashlib.md5(b"admin:Router:test-password").hexdigest()
        self.assertEqual(self.session.post.call_args.kwargs["json"],
                         {"login": "admin", "password": hashlib.sha256(("token" + digest).encode()).hexdigest()})

    def test_ndw4_success_and_server_signature(self):
        self.run_ndw4()
        self.assertEqual(self.session.post.call_count, 3)
        payload = self.session.post.call_args.kwargs["json"]
        self.assertIn("signature-proof", payload)
        self.assertNotIn("proof", payload)
        self.assertNotIn("password", payload)

    def test_ndw4_bad_server_signature_stops_before_final_post(self):
        with self.assertRaisesRegex(RuntimeError, "Подпись сервера"):
            self.run_ndw4(bad_signature=True)
        self.assertEqual(self.session.post.call_count, 2)

    def run_ndw4(self, bad_signature=False):
        self.session.get.return_value = response(401, {
            "WWW-Authenticate": 'x-ndw2-interactive, x-ndw4-interactive endpoint="/auth"'})
        salt = base64.b64encode(b"s" * 16).decode()
        nonce = base64.b64encode(b"n" * 16).decode()
        message = f"login1=admin,nonce1={nonce};iter2=1,memcost2=8,nonce2=server,salt2={salt};login3=admin,nonce3=server"
        key = hmac.digest(b"k" * 64, b"NDW4 Interactive Server Key", "sha3_512")
        signature = hmac.digest(key, message.encode(), "sha3_512")
        self.session.post.side_effect = [
            challenge({"salt": salt, "nonce": "server", "iter": 1, "memcost": 8}),
            challenge({"signature": base64.b64encode(b"bad" if bad_signature else signature).decode()}),
            response(200),
        ]
        with patch.object(router.os, "urandom", return_value=b"n" * 16), patch(
                "cryptography.hazmat.primitives.kdf.argon2.Argon2id") as kdf:
            kdf.return_value.derive.return_value = b"k" * 64
            router.login(self.session)
            kdf.assert_called_once_with(salt=b"s" * 16, length=64, iterations=1, lanes=1, memory_cost=8)

    def test_ndw4_does_not_send_credentials_to_other_origin(self):
        self.session.get.return_value = response(401, {
            "WWW-Authenticate": 'x-ndw4-interactive endpoint="//other.test/auth"'})
        with self.assertRaisesRegex(RuntimeError, "адрес авторизации"):
            router.login(self.session)
        self.session.post.assert_not_called()

    def test_check_action_only_reads_version(self):
        with patch("sys.argv", ["install_wireguard.py", "--action", "check", "--router", "router.test"]), patch.object(
                router, "login") as login, patch.object(router.requests, "Session") as session:
            session.return_value.__enter__.return_value = self.session
            router.main()
            login.assert_called_once_with(self.session)
            self.session.get.assert_called_once_with("https://router.test/rci/show/version", timeout=router.HTTP_TIMEOUT)
            self.session.post.assert_not_called()


if __name__ == "__main__":
    unittest.main()
