# Copyright 2026 Trobz
# License AGPL-3.0 or later (http://www.gnu.org/licenses/agpl).

import base64
import hashlib
import hmac
import json
import time
from datetime import datetime
from unittest.mock import patch

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from odoo import fields
from odoo.exceptions import ValidationError
from odoo.tests import HttpCase, new_test_user, tagged
from odoo.tools import mute_logger

from ..models.res_config_settings import PARAM_PREFIX
from ..tools import google_id_token

ENDPOINT = "/api/auth/google/generate_api_key"
LOGGER = "odoo.addons.auth_api_key_native_generate_google.controllers.main"
WEB_CLIENT = "web-client.apps.googleusercontent.com"
IOS_CLIENT = "ios-client.apps.googleusercontent.com"
KID = "test-kid"
# Marks a claim to leave out of the token.
DROP = object()


def _b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


@tagged("-at_install", "post_install")
class TestGenerateApiKeyGoogle(HttpCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        # Tokens are signed with a generated key; the JWKS endpoint is patched
        # to serve it, so no test reaches the network.
        cls.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        jwk = jwt.algorithms.RSAAlgorithm.to_jwk(
            cls.private_key.public_key(), as_dict=True
        )
        jwk.update(kid=KID, alg="RS256", use="sig")
        cls.jwks = {"keys": [jwk]}
        cls.user = new_test_user(cls.env, login="van@trobz.com", name="Nguyen Thi Van")
        ICP = cls.env["ir.config_parameter"].sudo()
        ICP.set_str(f"{PARAM_PREFIX}.audiences", f"{WEB_CLIENT},{IOS_CLIENT}")
        ICP.set_str(f"{PARAM_PREFIX}.allowed_domains", "trobz.com")

    def setUp(self):
        super().setUp()
        google_id_token._get_jwk_client.cache_clear()
        patcher = patch.object(jwt.PyJWKClient, "fetch_data", return_value=self.jwks)
        self.fetch_data = patcher.start()
        self.addCleanup(patcher.stop)

    # Helpers

    def _claims(self, **overrides):
        now = int(time.time())
        claims = {
            "iss": "https://accounts.google.com",
            "aud": WEB_CLIENT,
            "sub": "110169484474386276334",
            "email": "van@trobz.com",
            "email_verified": True,
            "hd": "trobz.com",
            "iat": now,
            "exp": now + 3600,
        }
        claims.update(overrides)
        return {key: value for key, value in claims.items() if value is not DROP}

    def _token(self, key=None, headers=None, **overrides):
        return jwt.encode(
            self._claims(**overrides),
            key or self.private_key,
            algorithm="RS256",
            headers={"kid": KID, **(headers or {})},
        )

    def _post(self, payload, expected_status=200):
        res = self.url_open(
            ENDPOINT,
            data=json.dumps(payload),
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(res.status_code, expected_status, res.text)
        return res

    def _payload(self, token=None, **overrides):
        payload = {
            "db": self.env.cr.dbname,
            "id_token": token or self._token(),
            "device_name": "Pixel 8",
        }
        payload.update(overrides)
        return {key: value for key, value in payload.items() if value is not DROP}

    def _keys(self, user=None):
        return (
            self.env["res.users.apikeys"]
            .sudo()
            .search([("user_id", "=", (user or self.user).id)], order="id")
        )

    def _assert_refused(self, payload, status, code):
        before = self._keys()
        res = self._post(payload, expected_status=status)
        self.assertEqual(res.json()["code"], code)
        self.assertEqual(self._keys(), before, "no key on a refused exchange")
        return res

    # Configuration

    def test_disabled_without_audience(self):
        self.env["ir.config_parameter"].sudo().set_str(
            f"{PARAM_PREFIX}.audiences", None
        )
        self._assert_refused(self._payload(), 404, "not_found")
        # The base password route is unaffected.
        res = self.url_open(
            "/api/auth/generate_api_key",
            data=json.dumps(
                {"db": self.env.cr.dbname, "login": "van@trobz.com", "password": "x"}
            ),
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(res.status_code, 401)

    @mute_logger(LOGGER)
    def test_disabled_with_unreadable_settings(self):
        self.env["ir.config_parameter"].sudo().set_str(
            f"{PARAM_PREFIX}.max_token_age", "ten minutes"
        )
        self._assert_refused(self._payload(), 404, "not_found")

    def test_settings_validation(self):
        Settings = self.env["res.config.settings"]
        valid = {
            "auth_google_api_key_audiences": WEB_CLIENT,
            "auth_google_api_key_allowed_domains": "trobz.com",
        }
        Settings.create(valid).execute()
        for invalid in (
            {"auth_google_api_key_allowed_domains": False},
            {"auth_google_api_key_allowed_domains": "Trobz.com"},
            {"auth_google_api_key_allowed_domains": "@trobz.com"},
            {"auth_google_api_key_max_token_age": 30},
            {"auth_google_api_key_max_token_age": 3601},
            {"auth_google_api_key_max_keys_per_user": 0},
            {"auth_google_api_key_max_keys_per_user": 101},
        ):
            with self.subTest(invalid=invalid), self.assertRaises(ValidationError):
                Settings.create({**valid, **invalid})

    # Success

    def test_success(self):
        for aud in (WEB_CLIENT, IOS_CLIENT):
            with self.subTest(aud=aud):
                self.assertFalse(self._keys())
                body = self._post(self._payload(self._token(aud=aud))).json()
                key = self._keys()
                self.assertEqual(len(key), 1)
                self.assertEqual(key.scope, "rpc")
                self.assertEqual(key.name, "Google sign-in (Pixel 8)")
                self.assertEqual(
                    body["user"],
                    {
                        "id": self.user.id,
                        "login": "van@trobz.com",
                        "name": "Nguyen Thi Van",
                    },
                )
                # The base module's duration (90 days by default) applies.
                expiration = datetime.fromisoformat(body["expiration_date"])
                delta = expiration.replace(tzinfo=None) - fields.Datetime.now()
                self.assertIn(delta.days, (88, 89, 90))
                uid = self.env["res.users.apikeys"]._check_credentials(
                    scope="rpc", key=body["api_key"]
                )
                self.assertEqual(uid, self.user.id)
                key._remove()

    def test_key_authenticates_json2(self):
        api_key = self._post(self._payload()).json()["api_key"]
        res = self.url_open(
            "/json/2/res.users/read",
            data=json.dumps({"ids": [self.user.id], "fields": ["login"]}),
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "X-Odoo-Database": self.env.cr.dbname,
            },
        )
        self.assertEqual(res.status_code, 200, res.text)
        self.assertEqual(res.json()[0]["login"], "van@trobz.com")

    def test_login_date_updated(self):
        self.assertFalse(self.user.login_date)
        self._post(self._payload())
        self.user.invalidate_recordset(["login_date"])
        self.assertTrue(self.user.login_date)

    # Token verification

    @mute_logger(LOGGER)
    def test_invalid_tokens(self):
        other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = int(time.time())
        tokens = {
            "bad signature": self._token(key=other_key),
            "alg none": jwt.encode(
                self._claims(), None, algorithm="none", headers={"kid": KID}
            ),
            "HS256 with the public key": self._hs256_with_public_key(),
            "unknown kid": self._token(headers={"kid": "other-kid"}),
            "wrong aud": self._token(aud="someone-else.apps.googleusercontent.com"),
            "wrong iss": self._token(iss="https://evil.example.com"),
            "expired": self._token(iat=now - 300, exp=now - 120),
            "missing email": self._token(email=DROP),
            "missing sub": self._token(sub=DROP),
            "iat in the future": self._token(iat=now + 300),
        }
        for label, token in tokens.items():
            with self.subTest(label):
                self._assert_refused(self._payload(token), 401, "invalid_token")

    def _hs256_with_public_key(self):
        secret = self.private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        header = _b64(json.dumps({"alg": "HS256", "typ": "JWT", "kid": KID}).encode())
        payload = _b64(json.dumps(self._claims()).encode())
        signature = hmac.new(
            secret, f"{header}.{payload}".encode(), hashlib.sha256
        ).digest()
        return f"{header}.{payload}.{_b64(signature)}"

    @mute_logger(LOGGER)
    def test_stale_token(self):
        token = self._token(iat=int(time.time()) - 700)
        self._assert_refused(self._payload(token), 401, "stale_token")

    @mute_logger(LOGGER)
    def test_wrong_domain(self):
        for label, overrides in {
            "missing hd": {"hd": DROP},
            "hd not allowed": {"hd": "other.com", "email": "van@other.com"},
            "suffix domain": {"email": "van@trobz.com.evil.io"},
            "personal account": {"hd": DROP, "email": "van@gmail.com"},
        }.items():
            with self.subTest(label):
                self._assert_refused(
                    self._payload(self._token(**overrides)), 403, "wrong_domain"
                )

    def test_domain_is_case_insensitive(self):
        self._post(self._payload(self._token(email="VAN@Trobz.COM")))

    @mute_logger(LOGGER)
    def test_email_unverified(self):
        token = self._token(email_verified=False)
        self._assert_refused(self._payload(token), 403, "email_unverified")

    def test_google_unavailable(self):
        self.fetch_data.side_effect = jwt.PyJWKClientConnectionError("down")
        with self.assertLogs(LOGGER, "WARNING") as logs:
            self._assert_refused(self._payload(), 503, "google_unavailable")
        self.assertIn("error=PyJWKClientConnectionError", logs.output[0])

    # User matching

    @mute_logger(LOGGER)
    def test_no_user(self):
        token = self._token(email="nobody@trobz.com")
        self._assert_refused(self._payload(token), 403, "no_user")

    @mute_logger(LOGGER)
    def test_archived_and_portal_users_excluded(self):
        new_test_user(self.env, login="archived@trobz.com").active = False
        new_test_user(self.env, login="portal@trobz.com", groups="base.group_portal")
        new_test_user(
            self.env,
            login="portal-email",
            email="portal2@trobz.com",
            groups="base.group_portal",
        )
        for email in ("archived@trobz.com", "portal@trobz.com", "portal2@trobz.com"):
            with self.subTest(email=email):
                token = self._token(email=email)
                self._assert_refused(self._payload(token), 403, "no_user")

    @mute_logger(LOGGER)
    def test_no_wildcard_match(self):
        new_test_user(self.env, login="jdoe", email="jxdoe@trobz.com")
        for email in ("va_@trobz.com", "%@trobz.com", "j_doe@trobz.com"):
            with self.subTest(email=email):
                token = self._token(email=email)
                self._assert_refused(self._payload(token), 403, "no_user")

    def test_login_takes_precedence_over_email(self):
        new_test_user(self.env, login="someone-else", email="van@trobz.com")
        body = self._post(self._payload()).json()
        self.assertEqual(body["user"]["id"], self.user.id)

    def test_ambiguous_logins(self):
        new_test_user(self.env, login="dup@trobz.com")
        new_test_user(self.env, login="DUP@trobz.com")
        # Would match by email if the fallback were tried.
        new_test_user(self.env, login="by-email", email="dup@trobz.com")
        token = self._token(email="dup@trobz.com")
        with self.assertLogs(LOGGER, "INFO") as logs:
            self._assert_refused(self._payload(token), 403, "no_user")
        self.assertIn("reason=ambiguous", logs.output[0])

    def test_email_fallback(self):
        user = new_test_user(self.env, login="nvan", email="Nvan@trobz.com")
        body = self._post(self._payload(self._token(email="nvan@trobz.com"))).json()
        self.assertEqual(body["user"]["id"], user.id)

    def test_ambiguous_emails(self):
        new_test_user(self.env, login="first", email="shared@trobz.com")
        new_test_user(self.env, login="second", email="shared@trobz.com")
        token = self._token(email="shared@trobz.com")
        with self.assertLogs(LOGGER, "INFO") as logs:
            self._assert_refused(self._payload(token), 403, "no_user")
        self.assertIn("reason=ambiguous", logs.output[0])

    # Two-factor authentication

    @mute_logger(LOGGER)
    def test_mfa_users(self):
        users_cls = type(self.env["res.users"])
        with patch.object(users_cls, "_mfa_url", return_value="/web/login/totp"):
            self._post(self._payload())
            self.env["ir.config_parameter"].sudo().set_bool(
                f"{PARAM_PREFIX}.allow_mfa_users", False
            )
            self._assert_refused(self._payload(), 403, "mfa_enabled")

    # Key lifecycle

    def test_rotation_per_device(self):
        self._post(self._payload())
        self._post(self._payload())
        self.assertEqual(self._keys().mapped("name"), ["Google sign-in (Pixel 8)"])
        self._post(self._payload(device_name="iPhone 15"))
        self.assertEqual(
            self._keys().mapped("name"),
            ["Google sign-in (Pixel 8)", "Google sign-in (iPhone 15)"],
        )

    def test_no_rotation_without_device_name(self):
        self._post(self._payload(device_name=DROP))
        self._post(self._payload(device_name="   "))
        self.assertEqual(
            self._keys().mapped("name"), ["Google sign-in", "Google sign-in"]
        )

    def test_device_name_is_cleaned(self):
        self._post(self._payload(device_name="  Pixel\n8\x00 "))
        self.assertEqual(self._keys().name, "Google sign-in (Pixel8)")

    def test_cap_removes_oldest_prefixed_key(self):
        self.env["ir.config_parameter"].sudo().set_int(
            f"{PARAM_PREFIX}.max_keys_per_user", 2
        )
        expiration_date = fields.Datetime.now().replace(year=2099)
        manual_key = (
            self.env["res.users.apikeys"]
            .with_user(self.user)
            .sudo()
            ._generate("rpc", "Hand-made key", expiration_date)
        )
        for device in ("A", "B", "C"):
            self._post(self._payload(device_name=device))
        self.assertEqual(
            self._keys().mapped("name"),
            ["Hand-made key", "Google sign-in (B)", "Google sign-in (C)"],
        )
        self.assertEqual(
            self.env["res.users.apikeys"]._check_credentials(
                scope="rpc", key=manual_key
            ),
            self.user.id,
        )

    # Request body

    def test_invalid_request(self):
        for label, payload in {
            "missing db": self._payload(db=DROP),
            "missing id_token": self._payload(id_token=DROP),
            "id_token not a string": self._payload(id_token=42),
            "bad id_token characters": self._payload(id_token="abc def<script>"),
            "id_token too long": self._payload(id_token="a" * 4097),
            "device_name not a string": self._payload(device_name=["Pixel"]),
            "device_name too long": self._payload(device_name="x" * 65),
        }.items():
            with self.subTest(label):
                self._assert_refused(payload, 400, "invalid_request")
        self._assert_refused([1, 2, 3], 400, "invalid_request")
        self.fetch_data.assert_not_called()

    def test_oversized_body(self):
        res = self.url_open(
            ENDPOINT,
            data=json.dumps(self._payload(pad="x" * 9000)),
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(res.status_code, 413)

    @mute_logger("odoo.http")
    def test_unknown_db(self):
        self._assert_refused(
            self._payload(db="this-db-does-not-exist"), 404, "not_found"
        )

    # Logging

    def test_secrets_never_logged(self):
        token = self._token()
        with self.assertLogs(LOGGER, "DEBUG") as logs:
            api_key = self._post(self._payload(token)).json()["api_key"]
            self._post(
                self._payload(self._token(email="nobody@trobz.com")),
                expected_status=403,
            )
        output = "\n".join(logs.output)
        self.assertIn("google_apikey_issued", output)
        self.assertIn("email=nobody@trobz.com", output)
        self.assertNotIn(token, output)
        self.assertNotIn(api_key, output)

    def test_forged_email_not_logged(self):
        token = self._token(
            key=rsa.generate_private_key(65537, 2048), email="forged@x.io"
        )
        with self.assertLogs(LOGGER, "INFO") as logs:
            self._post(self._payload(token), expected_status=401)
        self.assertNotIn("forged@x.io", "\n".join(logs.output))
