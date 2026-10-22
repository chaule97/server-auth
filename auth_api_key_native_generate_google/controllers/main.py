# Copyright 2026 Trobz
# License AGPL-3.0 or later (http://www.gnu.org/licenses/agpl).

import logging
import re
import unicodedata
from contextlib import ExitStack
from datetime import timedelta, timezone

import psycopg2
from werkzeug.exceptions import abort

import odoo
from odoo import fields, http
from odoo.http import request, route

from odoo.addons.auth_api_key_native_generate.controllers import main

from ..tools import google_id_token

_logger = logging.getLogger(__name__)

# Checked before any call to Google: a JWT is three base64url parts.
ID_TOKEN_RE = re.compile(r"[A-Za-z0-9_\-.]{1,4096}")
DEVICE_NAME_MAX_LENGTH = 64

ERRORS = {
    "invalid_token": (401, "Invalid Google ID token."),
    "stale_token": (401, "Google ID token issued too long ago, get a fresh one."),
    "email_unverified": (403, "The Google account email is not verified."),
    "wrong_domain": (403, "The Google account is not part of an allowed domain."),
    "no_user": (403, "No Odoo user matches this Google account."),
    "mfa_enabled": (
        403,
        (
            "Two-factor authentication is enabled for this user; API key "
            "generation from Google sign-in is not allowed."
        ),
    ),
    "not_found": (404, "Not found."),
    "google_unavailable": (503, "Google sign-in is unavailable, try again later."),
}


class InvalidRequest(Exception):
    """The request body is malformed."""


class AuthApiKeyNativeGenerate(main.AuthApiKeyNativeGenerate):
    def _error(self, status, code, message):
        """Build a JSON error response.

        ``error`` is a human readable message; ``code`` is a stable identifier
        clients can map on.
        """
        return request.make_json_response(
            {"error": message, "code": code}, status=status
        )

    def _open_env(self, stack, db):
        """Return an environment on ``db``, without any user.

        Raises a 404 JSON response (through ``werkzeug.exceptions.abort``) when
        the database is filtered out or does not exist. When the request is not
        already bound to ``db``, a dedicated cursor is entered on ``stack``: it
        is committed on a clean exit of the stack, persisting the new key.
        """
        if not http.router.db_filter([db]):
            abort(self._error(404, "not_found", "Database not found."))
        if request.db == db:
            return request.env(user=None, su=False)
        try:
            registry = odoo.modules.registry.Registry(db)
        except psycopg2.OperationalError:
            _logger.warning("Database %r not found or not reachable.", db)
            abort(self._error(404, "not_found", "Database not found."))
        cr = stack.enter_context(registry.cursor())
        return odoo.api.Environment(cr, None, {})

    def _issue_api_key(self, env, uid, name):
        """Issue an ``rpc`` API key owned by ``uid``.

        :returns: ``(api_key, expiration_date)``, the date being naive UTC.
        """
        duration = self._get_api_key_duration(env)
        # fields.Datetime.now() returns naive UTC, matching how Odoo stores
        # and compares apikeys.expiration_date (now() at time zone 'utc').
        expiration_date = fields.Datetime.now() + timedelta(days=duration)
        # Generate the key as the authenticated user, in superuser mode so
        # the fixed validity window is not capped by the user's group
        # ``api_key_duration`` limit. Keeping ``uid`` ensures the key is
        # owned by the authenticated user, not the superuser.
        api_key = env(user=uid, su=True)["res.users.apikeys"]._generate(
            scope="rpc", name=name, expiration_date=expiration_date
        )
        return api_key, expiration_date

    def _api_key_response(self, api_key, expiration_date, **extra):
        """Build the success response; ``extra`` keys are merged into it.

        The expiration date is serialized timezone-aware to be explicit
        towards external clients.
        """
        return request.make_json_response(
            {
                "api_key": api_key,
                "expiration_date": expiration_date.replace(
                    tzinfo=timezone.utc
                ).isoformat(),
                **extra,
            }
        )

    def _google_error(self, code):
        status, message = ERRORS[code]
        return self._error(status, code, message)

    def _google_rejected(self, db, code, claims=None, reason=None):
        """Log a refused exchange and return its error response.

        The email is only logged when it comes from verified claims, so forged
        claims never reach the logs.
        """
        email = (claims or {}).get("email")
        _logger.info(
            "google_apikey_rejected db=%s reason=%s email=%s",
            db,
            reason or code,
            email if isinstance(email, str) and email else "-",
        )
        return self._google_error(code)

    def _parse_google_request(self):
        """Return ``(db, id_token, device_name)`` from the JSON body.

        :raises InvalidRequest: the body is malformed
        """
        try:
            data = request.get_json_data()
        except ValueError as e:
            raise InvalidRequest("Invalid JSON body.") from e
        if not isinstance(data, dict):
            raise InvalidRequest("Request body must be a JSON object.")
        db = data.get("db")
        id_token = data.get("id_token")
        device_name = data.get("device_name")
        if not (db and isinstance(db, str)):
            raise InvalidRequest("'db' is required.")
        if not (isinstance(id_token, str) and ID_TOKEN_RE.fullmatch(id_token)):
            raise InvalidRequest("'id_token' is required and must be a JWT.")
        if device_name is not None:
            if not isinstance(device_name, str):
                raise InvalidRequest("'device_name' must be a string.")
            device_name = "".join(
                char for char in device_name if unicodedata.category(char) != "Cc"
            ).strip()
            if len(device_name) > DEVICE_NAME_MAX_LENGTH:
                raise InvalidRequest(
                    f"'device_name' is limited to {DEVICE_NAME_MAX_LENGTH} characters."
                )
        return db, id_token, device_name or None

    def _get_google_config(self, env, db):
        """Return the settings of ``db``, or None when the route is disabled.

        Settings that can't be read disable the route: they never fall back to
        accepting any audience or any domain.
        """
        try:
            config = env["res.config.settings"]._get_auth_google_api_key_config()
        except ValueError as e:
            _logger.error(
                "Google sign-in for API keys disabled on %r, invalid settings: %s",
                db,
                e,
            )
            return None
        return config if config["audiences"] else None

    def _issue_google_api_key(self, env, user, device_name, config, claims):
        prefix = config["key_name_prefix"]
        name = f"{prefix} ({device_name})" if device_name else prefix
        env(user=user.id, su=True)["res.users.apikeys"]._rotate_google_keys(
            prefix,
            config["max_keys_per_user"],
            device_key_name=name if device_name else None,
        )
        api_key, expiration_date = self._issue_api_key(env, user.id, name)
        # Record the sign-in in the user's login history, like a web login.
        env(user=user.id)["res.users"]._update_last_login()
        _logger.info(
            "google_apikey_issued db=%s uid=%s aud=%s key_name=%s",
            env.cr.dbname,
            user.id,
            claims["aud"],
            name,
        )
        return self._api_key_response(
            api_key,
            expiration_date,
            user={"id": user.id, "login": user.login, "name": user.name},
        )

    @route(
        "/api/auth/google/generate_api_key",
        type="http",
        auth="none",
        methods=["POST"],
        csrf=False,
        save_session=False,
        readonly=False,
        max_content_length=main.MAX_CONTENT_LENGTH,
    )
    def generate_api_key_google(self):
        """Exchange a Google ID token for a native Odoo API key.

        Request body (JSON)::

            {"db": "...", "id_token": "...", "device_name": "..."}

        Response body (JSON)::

            {"api_key": "...", "expiration_date": "...",
             "user": {"id": ..., "login": "...", "name": "..."}}

        The token must be signed by Google for one of the configured client
        IDs, belong to an allowed Workspace domain and match a single active
        internal user. No user is ever created.
        """
        try:
            db, id_token, device_name = self._parse_google_request()
        except InvalidRequest as e:
            _logger.info("google_apikey_rejected db=- reason=invalid_request email=-")
            return self._error(400, "invalid_request", str(e))

        with ExitStack() as stack:
            env = self._open_env(stack, db)
            config = self._get_google_config(env, db)
            if not config:
                return self._google_error("not_found")

            try:
                claims = google_id_token.verify(
                    id_token,
                    config["audiences"],
                    config["domains"],
                    config["max_token_age"],
                )
            except google_id_token.GoogleUnavailable as e:
                _logger.warning(
                    "google_apikey_failed db=%s reason=google_unavailable error=%s",
                    db,
                    type(e.__cause__ or e).__name__,
                )
                return self._google_error("google_unavailable")
            except google_id_token.GoogleIdTokenError as e:
                return self._google_rejected(db, e.code, e.claims)

            users = env["res.users"]._find_google_user(claims["email"])
            if len(users) != 1:
                return self._google_rejected(
                    db, "no_user", claims, reason="ambiguous" if users else None
                )
            # Google's 2-step verification stands in for Odoo's second factor,
            # unless the settings require Odoo's.
            if not config["allow_mfa_users"] and users._mfa_url():
                return self._google_rejected(db, "mfa_enabled", claims)

            return self._issue_google_api_key(env, users, device_name, config, claims)
