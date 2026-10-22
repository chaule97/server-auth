# Copyright 2026 Trobz
# License AGPL-3.0 or later (http://www.gnu.org/licenses/agpl).
"""Verification of Google ID tokens obtained by native apps.

The token is verified locally against Google's public keys: there is no call
to Google's token or userinfo endpoints, hence no client secret.
"""

import functools
import time

import jwt

GOOGLE_CERTS_URL = "https://www.googleapis.com/oauth2/v3/certs"
GOOGLE_ISSUERS = ("https://accounts.google.com", "accounts.google.com")
# Clock skew tolerated on ``exp``, and on an ``iat`` in the future, in seconds.
LEEWAY = 60
# Google's keys are cached for one hour per worker.
JWKS_LIFESPAN = 3600
REQUIRED_CLAIMS = ["exp", "iat", "iss", "aud", "sub", "email"]


class GoogleUnavailable(Exception):
    """Google's keys could not be fetched: an outage, not an auth failure."""


class GoogleIdTokenError(Exception):
    """The token is refused.

    ``claims`` is only set once the signature has been verified, so callers
    never act on (or log) forged claims.
    """

    code = None

    def __init__(self, message, claims=None):
        super().__init__(message)
        self.claims = claims


class InvalidToken(GoogleIdTokenError):
    code = "invalid_token"


class StaleToken(GoogleIdTokenError):
    """Valid, except that it was issued longer ago than ``max_age``."""

    code = "stale_token"


class EmailUnverified(GoogleIdTokenError):
    code = "email_unverified"


class WrongDomain(GoogleIdTokenError):
    code = "wrong_domain"


@functools.cache
def _get_jwk_client():
    return jwt.PyJWKClient(GOOGLE_CERTS_URL, lifespan=JWKS_LIFESPAN)


def _get_signing_key(kid):
    client = _get_jwk_client()
    # Load the key set first, so that an unreachable or unusable endpoint is
    # told apart from a token signed with an unknown key.
    try:
        client.get_signing_keys()
    except (jwt.PyJWKClientError, jwt.PyJWKSetError, ValueError) as e:
        raise GoogleUnavailable(str(e)) from e
    try:
        # Refreshes the key set once when ``kid`` is unknown.
        return client.get_signing_key(kid).key
    except (jwt.PyJWKClientConnectionError, jwt.PyJWKSetError) as e:
        raise GoogleUnavailable(str(e)) from e
    except jwt.PyJWKClientError as e:
        raise InvalidToken("Unknown signing key.") from e


def _check_claims(claims, domains, max_age):
    if claims["iss"] not in GOOGLE_ISSUERS:
        raise InvalidToken("Unexpected issuer.", claims)
    email, sub = claims["email"], claims["sub"]
    if not (isinstance(email, str) and email and isinstance(sub, str) and sub):
        raise InvalidToken("Missing email or subject.", claims)
    iat = claims["iat"]
    now = time.time()
    if not isinstance(iat, int | float) or isinstance(iat, bool) or iat > now + LEEWAY:
        raise InvalidToken("Invalid issued-at time.", claims)
    if claims.get("email_verified") is not True:
        raise EmailUnverified("Email address not verified.", claims)
    hd = claims.get("hd")
    local, at, email_domain = email.rpartition("@")
    if (
        not isinstance(hd, str)
        or hd.lower() not in domains
        or not (local and at)
        or email_domain.lower() != hd.lower()
    ):
        raise WrongDomain("Account outside of the allowed domains.", claims)
    # Checked last: a stale token is otherwise valid, so the client may get a
    # fresh one and retry, instead of signing the user out.
    if now - iat > max_age:
        raise StaleToken("Token issued too long ago.", claims)


def verify(token, audiences, domains, max_age):
    """Verify a Google ID token and return its claims.

    :param str token: the ID token (a JWT)
    :param audiences: accepted OAuth client IDs (``aud``)
    :param domains: accepted Workspace domains, lower-case (``hd``)
    :param int max_age: maximum age of the token, from ``iat``, in seconds
    :raises GoogleUnavailable: Google's keys cannot be fetched
    :raises GoogleIdTokenError: the token is refused; see its ``code``
    """
    try:
        header = jwt.get_unverified_header(token)
    except jwt.InvalidTokenError as e:
        raise InvalidToken("Malformed token.") from e
    # Pinned before any key lookup: rejects "none" and HS256 tokens signed
    # with the public key.
    if header.get("alg") != "RS256":
        raise InvalidToken("Unexpected algorithm.")
    kid = header.get("kid")
    if not kid or not isinstance(kid, str):
        raise InvalidToken("Missing key id.")
    key = _get_signing_key(kid)
    try:
        claims = jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            audience=list(audiences),
            leeway=LEEWAY,
            # iat is checked in _check_claims, to tell stale tokens apart.
            options={"require": REQUIRED_CLAIMS, "verify_iat": False},
        )
    except jwt.InvalidTokenError as e:
        raise InvalidToken(str(e)) from e
    _check_claims(claims, domains, max_age)
    return claims
