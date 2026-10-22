# Copyright 2026 Trobz
# License AGPL-3.0 or later (http://www.gnu.org/licenses/agpl).

import re

from odoo import api, fields, models
from odoo.exceptions import ValidationError
from odoo.tools import str2bool

PARAM_PREFIX = "auth_api_key_native_generate_google"
DEFAULT_MAX_TOKEN_AGE = 600
MAX_TOKEN_AGE_RANGE = (60, 3600)
DEFAULT_ALLOW_MFA_USERS = True
DEFAULT_KEY_NAME_PREFIX = "Google sign-in"
DEFAULT_MAX_KEYS_PER_USER = 10
MAX_KEYS_PER_USER_RANGE = (1, 100)


def _split(value):
    """Split a comma or line separated setting into a list of values."""
    return [item for item in re.split(r"[\s,]+", value or "") if item]


def _to_int(env, value, default, bounds, label):
    # Not "value in (...)": 0 == False, and 0 must be refused, not defaulted.
    if value is None or value is False or value == "":
        return default
    try:
        value = int(value)
    except (TypeError, ValueError) as e:
        raise ValueError(env._("%(label)s must be a number.", label=label)) from e
    low, high = bounds
    if not low <= value <= high:
        raise ValueError(
            env._(
                "%(label)s must be between %(low)s and %(high)s.",
                label=label,
                low=low,
                high=high,
            )
        )
    return value


def _to_bool(value, default):
    if value is None or value == "":
        return default
    return str2bool(value)  # raises ValueError on garbage


def parse_config(
    env,
    audiences,
    allowed_domains,
    max_token_age,
    allow_mfa_users,
    key_name_prefix,
    max_keys_per_user,
):
    """Validate the raw settings and return them parsed.

    Used both when saving the settings and when serving a request, so that a
    value edited directly in ``ir.config_parameter`` is held to the same
    rules. An empty ``audiences`` list means the route is disabled. ``env``
    only serves to translate the error messages.

    :raises ValueError: a value is invalid
    """
    config = {
        "audiences": _split(audiences),
        "domains": _split(allowed_domains),
        "max_token_age": _to_int(
            env,
            max_token_age,
            DEFAULT_MAX_TOKEN_AGE,
            MAX_TOKEN_AGE_RANGE,
            env._("Maximum token age"),
        ),
        "allow_mfa_users": _to_bool(allow_mfa_users, DEFAULT_ALLOW_MFA_USERS),
        "key_name_prefix": (key_name_prefix or "").strip() or DEFAULT_KEY_NAME_PREFIX,
        "max_keys_per_user": _to_int(
            env,
            max_keys_per_user,
            DEFAULT_MAX_KEYS_PER_USER,
            MAX_KEYS_PER_USER_RANGE,
            env._("Maximum keys per user"),
        ),
    }
    if config["audiences"] and not config["domains"]:
        raise ValueError(
            env._("At least one allowed domain is required when audiences are set.")
        )
    for domain in config["domains"]:
        if domain != domain.lower() or "@" in domain:
            raise ValueError(
                env._(
                    "Allowed domains must be lower-case, without '@': %(domain)s",
                    domain=domain,
                )
            )
    return config


class ResConfigSettings(models.TransientModel):
    _inherit = "res.config.settings"

    auth_google_api_key_audiences = fields.Char(
        string="Google Client IDs",
        config_parameter=f"{PARAM_PREFIX}.audiences",
        help="OAuth client IDs accepted as the token audience, comma-separated: "
        "usually the web client ID (Android) and the iOS client ID. Leave empty "
        "to disable the route.",
    )

    auth_google_api_key_allowed_domains = fields.Char(
        string="Allowed Workspace Domains",
        config_parameter=f"{PARAM_PREFIX}.allowed_domains",
        help="Google Workspace domains allowed to sign in, lower-case, "
        "comma-separated (e.g. example.com).",
    )

    auth_google_api_key_max_token_age = fields.Integer(
        string="Maximum Token Age (seconds)",
        default=DEFAULT_MAX_TOKEN_AGE,
        config_parameter=f"{PARAM_PREFIX}.max_token_age",
        help="Google ID tokens issued longer ago than this are refused as "
        "stale. Between 60 and 3600.",
    )

    auth_google_api_key_allow_mfa_users = fields.Boolean(
        string="Allow Two-Factor Users",
        default=DEFAULT_ALLOW_MFA_USERS,
        config_parameter=f"{PARAM_PREFIX}.allow_mfa_users",
        help="Let users with Odoo two-factor authentication get a key through "
        "Google sign-in, relying on Google's 2-step verification instead.",
    )

    auth_google_api_key_key_name_prefix = fields.Char(
        string="Key Name Prefix",
        default=DEFAULT_KEY_NAME_PREFIX,
        config_parameter=f"{PARAM_PREFIX}.key_name_prefix",
        help="Name of the issued keys, followed by the device name.",
    )

    auth_google_api_key_max_keys_per_user = fields.Integer(
        string="Maximum Keys per User",
        default=DEFAULT_MAX_KEYS_PER_USER,
        config_parameter=f"{PARAM_PREFIX}.max_keys_per_user",
        help="Beyond this number of Google sign-in keys, issuing a new one "
        "removes the oldest. Between 1 and 100.",
    )

    @api.constrains(
        "auth_google_api_key_audiences",
        "auth_google_api_key_allowed_domains",
        "auth_google_api_key_max_token_age",
        "auth_google_api_key_key_name_prefix",
        "auth_google_api_key_max_keys_per_user",
    )
    def _check_auth_google_api_key_settings(self):
        for settings in self:
            try:
                parse_config(
                    self.env,
                    settings.auth_google_api_key_audiences,
                    settings.auth_google_api_key_allowed_domains,
                    settings.auth_google_api_key_max_token_age,
                    settings.auth_google_api_key_allow_mfa_users,
                    settings.auth_google_api_key_key_name_prefix,
                    settings.auth_google_api_key_max_keys_per_user,
                )
            except ValueError as e:
                raise ValidationError(str(e)) from e

    @api.model
    def _get_auth_google_api_key_config(self):
        """Read the settings at request time; see :func:`parse_config`."""
        ICP = self.env["ir.config_parameter"].sudo()
        return parse_config(
            self.env,
            *(
                ICP.get_str(f"{PARAM_PREFIX}.{key}", None)
                for key in (
                    "audiences",
                    "allowed_domains",
                    "max_token_age",
                    "allow_mfa_users",
                    "key_name_prefix",
                    "max_keys_per_user",
                )
            ),
        )
