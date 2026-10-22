# Copyright 2026 Trobz
# License AGPL-3.0 or later (http://www.gnu.org/licenses/agpl).

from odoo import api, models
from odoo.tools.sql import escape_like_value


class ResUsersApikeys(models.Model):
    _inherit = "res.users.apikeys"

    @api.model
    def _rotate_google_keys(self, prefix, max_keys, device_key_name=None):
        """Make room for a new Google sign-in key of the current user.

        When ``device_key_name`` is given (a device name was sent), the keys
        with exactly that name are removed: signing in again on a device
        replaces its key. Then the oldest keys named after ``prefix`` are
        removed, so that once the new key is issued the user holds at most
        ``max_keys`` of them.

        Keys are recognised by their ``rpc`` scope and their name only: a key
        named the same way by hand is treated as a Google sign-in key.

        Must be called as the key owner, in superuser mode.
        """
        keys = self.search_fetch(
            [
                ("user_id", "=", self.env.uid),
                ("scope", "=", "rpc"),
                "|",
                ("name", "=", prefix),
                ("name", "=like", escape_like_value(f"{prefix} (") + "%"),
            ],
            ["name"],
            order="id desc",
        )
        if device_key_name:
            same_device = keys.filtered(lambda key: key.name == device_key_name)
            same_device._remove()
            keys -= same_device
        # max_keys >= 1 is ensured by the settings: with 0, this would keep
        # all keys but the newest.
        keys[max_keys - 1 :]._remove()
