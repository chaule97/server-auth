# Copyright 2026 Trobz
# License AGPL-3.0 or later (http://www.gnu.org/licenses/agpl).

from odoo import api, models
from odoo.tools.sql import escape_like_value


class ResUsers(models.Model):
    _inherit = "res.users"

    @api.model
    def _find_google_user(self, email):
        """Return the active internal users matching a verified Google email.

        The match is exact and case-insensitive, on ``login`` first, then on
        ``email`` only when no login matches. At most two records are
        returned, so that callers can tell a single match from an ambiguous
        one. Archived and portal/share users are never returned.
        """
        users = self.sudo().with_context(active_test=True)
        pattern = escape_like_value(email)
        domain = [("share", "=", False)]
        found = users.search(domain + [("login", "=ilike", pattern)], limit=2)
        if not found:
            found = users.search(domain + [("email", "=ilike", pattern)], limit=2)
        return found
