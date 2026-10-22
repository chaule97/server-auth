# Copyright 2026 Trobz
# License AGPL-3.0 or later (http://www.gnu.org/licenses/agpl).

{
    "name": "Auth Api Key Native Generate Google",
    "summary": "Exchange a Google ID token for a native Odoo API key",
    "version": "20.0.1.0.0",
    "license": "AGPL-3",
    "author": "Trobz,Odoo Community Association (OCA)",
    "website": "https://github.com/OCA/server-auth",
    "development_status": "Beta",
    "depends": ["auth_api_key_native_generate"],
    "external_dependencies": {"python": ["PyJWT>=2.8", "cryptography"]},
    "data": [
        "views/res_config_settings.xml",
    ],
}
