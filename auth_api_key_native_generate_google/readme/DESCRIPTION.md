This module adds an HTTP endpoint that exchanges a **Google ID token**, obtained
by a native app (Android Credential Manager, iOS GIDSignIn, `google_sign_in` in
Flutter), for a native Odoo API key (`res.users.apikeys`).

It extends `auth_api_key_native_generate`, which does the same exchange from a
login and a password. The key, its `rpc` scope, its validity window and the
response shape are the same, so a client can switch between both exchanges
without changing how it uses the key. The user never types an Odoo password.

- The token is verified on the server against Google's public keys: RS256
  signature, issuer, audience (the configured client IDs), expiry, freshness
  and verified email.
- Only accounts of the configured Google Workspace domains are accepted. The
  `hd` claim and the email domain must both match exactly.
- The Google account must match one existing, active, internal user, by login
  first, then by email. No user is ever created.
- Each device gets its own key, replaced when the same device signs in again.

Stock `auth_oauth` doesn't fit this case: it is built for the browser redirect
flow, validates an OAuth access token and opens a web session, while a native
app holds an ID token and needs an API key.
