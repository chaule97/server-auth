Go to **Settings > General Settings > Integrations > Google Sign-in for API
Keys**:

- **Google Client IDs**: the OAuth client IDs accepted as the token audience,
  comma-separated. On Android the token is issued for the **web** client ID
  (the app's `serverClientId`), on iOS for the **iOS** client ID, so this is
  usually both. Empty (the default) disables the route: it answers `404`, as
  if the module were not installed.
- **Allowed Workspace Domains**: lower-case, comma-separated, e.g.
  `example.com`. Required when client IDs are set.
- **Maximum Token Age** (default `600` seconds, `60` to `3600`): tokens issued
  longer ago are refused as stale.
- **Allow Two-Factor Users** (default on): users with Odoo two-factor
  authentication get a key through this route, relying on Google's 2-step
  verification instead. Turn it off to refuse them, as the password route does.
- **Key Name Prefix** (default `Google sign-in`): issued keys are named
  `<prefix> (<device name>)`.
- **Maximum Keys per User** (default `10`, `1` to `100`): beyond that number of
  keys named after the prefix, issuing a new one removes the oldest.

The key validity is the base module's setting. The values are stored as
`auth_api_key_native_generate_google.*` system parameters. A value that can't
be read at request time (edited directly in the system parameters) disables
the route and logs an error; it never falls back to accepting any client ID or
domain.

No client secret is needed: client IDs aren't secrets, and the token is
verified locally, without calling Google's token endpoint.

In the Google Cloud project of the Workspace, set the OAuth consent screen to
*Internal*, so that Google itself refuses accounts from outside the
organization. This module remains the authoritative check.

## Reverse proxy

- Rate-limit `/api/auth/google/generate_api_key`. There is no secret to guess,
  so Odoo's login cooldown doesn't apply. Allow a whole office signing in from
  one NAT IP (e.g. 30 requests per minute per IP).
- Do not put HTTP Basic Authentication in front of this route or `/json/2`:
  the app sends its API key in the `Authorization` header, and Basic
  credentials shipped inside a distributed app protect nothing.
- Enable proxy mode, so that client IPs in the logs are accurate.
