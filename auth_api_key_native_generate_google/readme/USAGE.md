Request a key by POSTing the Google ID token to the endpoint:

```
POST /api/auth/google/generate_api_key
Content-Type: application/json

{
  "db": "mydb",
  "id_token": "eyJhbGciOiJSUzI1NiIs...",
  "device_name": "Pixel 8"
}
```

`device_name` is optional (64 characters at most). Each device should send a
stable name that is unique for the user, for instance the device model plus a
short identifier generated once per install (`Pixel 8 · 3f9a`): a sign-in
replaces the user's key with the same name. Without a device name, no key is
replaced.

On success (HTTP 200) the response holds the key, its expiration date (ISO
8601, UTC) and the matched user:

```json
{
  "api_key": "0123456789abcdef...",
  "expiration_date": "2027-01-19T08:00:00+00:00",
  "user": { "id": 42, "login": "jane@example.com", "name": "Jane Doe" }
}
```

Use the key as the bearer credential for `/json/2`:

```
curl -H "Authorization: Bearer 0123456789abcdef..." \
     https://mydb.example.com/json/2/...
```

The key is listed in the user's preferences, under *Account Security > API
Keys*, where it can be revoked. Archiving the user, removing the key or
reaching its expiration date invalidates it.

Error responses hold a human readable `error` and a stable `code`. Clients map
on `code`:

| Status | `code` | When | Suggested client behaviour |
|---|---|---|---|
| 400 | `invalid_request` | malformed body, bad `id_token` characters | "sign-in failed" |
| 401 | `invalid_token` | signature, algorithm, key, audience, issuer, expiry, missing claims | sign out of Google, "sign-in failed" |
| 401 | `stale_token` | token older than the maximum age | get a fresh token interactively, retry once |
| 403 | `email_unverified` | email not verified | sign out of Google, "sign-in failed" |
| 403 | `wrong_domain` | account outside of the allowed domains | sign out of Google, "use your company account" |
| 403 | `no_user` | no single active internal user matches | sign out of Google, "no Odoo user, contact an admin" |
| 403 | `mfa_enabled` | two-factor user, and they are not allowed | "sign in with a password" |
| 404 | `not_found` | unknown database, or route not configured | "sign-in failed" |
| 413 | (no JSON body) | body over 8 KiB | "sign-in failed" |
| 503 | `google_unavailable` | Google's keys can't be fetched | "try again", keep any existing key |

A `stale_token` typically comes from a cached token, e.g. returned by
`attemptLightweightAuthentication()` in `google_sign_in`: the client should
request a fresh one, and must not sign the user out of Google.

The user is matched on the verified Google email, exactly and
case-insensitively: on `login` first, then on `email` when no login matches.
The Workspace primary address must be stored in one of them; aliases are not
resolved. Several matches are refused as ambiguous.

Nonces are not used: `google_sign_in` accepts a nonce only once per app launch.
Replay is limited by TLS and the maximum token age, and a replayed token gives
nothing the same Google account couldn't get by signing in again.
