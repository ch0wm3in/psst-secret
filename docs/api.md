# API

A small JSON API runs alongside the HTML views. Clients encrypt and decrypt locally as
described in the [encryption format](format.md).

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/v1/info` | [Server and supported versions](#server-info) |
| `POST` | `/api/v1/whisper` | Create a send-mode whisper (ciphertext and metadata) |
| `POST` | `/api/v1/whisper/request` | Create a receive-mode request |
| `GET` | `/api/v1/whisper/submit/<request_id>` | Get a receive request's public key; check it against the submit link fingerprint |
| `POST` | `/api/v1/whisper/submit/<request_id>` | Submit ciphertext to a receive-mode request |
| `POST` | `/api/v1/whisper/<view_id>/reveal` | Reveal ciphertext with a valid `reveal_token` |
| `GET` | `/api/v1/whisper/<view_id>/status` | [Check a receive request](#receive-request-status) without consuming a view |
| `GET`, `PATCH` | `/api/v1/whisper/<view_id>/access` | Read or update [receive reader access](configuration.md#receive-reader-access) (creator only) |
| `POST` | `/api/v1/cli/token` | Exchange a sign-in code for an [API token](#api-tokens) |
| `POST` | `/api/v1/cli/revoke` | Revoke the API token sent with the request |

Never send the URL fragment, decryption key, private key seed, or password to any
endpoint. Requests that carry ciphertext or key material include the format version
`v`; see [Versions](format.md#versions).

## Versioning and schema

The `/api/v1/` endpoints follow the [compatibility policy](format.md#compatibility-policy).
The OpenAPI schema is generated with
[drf-spectacular](https://drf-spectacular.readthedocs.io/), served at `/api/schema/`
with interactive docs at `/api/docs/`, and committed as
[`spec/openapi.yaml`](../spec/openapi.yaml). A test fails when the committed schema is
out of date.

The unversioned paths (`/api/whisper`, `/api/whisper/request`,
`/api/whisper/submit/<request_id>`, and `/api/whisper/<view_id>/access`) are deprecated
aliases kept for existing clients. The browser app reveals through
`POST /whisper/<view_id>`, which returns the same JSON, or renders the decryption page
with `?render=1`. Neither is part of the documented schema.

## Server info

`GET /api/v1/info` returns the server version, the API version, the format versions
the server accepts for new whispers, how clients can authenticate, and which optional
features, sign-in policies, and limits the deployment uses. It never requires sign-in,
so clients can call it before they have a token.

```json
{
  "server_version": "v1.4.0",
  "api_version": 1,
  "format_versions": [1],
  "auth": {
    "login_required": true,
    "loopback_pkce": true,
    "manual_code": false,
    "extension_redirect": false,
    "scopes": ["whisper:create", "whisper:read", "request:manage"]
  },
  "features": {
    "email_notifications": true,
    "receive_access": {"enabled": true, "default": false, "required": false},
    "receive_history": false,
    "rich_text": true
  },
  "policies": {"view_requires_auth": false, "submit_requires_auth": false},
  "limits": {
    "max_upload_bytes": 10000000,
    "max_views": 100,
    "expiry_options": ["5m", "1h", "1d", "1w", "1M"]
  }
}
```

- **`auth`:** `login_required` says whether creating whispers needs authentication.
  `loopback_pkce` and `manual_code` say which [API token](#api-tokens) sign-in methods
  are available, and `extension_redirect` whether
  [browser extensions](#browser-extensions) can sign in; `scopes` is empty when API
  tokens are off.
- **`features`:** optional features from the [configuration](configuration.md).
  `email_notifications` says whether `notify_email` sends email. `receive_access` says
  whether requests accept [reader restrictions](#receive-reader-access), whether
  `creator_only` defaults to on, and whether it is required. `receive_history` refers to
  saved requests in the web app, and `rich_text` to Markdown rendering of text envelopes
  with `"format": "markdown"`.
- **`policies`:** whether every reveal or submission requires sign-in, regardless of the
  per-whisper `require_auth_view` and `require_auth_submit` options.
- **`limits`:** the largest accepted request body in bytes (ciphertext is base64, so
  plaintext must be smaller), the highest `max_views`, and the accepted `expiry` values.

Clients should hide or disable options the server does not offer. New fields may be
added within API version 1, so ignore fields you do not recognize.

## Reveal tokens

Both creation endpoints require `reveal_token_hash`; see
[Reveal tokens](format.md#reveal-tokens) for how to generate it. Reveal requests send
`reveal_token` in a JSON or form body. The token is optional only for
[legacy whispers](how-it-works.md#reveal-tokens) created before tokens existed. See
[Reveal tokens](how-it-works.md#reveal-tokens) for the full behaviour.

## Receive request status

`POST /api/v1/whisper/request` returns `id`, `submit_url`, `view_url`, and `expires_at`.
`GET /api/v1/whisper/<view_id>/status` then reports whether the request has been
submitted, without returning ciphertext or counting as a view.

```json
{
  "status": "submitted",
  "expires_at": "2026-11-07T14:39:50.077000Z",
  "view_count": 0,
  "max_views": 1,
  "remaining_views": 1
}
```

`status` is `pending` until something is submitted. Requests that expired, were burned,
or never existed return `{"status": "gone"}` with `404` or `410`; send-mode whispers are
reported as gone too. The endpoint applies the same sign-in and
[reader access](#receive-reader-access) checks as revealing, needs the `whisper:read`
scope for [API tokens](#scopes), and has its own rate limit
(`API_THROTTLE_RATE_STATUS`). It needs only the view identifier, so it reveals nothing
that opening the view link without its fragment does not.

## Receive reader access

`POST /api/v1/whisper/request` also accepts `creator_only` (boolean) and
`allowed_reader_emails` (up to 20 verified primary emails). The access endpoint accepts
the same fields; omitted fields keep their current values. Turning off `creator_only`
clears the approved readers, and is rejected when the restriction is mandatory.
These requests use session authentication with CSRF protection, or an
[API token](#api-tokens) with the `request:manage` scope, and responses contain only
restriction settings.

## API tokens

Non-browser clients, such as the CLI and the browser extension, authenticate with API
tokens when `ENABLE_AUTH` and `PSST_ENABLE_API_TOKENS` are set (see
[Configuration](configuration.md#api-tokens)). Clients get a token through a loopback
redirect with PKCE ([RFC 8252](https://www.rfc-editor.org/rfc/rfc8252) and
[RFC 7636](https://www.rfc-editor.org/rfc/rfc7636)). The user signs in through the
normal web login in their browser, so every configured social provider and local login
work, and MFA and Conditional Access apply as usual. The device authorization grant
(RFC 8628) is not supported, because some organizations block it.

### Sign-in flow

1. The client starts a temporary HTTP listener on `http://127.0.0.1:<port>/callback` or
   `http://[::1]:<port>/callback` (up to 255 characters). It generates a random `code_verifier` (43 to 128
   characters from `A-Z a-z 0-9 - . _ ~`), its S256 `code_challenge` (the unpadded
   base64url SHA-256 of the verifier), and a random `state`.
2. The client opens the browser at:

   ```text
   /cli/authorize?redirect_uri=http://127.0.0.1:53682/callback&code_challenge=<challenge>&code_challenge_method=S256&state=<state>&client_name=psst%20CLI&scope=whisper:create%20whisper:read
   ```

   `scope` is optional and defaults to every scope. `client_name` (up to 64
   characters) is shown to the user but is not verified.
3. The user signs in if needed, then approves or denies the client. The page shows the
   client name, the requested scopes, and the redirect host.
4. The browser is redirected to `redirect_uri?code=<code>&state=<state>`, or to
   `redirect_uri?error=access_denied&state=<state>` when the user denies access.
5. The client checks `state`, then exchanges the code within 60 seconds:

   ```http
   POST /api/v1/cli/token
   Content-Type: application/json

   {"code": "psstc_...", "code_verifier": "...", "redirect_uri": "http://127.0.0.1:53682/callback"}
   ```

   Form-encoded bodies with `grant_type=authorization_code` are also accepted. The
   response is:

   ```json
   {"access_token": "psst_...", "token_type": "Bearer", "expires_in": 604800, "expires_at": "2026-01-08T12:00:00Z", "scope": "whisper:create whisper:read"}
   ```

6. The client sends `Authorization: Bearer psst_...` on `/api/v1/` requests.
   Tokens are not accepted on other paths.

The authorize endpoint accepts only `http://127.0.0.1:<port>/<path>` and
`http://[::1]:<port>/<path>` redirect URIs, with any port and a path made of letters,
digits, `-`, `.`, `_`, `~`, and `/`, plus the exact
[extension redirect URIs](#browser-extensions) the server allows. `localhost`, other
hosts, query strings, and fragments are rejected. It requires `state` and the `S256`
challenge method, and rejects `plain`. When a request is invalid, it shows an error page
and never redirects.

Codes are random, single-use, stored as hashes, and bound to the user, the code
challenge, and the exact `redirect_uri`. A failed exchange also uses up the code.
Presenting a used code again revokes the token issued from it. Token exchange is
rate-limited per IP.

### Browser extensions

Browser extensions cannot listen on a loopback port. They use the same flow with
`identity.launchWebAuthFlow`, and the browser intercepts the redirect to its reserved
domain instead of loading it:

| Browser | Redirect URI (`identity.getRedirectURL('callback')`) |
|---|---|
| Chrome, Edge | `https://<extension id>.chromiumapp.org/callback` |
| Firefox | `https://<hash>.extensions.allizom.org/callback` |

The server accepts these only when they are listed exactly in
[`PSST_API_TOKEN_EXTENSION_REDIRECT_URIS`](configuration.md#api-tokens); there are no
wildcards. The approval page shows the extension's host. Clients can check
`auth.extension_redirect` in [`/api/v1/info`](#server-info) before opening the sign-in
window.

### Scopes

| Scope | Allows |
|---|---|
| `whisper:create` | `POST /api/v1/whisper`, and `GET`/`POST /api/v1/whisper/submit/<request_id>` |
| `whisper:read` | `POST /api/v1/whisper/<view_id>/reveal` and `GET /api/v1/whisper/<view_id>/status` |
| `request:manage` | `POST /api/v1/whisper/request` and `/api/v1/whisper/<view_id>/access` |

A token without the required scope gets `403`.

### Using and revoking tokens

Tokens start with `psst_` so secret scanners can detect them. The server stores only a
SHA-256 hash, together with the user, client name, scopes, and the created, last-used,
and expiry times. A token is authenticated before the login requirement is checked, so
`LOGIN_REQUIRED_EXEMPT_URLS`, `PSST_FORCE_AUTH_VIEW`, `PSST_FORCE_AUTH_SUBMIT`, and
per-whisper sign-in options all treat the request as coming from the token's user.
Token requests skip CSRF checks; session requests keep them. Token requests are
rate-limited per user.

A token stops working when it expires, is revoked, or its user is deactivated. Deleting
or disabling a user at the identity provider does not reach existing tokens until
they expire, so keep `PSST_API_TOKEN_TTL` short.

- `POST /api/v1/cli/revoke` revokes the token sent with the request (for `psst logout`)
  and returns `204`.
- Signed-in users can list and revoke their tokens at `/cli/tokens`, linked as
  **API tokens** in the account menu.
- Administrators can list and delete tokens in the Django admin.

### Headless machines and SSH

The browser must reach the loopback listener on the machine running the client. On a
remote machine, forward the callback port and open the authorize URL in a local browser:

```sh
ssh -L 53682:127.0.0.1:53682 user@remote-host
```

If `PSST_ENABLE_API_TOKEN_MANUAL_CODE` is set, clients can instead send
`redirect_uri=urn:ietf:wg:oauth:2.0:oob`. After approval, the page shows the code,
which the user pastes into the client. The code expires after 5 minutes, and the
exchange still requires PKCE and the same `redirect_uri`. This fallback is off by
default, because it lets the sign-in finish on a different device.

## Errors

Errors return JSON with an `error` message.

| Status | Meaning |
|---|---|
| `400` | Invalid input, or an invalid, expired, or reused sign-in code |
| `401` | `/api/v1/` request without the required sign-in, or with an invalid, expired, or revoked API token. Never a redirect to the login page |
| `403` | Missing or invalid reveal token, sign-in required, IP not allowed, missing token scope, or missing CSRF token on a session request |
| `404` | Unknown whisper or request, or the access endpoint is unavailable to the caller |
| `409` | A receive request has already been submitted |
| `410` | The whisper or request has expired |
| `429` | Rate limit exceeded |
| `503` | Redis is unavailable or rejected the request (for example, out of memory or unreachable), including during rate limiting. |

A `503` means the outcome is uncertain, not that nothing was stored. Failed creations
roll back their database row and try to delete any Redis entry, but that cleanup is
best-effort. Leftover entries expire with their TTL, and a link was never returned for them.
A submission may have been saved if the connection failed after Redis accepted it; if
retrying returns `409`, the earlier submission succeeded.
