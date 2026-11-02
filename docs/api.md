# API

A small JSON API runs alongside the HTML views. The OpenAPI schema is generated with
[drf-spectacular](https://drf-spectacular.readthedocs.io/).

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/whisper` | Create a send-mode whisper (ciphertext and metadata) |
| `POST` | `/api/whisper/request` | Create a receive-mode request |
| `POST` | `/api/whisper/submit/<request_id>` | Submit ciphertext to a receive-mode request |
| `GET` | `/whisper/<view_id>` | Show a confirmation page without consuming a view |
| `POST` | `/whisper/<view_id>` | Reveal ciphertext with a valid `reveal_token`; `?render=1` renders the decryption page |
| `GET`, `PATCH` | `/api/whisper/<view_id>/access` | Read or update [receive reader access](configuration.md#receive-reader-access) (creator only) |

Never send the URL fragment, decryption key, private key seed, or password to any
endpoint.

## Reveal tokens

Both creation endpoints require `reveal_token_hash`, the lowercase SHA-256 hex digest
of a client-generated token. Create the token from 32 cryptographically random bytes,
independent of all encryption keys, encode it as 64 lowercase hex characters, and hash
that ASCII string. Keep the token in the view link fragment.

Reveal requests send `reveal_token` in a JSON or form body. The token is optional only
for [legacy whispers](how-it-works.md#reveal-tokens) created before tokens existed. See
[Reveal tokens](how-it-works.md#reveal-tokens) for the full behaviour.

## Receive reader access

`POST /api/whisper/request` also accepts `creator_only` (boolean) and
`allowed_reader_emails` (up to 20 verified primary emails). The access endpoint accepts
the same fields; omitted fields keep their current values. Turning off `creator_only`
clears the approved readers, and is rejected when the restriction is mandatory.
These requests use session authentication with CSRF protection, and responses contain
only restriction settings.

## Errors

Errors return JSON with an `error` message.

| Status | Meaning |
|---|---|
| `400` | Invalid input |
| `403` | Missing or invalid reveal token, sign-in required, or IP not allowed |
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
