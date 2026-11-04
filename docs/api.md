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
| `GET`, `PATCH` | `/api/v1/whisper/<view_id>/access` | Read or update [receive reader access](configuration.md#receive-reader-access) (creator only) |

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

`GET /api/v1/info` returns the server version, the API version, and the format versions
the server accepts for new whispers:

```json
{"server_version": "v1.4.0", "api_version": 1, "format_versions": [1]}
```

## Reveal tokens

Both creation endpoints require `reveal_token_hash`; see
[Reveal tokens](format.md#reveal-tokens) for how to generate it. Reveal requests send
`reveal_token` in a JSON or form body. The token is optional only for
[legacy whispers](how-it-works.md#reveal-tokens) created before tokens existed. See
[Reveal tokens](how-it-works.md#reveal-tokens) for the full behaviour.

## Receive reader access

`POST /api/v1/whisper/request` also accepts `creator_only` (boolean) and
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
