# Encryption format

This is the normative specification of the psst-secret encryption format, link
fragments, and reveal tokens. [`static/js/crypto.js`](../static/js/crypto.js) and any
other client implement it, and the [test vectors](#test-vectors) check it. For the
security model, see [How it works](how-it-works.md). For endpoints, see [API](api.md).

## Versions

| Version | Status |
|---|---|
| `0` | Legacy. Links and payloads created before format versioning. Uses the same algorithms and layouts as version 1, but carries no version marker. Read only. |
| `1` | Current. |

Clients must:

- write `v=1` in every link fragment and `"v": 1` in every API request that carries
  ciphertext or key material;
- treat a missing `v` as version 0;
- reject a version they do not support before sending a reveal request, submitting, or
  decrypting.

The [`GET /api/v1/info`](api.md#server-info) endpoint lists the format versions a
server accepts. The server stores `v` with the ciphertext and returns it on reveal.

## Encoding

- **Binary values** use standard base64 with padding
  ([RFC 4648 §4](https://www.rfc-editor.org/rfc/rfc4648#section-4)), in JSON and in
  fragments.
- **Text**, including passwords, is encoded as UTF-8 without normalization.
- **Fragments** are `application/x-www-form-urlencoded`, as produced by
  `URLSearchParams`, so base64 `+`, `/`, and `=` are percent-encoded. Parameter order
  is not significant, and clients ignore unknown parameters.
- **AES-256-GCM** uses a random 12-byte IV, no additional data, and a 16-byte tag. The
  `ciphertext` field is `base64(ciphertext || tag)`, as returned by Web Crypto.

## Plaintext envelope

Before encryption, the whisper is serialized as UTF-8 JSON:

| Type | Envelope |
|---|---|
| Text | `{"type": "text", "content": "...", "format": "markdown"}`. `format` is optional; without it the content is plain text. |
| Files | `{"type": "files", "files": [{"filename": "...", "mimetype": "...", "data": "<base64>"}]}` |

Readers also accept the legacy single-file envelope
`{"type": "file", "filename": "...", "mimetype": "...", "data": "<base64>"}`, and show
any other plaintext as text. Treat filenames as untrusted: strip path separators and
null bytes before saving.

## Reveal tokens

Every whisper has a reveal token, independent of all encryption keys:

1. Generate 32 random bytes and encode them as 64 lowercase hex characters. This string
   is the token.
2. Send `reveal_token_hash`, the lowercase hex SHA-256 digest of the token's ASCII
   bytes, when creating the whisper.
3. Keep the token in the view link fragment as `reveal`, and send it as `reveal_token`
   only in the reveal request.

## Send mode

1. Generate a random 32-byte AES-256-GCM key.
2. Encrypt the envelope. Send `ciphertext`, `iv`, and an empty `salt`.
3. View link fragment: `v=1&reveal=<token>&key=<base64 key>`.

### Password protection

The key is derived from the password instead of generated:

| Parameter | Value |
|---|---|
| KDF | PBKDF2-HMAC-SHA256 |
| Iterations | 600,000 |
| Salt | 16 random bytes, sent as `salt` |
| Output | 32-byte AES-256-GCM key |

View link fragment: `v=1&reveal=<token>`. The password is shared separately.

## Receive mode

The recipient creates a request with an **X-Wing** key pair (ML-KEM-768 + X25519,
[draft-connolly-cfrg-xwing-kem](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/)):

| Value | Size |
|---|---|
| Seed (private key) | 32 bytes |
| Public key | 1,216 bytes |
| Encapsulated key | 1,120 bytes |
| Shared secret | 32 bytes |

1. **Request.** Generate a random seed and derive the key pair. Send `public_key`. The
   fingerprint is `base64(SHA-256(public key))`.
   - Submit link fragment: `v=1&fp=<fingerprint>`.
   - View link fragment: `v=1&reveal=<token>&key=<base64 seed>`.
2. **Password protection (optional).** Encrypt the seed with AES-256-GCM under a
   password-derived key (same PBKDF2 parameters as send mode). Send `salt`,
   `wrapped_key_iv`, and `wrapped_key`, and leave `key` out of the view link fragment.
3. **Submit.** The sender fetches the public key, checks its SHA-256 digest against
   `fp`, and stops if they differ. The sender then encapsulates to the public key and
   derives the AES-256-GCM key with HKDF:

   | Parameter | Value |
   |---|---|
   | Hash | SHA-256 |
   | Input key material | X-Wing shared secret |
   | Salt | 32 zero bytes |
   | Info | ASCII `psst-receive-v2` |
   | Output | 32 bytes |

   The sender encrypts the envelope and sends `ciphertext`, `iv`, and
   `encapsulated_key`. The `psst-receive-v2` label predates format versioning and is
   part of format version 1.
4. **Reveal.** The recipient regenerates the key pair from the seed, decapsulates
   `encapsulated_key`, derives the same key, and decrypts.

## Legacy links

Version 0 links have no `v` parameter:

| Link | Fragment |
|---|---|
| View | `reveal=<token>&key=<key>` or `reveal=<token>` |
| View, before reveal tokens | `<base64 key>` only |
| Submit | `<base64 fingerprint>` only |

## Test vectors

[`spec/vectors/v1/`](../spec/vectors/v1/) holds fixed inputs and expected outputs for
each mode: `send.json`, `password.json`, and `receive.json`. Each case lists its
random inputs (key, seed, salt, IV, X-Wing encapsulation randomness, and reveal token),
the plaintext, and the expected ciphertext, token hash, and fragments.

The vectors are generated by
[`spec/vectors/generate.mjs`](../spec/vectors/generate.mjs), independently of
`crypto.js`. The Playwright test `whispers/tests/browser/test_format.py` runs them
against `crypto.js` in CI. See [Development](development.md#format-specification-and-api-schema)
to regenerate them.

## Compatibility policy

These rules apply to this format and to the [versioned API](api.md):

- **Additive only within a version.** Version 1 may gain new optional JSON fields,
  fragment parameters, and endpoints. Fields and parameters are never renamed, removed,
  or given a different meaning. Clients ignore what they do not recognize.
- **Breaking changes bump the version.** A new algorithm, parameter, encoding, layout,
  or required field becomes format version 2 (or `/api/v2/`). During a deprecation
  window, servers and clients support both versions.
- **Old whispers stay readable.** Clients keep decrypting a format version for at least
  the maximum whisper lifetime (currently 1 month) after they stop writing it.
