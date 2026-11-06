# psst-secret

A zero-knowledge app for sharing secrets, which we call **whispers**. Whispers are
encrypted and decrypted in the browser, so the server never sees plaintext or keys. By
default, ciphertext is kept only in Redis memory and never touches disk.

## Features

- **Send mode:** encrypt text or files with AES-256-GCM and share a link. The key stays
  in the link's URL fragment, which is never sent to the server.
- **Receive mode:** request a whisper from someone else with a submit link. It is
  encrypted to your post-quantum hybrid X-Wing key (ML-KEM-768 + X25519).
- **Password protection:** optionally protect whispers with a password (PBKDF2).
- **Burn after reading and expiry:** limit the number of reveals and expire whispers
  after 5 minutes to 1 month.
- **Access restrictions:** limit access by IP/CIDR, require sign-in, or restrict
  receive-mode reveals to approved accounts.
- **Saved receive requests:** optionally keep your receive requests, with labels and
  status, in your own browser instead of storing each view link yourself.
- **Secret generator:** generate passwords or passphrases in the browser.
- **Formatted text:** a Markdown editor with a plain-text toggle.
- **Optional integrations:** SSO and local login (django-allauth), email notifications
  (SMTP or Azure Communication Services), and anonymous statistics.
- **API tokens:** command-line and extension clients sign in through the browser with a
  loopback redirect and PKCE, using any configured login method.
- **White-labeling:** custom name, logo, favicon, and colors.
- **Languages:** English, Danish, Czech, Swedish, and Filipino.

## Quick start

Pre-built images are published to
[ghcr.io/ch0wm3in/psst-secret](https://github.com/ch0wm3in/psst-secret/pkgs/container/psst-secret)
for every release. Start the app, PostgreSQL, and Redis (with persistence disabled):

```bash
docker compose up -d
```

The app is served by [Granian](https://github.com/emmett-framework/granian) on port
`8000`. Set at least `SECRET_KEY` and `ALLOWED_HOSTS` before exposing it.

## Documentation

| Document | Contents |
|---|---|
| [How it works](docs/how-it-works.md) | Encryption flows, storage, reveal tokens, expiry, and security model |
| [Encryption format](docs/format.md) | Versioned format specification, test vectors, and compatibility policy |
| [Configuration](docs/configuration.md) | Environment variables and optional features |
| [API](docs/api.md) | Versioned `/api/v1/` endpoints, OpenAPI schema, and error codes |
| [Development](docs/development.md) | Local setup, frontend assets, translations, tests, and regenerating the schema and test vectors |
| [Security policy](SECURITY.md) | Reporting vulnerabilities |

## License

See [LICENSE](LICENSE).

The passphrase wordlist in `static/js/wordlist-en.js` is the
[EFF Large Wordlist for Passphrases](https://www.eff.org/dice) by the Electronic
Frontier Foundation, licensed under
[CC BY 3.0 US](https://creativecommons.org/licenses/by/3.0/us/).
