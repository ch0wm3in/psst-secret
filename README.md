# psst-secret

A privacy-focused, zero-knowledge app for sharing secrets securely. We call them whispers. All encryption and decryption happens in the browser — the server never sees your plaintext. By default, encrypted data and public key material are stored only in volatile memory (Redis with persistence disabled) and never touch disk.

## Demo
<https://psst-secret-1-1-4.onrender.com/>

## Features

- **Zero-knowledge architecture** — whispers are encrypted client-side with AES-256-GCM using the [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API). Decryption key material stays in the view link's URL fragment or is protected by your password.
- **In-memory ciphertext storage** — encrypted data and public key material are stored in Redis with persistence disabled (`--save "" --appendonly no`) by default. Ciphertexts never touch disk in this configuration. If Redis restarts, all whispers are gone — by design.
- **Send mode** — encrypt a whisper (text or file) and get a shareable link.
- **Receive mode** — create a request using **X-Wing**, a hybrid of **ML-KEM-768** (post-quantum, FIPS 203) and **X25519**. Share a submit link containing the public-key fingerprint and keep a separate view link containing the private key seed. The submit link cannot be used to find, read, or burn the submitted whisper.
- **Post-quantum ready** — send mode uses 256-bit symmetric encryption; receive mode uses hybrid key exchange, which remains protected as long as either component holds.
- **Password protection** — optionally protect whispers with a password (PBKDF2, 600,000 iterations, SHA-256). In send mode, the password derives the encryption key. In receive mode, it protects your private key seed; the sender does not need your password.
- **View counter / burn-after-read** — configure how many successful reveals a whisper allows before it self-destructs. `1` = burn after first read; `0` = unlimited (no view-based destruction); any other value enforces a strict reveal counter atomically in Redis.
- **Auto-expiry** — whispers expire after a configurable duration (5 minutes to 1 month). Redis TTLs evict keys automatically, and a background thread cleans up orphaned DB metadata every 60 seconds.
- **IP/CIDR restriction** — restrict who can view (send mode) or submit (receive mode) a whisper by IP address or CIDR range.
- **Optional authentication (SSO)** — opt-in [django-allauth](https://docs.allauth.org/) integration with pluggable social providers and/or local username/password. Disabled by default.
- **Optional per-whisper auth** — individual whispers can require an authenticated viewer or submitter. Global overrides force auth for all whispers.
- **Optional email notifications** — notify the receiver (send mode) or creator (receive mode) by email when a whisper is created or submitted. Supports Django's standard SMTP backend or Azure Communication Services.
- **Opt-in anonymous statistics** — hourly aggregate submission and reveal counts, retained for 365 days, with relative time filters. Disabled by default; enable with `PSST_ENABLE_STATS=True`.
- **Internationalization** — English, Danish (`da`), Czech (`cs`), Swedish (`sv`), and Filipino (Tagalog, `fil`) out of the box, with a per-request language switcher.
- **No-cache headers** — middleware ensures browsers and proxies never cache whisper pages.

## How it works

### Send mode

1. You enter a whisper (text or file) in the browser.
2. A random AES-256-GCM key is generated client-side.
3. The whisper is encrypted in-browser. Only the ciphertext and encryption parameters are sent to the server.
4. The key is placed in the URL fragment (`#key`), which is never sent to the server. If you set a password, the key is derived from it instead and the link contains no key fragment.
5. You share the link. The recipient's browser decrypts it using the key from the fragment or a key derived from the password you share separately.

For a password-protected whisper, the recipient enters the password to derive the key locally. The server stores only the random PBKDF2 salt, not the password or derived key.

Send mode uses symmetric AES-256-GCM encryption, not public-key cryptography. Grover's algorithm at most halves the effective key strength to 128 bits; Shor's algorithm does not apply to this symmetric cipher.

### Receive mode

1. You configure options (expiry, password, burn-after-read, IP restriction) and create a request. Your browser generates an **X-Wing** key pair using ML-KEM-768 and X25519.
2. The public key is stored on the server. You get a **submit link** containing its fingerprint and a **view link** containing the private key seed in its fragment. If you set a password, the seed is encrypted with that password instead.
3. You share the submit link and keep the view link. These links use different random identifiers, so the submit link does not reveal the view link.
4. The sender's browser verifies the public key against the fingerprint in the submit link, preventing the server from substituting a different key. It encrypts the whisper to your public key using X-Wing, HKDF-SHA256, and AES-256-GCM, then uploads the ciphertext and key encapsulation. The sender does not need your password.
5. You open your view link and, if required, enter your password. Your browser uses the private key seed to decrypt the whisper. The submit link alone cannot decrypt it.

The hybrid key exchange protects receive-mode whispers as long as either ML-KEM-768 or X25519 remains secure, including against attackers who record encrypted traffic today to try to decrypt it with a quantum computer later.

### Why the URL fragment?

The fragment is the part of a URL after `#`. [RFC 3986 §3.5](https://www.rfc-editor.org/rfc/rfc3986#section-3.5) reserves it for browser-side processing, and [RFC 9110 §7.1](https://www.rfc-editor.org/rfc/rfc9110#section-7.1) excludes it from HTTP requests. Key material in the fragment is therefore not sent to the server or included in HTTP request logs. Password-protected view links contain no decryption key fragment.

## Requirements

- Python 3.14
- Django 6.0+
- Node.js 20+ and npm (local frontend builds only)
- Redis 7+ (persistence disabled)
- PostgreSQL 16+ (optional — SQLite works for development)

## Quick start

### Using Docker (recommended)

Pre-built images are published to [ghcr.io/ch0wm3in/psst-secret](https://github.com/ch0wm3in/psst-secret/pkgs/container/psst-secret) on every release tag.

```bash
# Bring up app + PostgreSQL + Redis (Redis runs with persistence disabled)
docker compose up -d
```

The app is served by [Granian](https://github.com/emmett-framework/granian) on port `8000`.

### Local development

```bash
git clone https://github.com/ch0wm3in/psst-secret.git && cd psst-secret
uv sync  # or: pip install -e .
python manage.py tailwind install
python manage.py tailwind build

# Start Redis (no persistence — ciphertexts stay in RAM only)
docker compose up -d redis

python manage.py migrate
python manage.py runserver
```

Open [http://localhost:8000](http://localhost:8000).

While changing templates or frontend JavaScript, run the Tailwind watcher in a
separate terminal:

```bash
python manage.py tailwind start
```

Tailwind, Alpine.js, and noble-post-quantum are installed from the locked npm dependencies in
`theme/static_src/`. Production Docker builds compile these into local Django
static assets, so the application does not depend on CDNs at runtime.

## Architecture

psst-secret uses a split storage model:

| Store | What it holds | Persistence |
|---|---|---|
| **Redis** | Ciphertext, IV, PBKDF2 salt, receive-mode public key, key encapsulation, password-encrypted private key seed and its IV, remaining-views counter | **In-memory only by default** — `--save "" --appendonly no` |
| **PostgreSQL / SQLite** | Metadata: view identifier, separate submit token, creation and expiry timestamps, mode, max-views, IP restriction, auth flags, optional notification email | On disk |

With the default configuration, encrypted data **never touches disk**. If Redis restarts, all ciphertexts are lost (a feature, not a bug). Orphaned DB metadata is cleaned up automatically — the background thread and on-access checks both delete DB rows when their Redis key is gone. The server does not store plaintext, unencrypted private keys, or passwords. An email address is stored only if you opt in to notifications.

> A [persistence-enabled Compose example](docker-compose-with-persistence-example.yml) is provided for users who explicitly want Redis persistence (e.g. for a long-lived single-node deployment with periodic restarts). Enabling persistence writes encrypted data to disk and retains it across restarts; it does not give the server decryption keys, but it removes the in-memory-only storage guarantee. Set `ABOUT_PAGE_PERSISTENCE_ENABLED=True` so the About page accurately describes your deployment.

### Expiry & view-counter: belt and suspenders

1. **Redis TTL** — each key is stored with a TTL matching the whisper's expiry. Redis evicts them automatically.
2. **Atomic reveal counter** — each successful reveal decrements a Redis counter using `WATCH`/`MULTI`/`EXEC`. When the counter reaches zero the whisper is deleted in the same transaction (no race conditions, even under concurrent reveals).
3. **Background thread** — runs every 60s, deletes expired DB rows and their Redis keys (defense-in-depth).
4. **On-access cleanup** — if a user visits a whisper whose Redis key has vanished, the orphaned DB row is deleted immediately.

## Environment variables

### Core

| Variable | Description | Default |
|---|---|---|
| `SECRET_KEY` | Django secret key. **Required in production** (app refuses to start with the insecure default when `DEBUG=False`). | Insecure default (dev only) |
| `DEBUG` | Enable Django debug mode. | `False` |
| `ALLOWED_HOSTS` | Comma-separated list of allowed hostnames. | `localhost,127.0.0.1` |
| `DATABASE_URL` | Database connection string ([dj-database-url](https://github.com/jazzband/dj-database-url) format). | `sqlite:///db.sqlite3` |
| `REDIS_URL` | Redis connection string for in-memory ciphertext storage. | `redis://localhost:6379/0` |

### Security

| Variable | Description | Default |
|---|---|---|
| `NUM_PROXIES` | Number of trusted reverse proxies in front of Django. Controls how `X-Forwarded-For` is parsed for IP-based restrictions and rate limiting. `0` = ignore the header and use `REMOTE_ADDR`. | `0` |
| `MAX_UPLOAD_SIZE` | Maximum request body size in bytes (caps encrypted payload size). | `10000000` |
| `CSRF_TRUSTED_ORIGINS` | Comma-separated list of origins (scheme + host) trusted for CSRF (e.g. `https://psst.example.com`). | _empty_ |

### Statistics

| Variable | Description | Default |
|---|---|---|
| `PSST_ENABLE_STATS` | Enable anonymous statistics collection and the `/stats` page. Requires login when `ENABLE_AUTH=True`. | `False` |

After running `python manage.py migrate`, enable statistics in your environment:

```bash
PSST_ENABLE_STATS=True
```

Restart the app after changing this setting. When disabled, no statistics are collected, the navigation link is hidden, and `/stats` returns 404. Existing counters continue to expire even while collection is disabled. Collection starts when enabled; there is no historical backfill.

The page offers 1 day, 1 week (default), 1 month, 3 months, 6 months, and 1 year. Months use 30 days and a year uses 365 days. Windows are rounded to UTC hours, include the current partial hour, and show their actual boundaries. It reports total submitted whispers, sends versus completed receives, daily trends and averages, busiest days and weekdays, burn-after-read share, expiry choices, and successful reveals. Pending receive requests do not count as submissions. Reveals mean ciphertext delivered by the server, not unique readers or confirmed client-side decryptions.

Only fixed hourly counters are stored in PostgreSQL / SQLite, with no whisper identifiers, content, keys, IP addresses, accounts, emails, or individual event records. No third-party analytics or visitor tracking is used. These counters survive whisper deletion and Redis restarts. Exact live totals can still reveal aggregate activity on a quiet instance; this is not differential privacy.

Buckets older than the rolling 365-day cutoff are removed by the existing background cleanup every 60 seconds, by `python manage.py cleanup_expired`, and when the stats page is read. Old buckets are excluded from reports regardless of cleanup timing. Entire boundary buckets are discarded, so up to an hour of otherwise valid history may be omitted. Database backups and infrastructure logs require their own retention policies. Counter recording is best-effort: database failures or process crashes can undercount, but do not prevent whisper delivery.

### Email notifications

| Variable | Description | Default |
|---|---|---|
| `PSST_ENABLE_EMAIL` | Enable email notifications (sender / creator notifications on creation and submission). | `False` |
| `EMAIL_BACKEND` | Django email backend. Use `django.core.mail.backends.smtp.EmailBackend` for SMTP or `azure_communication_email.EmailBackend` for Azure Communication Services. | `django.core.mail.backends.console.EmailBackend` |
| `DEFAULT_FROM_EMAIL` | From-address used for all outbound mail. | `noreply@localhost` |
| `AZURE_COMMUNICATION_CONNECTION_STRING` | Azure Communication Services connection string. Only required when using the Azure email backend. | _empty_ |

### Authentication (SSO / allauth)

All authentication features are **disabled by default**. Set `ENABLE_AUTH=True` to activate them.

| Variable | Description | Default |
|---|---|---|
| `ENABLE_AUTH` | Enable django-allauth authentication. Adds login-required middleware, allauth apps, and the `/login/` page. | `False` |
| `ENABLE_LOCAL_LOGIN` | Allow username/password login (in addition to SSO providers). Only takes effect when `ENABLE_AUTH=True`. | `False` |
| `PSST_FORCE_AUTH_VIEW` | Require authentication to **view** all whispers (overrides per-whisper setting). | `False` |
| `PSST_FORCE_AUTH_SUBMIT` | Require authentication to **submit** to all receive-mode requests (overrides per-whisper setting). | `False` |
| `ACCOUNT_DEFAULT_HTTP_PROTOCOL` | Protocol used by allauth when building absolute URLs in emails. | `https` (`http` in `DEBUG`) |
| `ACCOUNT_EMAIL_VERIFICATION` | allauth email verification mode: `"mandatory"`, `"optional"`, or `"none"`. | `"none"` |
| `LOGIN_REQUIRED_EXEMPT_URLS` | Comma-separated regex patterns for paths that bypass the login requirement (matched without leading `/`). | `login/,accounts/.*,i18n/.*,static/.*` |
| `SOCIAL_AUTH_PROVIDERS` | Comma-separated list of allauth social provider names to enable (e.g. `google,github`). | _empty_ |
| `{PROVIDER}_SOCIAL_AUTH_CONFIG` | JSON configuration for each social provider (uppercased provider name, e.g. `GOOGLE_SOCIAL_AUTH_CONFIG`). | `{}` |

### Rate limiting

| Variable | Description | Default |
|---|---|---|
| `API_THROTTLE_RATE_ANON` | Global anonymous API rate limit (DRF format, e.g. `100/hour`). | `60/minute` |
| `API_THROTTLE_RATE_CREATE` | Rate limit for whisper/request creation and submit API endpoints. | `20/minute` |
| `THROTTLE_RATE_VIEW` | Rate limit for the whisper view page (per IP, cache-based). | `30/minute` |

### Branding & build info

| Variable | Description | Default |
|---|---|---|
| `BRAND_COLORS` | Tailwind color palette as JSON (shade → hex). | Teal palette |
| `ABOUT_PAGE_PERSISTENCE_ENABLED` | When `True`, the about page describes Redis as persisted (use this if you have explicitly enabled Redis persistence). | `False` |

Example custom brand colors (blue):

```bash
BRAND_COLORS='{"50":"#eff6ff","100":"#dbeafe","200":"#bfdbfe","300":"#93c5fd","400":"#60a5fa","500":"#3b82f6","600":"#2563eb","700":"#1d4ed8","800":"#1e40af","900":"#1e3a8a","950":"#172554"}'
```

## Translations

The UI is available in English, Danish, Czech, Swedish, and Filipino (Tagalog). The language switcher keeps each language's native name: **English**, **Dansk**, **Čeština**, **Svenska**, and **Filipino**. Filipino uses the `fil` locale code. Translations live in `locale/<lang>/LC_MESSAGES/` and are split into two catalogs:

| Catalog | Covers | How to mark strings |
|---|---|---|
| `django.po` | Templates (including inline `<script>` blocks in templates) and Python code | `{% trans "…" %}` / `{% blocktrans %}` in templates, `gettext()` in Python |
| `djangojs.po` | Standalone JavaScript files in `static/js/` | `gettext('…')`, and `interpolate(gettext('… %s …'), [value])` for dynamic values |

JavaScript translations are served by Django's `JavaScriptCatalog` at `/jsi18n/`, which is loaded in `base.html` before any other script, so `gettext()` and `interpolate()` are available globally.

Keep dynamic values out of the translatable text — never build sentences with string concatenation, since word order differs between languages:

```js
// Good
interpolate(gettext('This whisper will be destroyed after %s views.'), [maxViews]);
// Bad — cannot be translated correctly
'This whisper will be destroyed after ' + maxViews + ' views.';
```

### Updating translations

After adding or changing user-facing strings, regenerate both catalogs:

```bash
# Templates + Python
uv run --env-file .env python manage.py makemessages -l da -l cs -l sv -l fil --ignore='node_modules' --ignore='theme/static_src/*' --ignore='staticfiles/*' --ignore='.venv/*'

# Standalone JavaScript
uv run --env-file .env python manage.py makemessages -l da -l cs -l sv -l fil -d djangojs --ignore='node_modules' --ignore='theme/*' --ignore='staticfiles/*' --ignore='.venv/*'
```

Then fill in the empty `msgstr ""` entries (and review any `#, fuzzy` ones) in each language's `django.po` and `djangojs.po` catalogs, validate, and compile:

```bash
uv run --env-file .env python scripts/check_translations.py
uv run --env-file .env python manage.py compilemessages -l da -l cs -l sv -l fil
```

The Docker entrypoint runs `compilemessages` on startup, but commit the compiled `.mo` files as well so local development picks them up.

To add a new language, add it to `LANGUAGES` in `psst_secret/settings.py` and run the commands above with `-l <code>`.

## Project structure

```
psst_secret/             Django project config (settings, urls, wsgi, asgi)
theme/                   django-tailwind app and compiled frontend assets
├── static_src/          Locked Tailwind, Alpine.js, and noble-post-quantum build dependencies
└── static/              Generated CSS and JavaScript served by Django
whispers/                Main app
├── models.py            Whisper model (metadata only — no ciphertext fields)
├── stats.py             Opt-in anonymous hourly counters and 365-day retention
├── redis_store.py       Redis helpers for in-memory ciphertext + atomic reveal counter
├── views.py             API + page views (create, reveal, submit)
├── auth_views.py        Custom login page (allauth integration)
├── serializers.py       DRF serializers for the JSON API
├── email.py             Email notifications (Django SMTP or Azure Communication Services)
├── constants.py         Expiry deltas shared between server and admin
├── middleware.py        No-cache + login-required middleware
├── apps.py              App config + background cleanup thread
├── urls.py              URL routing
├── admin.py             Django admin config
├── management/          Management commands (e.g. cleanup_expired)
├── templatetags/        Custom template tags (settings_value, to_json, …)
├── tests/               pytest-django test suite
└── migrations/          Database migrations
static/js/crypto.js      Client-side AES-256-GCM, X-Wing, HKDF-SHA256, and password protection
templates/               Django templates (Tailwind CSS)
locale/                  Translations (Danish, Czech, Swedish, Filipino; English source strings)
```

## API

A small JSON API is exposed alongside the HTML views. The OpenAPI schema is generated via [drf-spectacular](https://drf-spectacular.readthedocs.io/).

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/whisper` | Create a send-mode whisper (ciphertext + metadata) |
| `POST` | `/api/whisper/request` | Create a receive-mode request |
| `POST` | `/api/whisper/submit/<request_id>` | Submit ciphertext to a receive-mode request |

## Security properties

- By default, the server stores encrypted data and public key material **only in Redis memory** — never on disk (unless persistence is explicitly enabled). Metadata (identifiers, timestamps, mode, flags, counter limit, optional notification email) lives in PostgreSQL / SQLite.
- The URL fragment is never sent to the server per the HTTP specification. Send links carry the symmetric key; receive view links carry the private key seed. Password-protected view links carry neither.
- AES-256-GCM provides authenticated encryption — tampering is detected.
- Receive mode uses X-Wing (ML-KEM-768 + X25519), HKDF-SHA256, and AES-256-GCM. The submit-link fingerprint binds the sender's encryption to the request creator's public key.
- Separate random submit and view identifiers prevent a submit-link holder from finding, reading, or burning the submitted whisper.
- Password-derived keys use PBKDF2 with 600,000 iterations and SHA-256. In receive mode, the password encrypts the private key seed; it is not required for submission.
- The reveal counter is decremented atomically in Redis (`WATCH`/`MULTI`/`EXEC`); when it reaches zero the whisper is deleted in the same transaction. Burn-after-read (`max_views=1`) is the default.
- Redis runs with persistence disabled (`--save "" --appendonly no`) by default — all ciphertexts are lost on restart.
- If Redis evicts a key before the DB row is cleaned up, the next access deletes the orphaned row automatically.
- The app refuses to start in production (`DEBUG=False`) with the insecure default `SECRET_KEY`.

## License

See [LICENSE](LICENSE).
