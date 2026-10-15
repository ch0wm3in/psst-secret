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
- **Secret generator** — in send mode, generate a password or an English passphrase straight into the whisper with **Generate secret**, or open the options dialog next to it to choose the length, character types and minimum counts, ambiguous-character avoidance, word count, separator, capitalization, and the number and position of symbols, with a live preview and entropy estimate. The password field's **Generate** button uses a preset that meets the password requirements. Everything is generated in the browser with `crypto.getRandomValues` and unbiased rejection sampling; nothing is sent to the server. Passphrases use the [EFF large wordlist](https://www.eff.org/dice). Other scripts can call `window.PsstSecretGenerator.generate('password' | 'passphrase' | 'whisperPassword', overrides)`.
- **View counter / burn-after-read** — configure how many successful reveals a whisper allows before it self-destructs. `1` = burn after first read; `0` = unlimited (no view-based destruction); any other value enforces a strict reveal counter atomically in Redis.
- **Auto-expiry** — whispers expire after a configurable duration (5 minutes to 1 month). Redis TTLs evict keys automatically, and a background thread cleans up orphaned DB metadata every 60 seconds.
- **IP/CIDR restriction** — restrict who can view (send mode) or submit (receive mode) a whisper by IP address or CIDR range.
- **Optional authentication (SSO)** — opt-in [django-allauth](https://docs.allauth.org/) integration with pluggable social providers and/or local username/password. Disabled by default.
- **Optional per-whisper auth** — individual whispers can require an authenticated viewer or submitter. Global overrides force auth for all whispers.
- **Opt-in receive reader access** — restrict receive-mode reveals to the creator and approved accounts, selected by verified primary email. Creators can edit access from the reveal link without revealing or burning the whisper. Optional defaults and mandatory restrictions are configurable.
- **Optional email notifications** — notify the receiver (send mode) or creator (receive mode) by email when a whisper is created or submitted. Supports Django's standard SMTP backend or Azure Communication Services.
- **Opt-in anonymous statistics** — hourly aggregate submission and reveal counts, retained for 365 days, with relative time filters. Disabled by default; enable with `PSST_ENABLE_STATS=True`.
- **Internationalization** — English, Danish (`da`), Czech (`cs`), Swedish (`sv`), and Filipino (Tagalog, `fil`) out of the box, with a per-request language switcher.
- **Deployment summary** — the About page lists which optional features and sign-in requirements are enabled on the instance, in plain language for end users.
- **White-labeling** — replace the application name, logo, favicon, and brand colors, and hide the GitHub links, footer tagline, and navigation-bar name, all through environment variables.
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
# Setup .env file
# source the env file however you want
source .venv/bin/activate
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

Tailwind, Alpine.js, noble-post-quantum, and esbuild are installed from the locked npm dependencies in
`theme/static_src/`. The frontend build also minifies the custom scripts in `static/js/`
into `theme/static/js/crypto.min.js` and `theme/static/js/password-strength.min.js`,
which are loaded by the templates. Keep editing the readable source files, not the
generated assets. Production Docker builds compile all frontend assets locally,
so the application does not depend on CDNs at runtime.

The Tailwind watcher builds the JavaScript assets once at startup but only watches
CSS changes. After editing a custom JavaScript source, rebuild it with:

```bash
npm --prefix theme/static_src run build:custom
```

Run `python manage.py tailwind build` to rebuild all frontend
assets, then run `collectstatic` as usual for production deployments.

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
| `EMAIL_BACKEND` | Backend for `MAILERS["default"]`. This environment variable remains supported; the deprecated Django `EMAIL_BACKEND` setting is no longer used. Use `django.core.mail.backends.smtp.EmailBackend` for SMTP or `django_better_azure_communication_email.EmailBackend` for Azure Communication Services. | `django.core.mail.backends.console.EmailBackend` |
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
| `PSST_ENABLE_RECEIVE_ACCESS` | Enable creator-owned receive requests and reader-access controls. Requires `ENABLE_AUTH=True`. | `False` |
| `PSST_RECEIVE_ACCESS_DEFAULT` | Enable restricted reader access by default for new receive requests; creators can turn it off. Requires the feature and authentication to be enabled. | `False` |
| `PSST_FORCE_RECEIVE_ACCESS` | Require restricted access for new receive requests and access updates; creators cannot turn it off. Overrides the default setting. Requires the feature and authentication to be enabled. | `False` |
| `ACCOUNT_DEFAULT_HTTP_PROTOCOL` | Protocol used by allauth when building absolute URLs in emails. | `https` (`http` in `DEBUG`) |
| `ACCOUNT_EMAIL_VERIFICATION` | allauth email verification mode: `"mandatory"`, `"optional"`, or `"none"`. | `"none"` |
| `LOGIN_REQUIRED_EXEMPT_URLS` | Comma-separated regex patterns for paths that bypass the login requirement (matched without leading `/`). | `login/,accounts/.*,i18n/.*,static/.*` |
| `SOCIAL_AUTH_PROVIDERS` | Comma-separated list of allauth social provider names to enable (e.g. `google,github`). | _empty_ |
| `{PROVIDER}_SOCIAL_AUTH_CONFIG` | JSON configuration for each social provider (uppercased provider name, e.g. `GOOGLE_SOCIAL_AUTH_CONFIG`). | `{}` |

### Receive reader access

Enable the optional feature with:

```bash
ENABLE_AUTH=True
PSST_ENABLE_RECEIVE_ACCESS=True
```

Set `PSST_RECEIVE_ACCESS_DEFAULT=True` to start with **Only me and approved readers**
checked while allowing creators to disable it. Set `PSST_FORCE_RECEIVE_ACCESS=True`
instead to make the restriction mandatory. These settings do not retroactively
restrict existing requests.

Run `python manage.py migrate` after upgrading. Requests
created by signed-in users while this feature is enabled record their creator,
even if the restriction is initially off. Older requests without a recorded creator
cannot use the access editor. Anonymous callers cannot create restricted requests.

Additional readers must already have active accounts with unique, verified primary
email addresses in django-allauth. Enter up to 20 addresses, separated by commas,
semicolons, spaces, or newlines. No invitations or keys are emailed, and no account
directory is exposed. Grants are bound to account IDs, not future registrations
with the same email address. The creator remains a reader and is the only account
that can edit access; approved readers and administrators have no implicit management
or reveal bypass.

Open the reveal link to edit access while a request is pending, before revealing it,
or after a reveal that has not exhausted its view limit. Saving access does not
consume a reveal. Restricted reveals require sign-in even if a login middleware
exemption permits visiting the URL. Submitter authentication remains controlled
separately by the existing submit settings.

Approved readers still need the complete reveal link (including its private key
fragment, where applicable) and any password. Share those separately. All readers
share the existing view limit, so a single-view whisper is destroyed after the first
authorized reveal. Revoking an account blocks future retrievals, not in-flight
retrievals or ciphertext/plaintext already obtained. Disabling the feature or
authentication does not silently unlock previously restricted whispers; authentication
must be restored to read them. Deleting the creator account deletes its owned
request metadata; any remaining Redis ciphertext expires by its existing TTL.

Creator and reader account references are operational metadata in PostgreSQL/SQLite,
not analytics. They are never included in anonymous statistics. Ciphertext and key
material remain in Redis, and private keys and passwords remain client-side.

### Rate limiting

| Variable | Description | Default |
|---|---|---|
| `API_THROTTLE_RATE_ANON` | Global anonymous API rate limit (DRF format, e.g. `100/hour`). | `60/minute` |
| `API_THROTTLE_RATE_CREATE` | Rate limit for whisper/request creation and submit API endpoints. | `20/minute` |
| `THROTTLE_RATE_VIEW` | Rate limit for the whisper view page (per IP, cache-based). | `30/minute` |
| `API_THROTTLE_RATE_RECEIVE_ACCESS` | Shared per-account limit for authenticated receive creation and access-management requests, including failed reader-email lookups. | `10/minute` |

Reader-email validation reveals whether an address is eligible for access. Both
receive creation and access-management requests share the limit above, keyed by
the signed-in account rather than client IP. Invalid addresses consume the same
budget as successful requests; exceeding it returns HTTP 429 before looking up
reader accounts. Anonymous requests retain their existing per-IP limits. This
limits account enumeration but does not eliminate the eligibility signal.

### Branding & build info

| Variable | Description | Default |
|---|---|---|
| `BRAND_COLORS` | Tailwind color palette as JSON (shade → hex). | Teal palette |
| `PSST_BRAND_NAME` | Application name shown in the navigation bar, browser tab titles, sign-in page, About page, footer, notification emails, and API docs. | `psst-secret` |
| `PSST_BRAND_LOGO_URL` | Logo image that replaces the 🤫 emoji in the navigation bar and sign-in page. Emails link to an absolute `http(s)` URL directly and embed a `data:image/` URI as an inline attachment referenced by `cid:`; root-relative paths are left out of emails. Many email clients do not render SVG, so use PNG for email logos. | *(emoji)* |
| `PSST_BRAND_FAVICON_URL` | Favicon that replaces the default 🤫 icon. | `/static/favicon.svg` |
| `PSST_HIDE_SOCIAL_LINKS` | Hide the GitHub repository link in the footer and show the version as plain text instead of linking to GitHub releases. | `False` |
| `PSST_HIDE_FOOTER_TEXT` | Hide the `<name> — Psst! Don't tell anyone.` tagline in the footer. | `False` |
| `PSST_HIDE_NAV_BRAND_NAME` | Hide the application name next to the logo in the navigation bar and sign-in page (useful when the logo already contains the name). The name stays in tab titles and remains available to screen readers. | `False` |
| `ABOUT_PAGE_PERSISTENCE_ENABLED` | When `True`, the about page describes Redis as persisted (use this if you have explicitly enabled Redis persistence). | `False` |

Example custom brand colors (blue):

```bash
BRAND_COLORS='{"50":"#eff6ff","100":"#dbeafe","200":"#bfdbfe","300":"#93c5fd","400":"#60a5fa","500":"#3b82f6","600":"#2563eb","700":"#1d4ed8","800":"#1e40af","900":"#1e3a8a","950":"#172554"}'
```

Example white-label configuration:

```bash
PSST_BRAND_NAME="Acme Secrets"
PSST_BRAND_LOGO_URL=https://assets.acme.example/logo.svg
PSST_BRAND_FAVICON_URL=https://assets.acme.example/favicon.ico
PSST_HIDE_SOCIAL_LINKS=True
PSST_HIDE_FOOTER_TEXT=True
PSST_HIDE_NAV_BRAND_NAME=True
```

Logo and favicon values must be an absolute `http(s)` URL, a path starting with `/`
(for example, an asset served by your reverse proxy), or a `data:image/` URI that embeds
the image directly in the variable. Startup fails with system check `whispers.E001`
for anything else. Externally hosted images are fetched by every visitor's browser, so
the image host can see visitor IP addresses. Use a same-origin path or a `data:` URI to
avoid this. The URL fragment that holds the key is never sent with these requests.

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
python manage.py makemessages -l da -l cs -l sv -l fil --ignore='node_modules' --ignore='theme/static_src/*' --ignore='staticfiles/*' --ignore='.venv/*'

# Standalone JavaScript
python manage.py makemessages -l da -l cs -l sv -l fil -d djangojs --ignore='node_modules' --ignore='theme/*' --ignore='staticfiles/*' --ignore='.venv/*'
```

Then fill in the empty `msgstr ""` entries (and review any `#, fuzzy` ones) in each language's `django.po` and `djangojs.po` catalogs, validate, and compile:

```bash
python scripts/check_translations.py
python manage.py compilemessages -l da -l cs -l sv -l fil
```

The Docker entrypoint runs `compilemessages` on startup, but commit the compiled `.mo` files as well so local development picks them up.

To add a new language, add it to `LANGUAGES` in `psst_secret/settings.py` and run the commands above with `-l <code>`.

## Testing

Run the Django suite as usual. Browser cases are skipped unless explicitly enabled:

```bash
pytest -n 4
```

The Playwright tests in `whispers/tests/browser/` run real client-side encryption
against an isolated Django live test server. They use a fresh fake Redis store per
test and Django's test database, never the running application's data. With
`pytest-xdist`, each worker gets its own database, browser, cache, and Redis state;
live servers bind to random ports. The production cleanup loop is disabled by the
test app configuration so it cannot interfere with test data. No separate
development server or Redis service is needed. For a fully local run without
PostgreSQL, select SQLite with `DATABASE_URL=sqlite:///:memory:` as shown below.

Install the browser binaries once, and rebuild the frontend assets after changing
JavaScript or templates (Node.js is required for the asset build):

```bash
uv sync --locked
playwright install chromium firefox
npm ci --prefix theme/static_src
python manage.py tailwind build
pytest whispers/tests/browser --browser-tests -n 4
```

On Linux, Playwright may require system libraries. Install them using
`playwright install-deps chromium firefox`; this may require
administrator privileges.

Run both browser engines, keep failure screenshots and traces, or run the complete
Django and browser suites together:

```bash
pytest whispers/tests/browser --browser-tests -n 4 --browser chromium --browser firefox --tracing=retain-on-failure --screenshot=only-on-failure
pytest --browser-tests -n 4
```

Adjust `-n 4` to fit your machine's CPU and memory; use `-n 0` to run sequentially.
For interactive debugging, use `-n 0 --headed`, or `-k <test_name>` to target a workflow. Open a
failure trace with `playwright show-trace <path-to-trace.zip>`.
Artifacts under `test-results/` are ignored by Git. They contain synthetic test
plaintext, passwords, and keys, so treat them as sensitive if you adapt the suite
to use other data. Never point these tests at a deployed instance.

Browser coverage includes send and receive text/file round trips; individual and
bulk downloads; passwords and retries; expiry, burns, and view limits; IP and
authentication restrictions; approved-reader management and revocation; email
notifications; clipboard actions; all supported languages; live statistics;
desktop/mobile rendering; legacy payloads; and validation, network, and server
errors. Security assertions cover fragment isolation, plaintext/password/key
privacy, authenticated CSRF checks, ciphertext tampering, and safe text rendering.

Browser tests complement, rather than replace, the Django tests for internal
model/serializer behavior, concurrent Redis transitions, cleanup commands, and
email failure handling. Real SSO providers, SMTP/Azure delivery, and production
proxy/deployment configuration require separate integration testing. Browser
sessions enable `DJANGO_ALLOW_ASYNC_UNSAFE` only inside the test process to allow
Playwright's synchronous event loop to coexist with Django's synchronous test ORM;
application settings are unchanged.

Pull-request CI runs independent Unit Tests and E2E Tests jobs concurrently.
The unit job excludes browser tests and uses four workers; the E2E job rebuilds
frontend assets and runs Chromium and Firefox with four workers. Each job starts
and cleans up its own services. Browser failure artifacts are retained for three days.

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
| `GET`, `PATCH` | `/api/whisper/<view_id>/access` | Read or update receive reader access (creator only; feature must be enabled) |

Receive creation (`POST /api/whisper/request`) accepts optional `creator_only`
(boolean) and `allowed_reader_emails` (array of up to 20 verified primary emails).
The access endpoint accepts the same fields; omitted fields retain their current
values. Disabling the restriction clears approved readers. A mandatory setting
rejects attempts to disable it. Requests use the existing session authentication
and CSRF protection; access responses contain only restriction settings, never
ciphertext or keys.

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
- Receive reader restrictions are checked before Redis retrieval or reveal counting. They complement client-side encryption, rather than replacing possession of the decryption key.
- Reader-validation failures return a fixed translated message, never internal exception details.

## License

See [LICENSE](LICENSE).

The passphrase wordlist in `static/js/wordlist-en.js` is the [EFF Large Wordlist for Passphrases](https://www.eff.org/dice) by the Electronic Frontier Foundation, licensed under [CC BY 3.0 US](https://creativecommons.org/licenses/by/3.0/us/).
