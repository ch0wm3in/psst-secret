# Configuration

All settings are read from environment variables. Optional features are off by default
unless noted otherwise. Restart the app after changing them.

- [Core](#core)
- [Security and rate limiting](#security-and-rate-limiting)
- [Authentication](#authentication)
- [Receive reader access](#receive-reader-access)
- [Email notifications](#email-notifications)
- [Formatted text](#formatted-text)
- [Statistics](#statistics)
- [Branding](#branding)

## Core

| Variable | Description | Default |
|---|---|---|
| `SECRET_KEY` | Django secret key. Required when `DEBUG=False`; the app refuses to start with the insecure default. | Insecure default (dev only) |
| `DEBUG` | Enable Django debug mode. | `False` |
| `ALLOWED_HOSTS` | Comma-separated allowed hostnames. | `localhost,127.0.0.1` |
| `DATABASE_URL` | Database connection string ([dj-database-url](https://github.com/jazzband/dj-database-url) format). | `sqlite:///db.sqlite3` |
| `REDIS_URL` | Redis connection string for ciphertext storage. | `redis://localhost:6379/0` |
| `ABOUT_PAGE_PERSISTENCE_ENABLED` | Describe Redis as persistent on the About page. Set this if you enabled Redis persistence. | `False` |
| `APP_VERSION` | Version shown in the footer. Set by the Docker build from the release tag. | `dev` |

## Security and rate limiting

| Variable | Description | Default |
|---|---|---|
| `NUM_PROXIES` | Number of trusted reverse proxies, used to read the client IP from `X-Forwarded-For` for IP restrictions and rate limiting. `0` ignores the header. | `0` |
| `MAX_UPLOAD_SIZE` | Maximum request body size in bytes (caps encrypted payload size). | `10000000` |
| `CSRF_TRUSTED_ORIGINS` | Comma-separated trusted origins, e.g. `https://psst.example.com`. | _empty_ |
| `API_THROTTLE_RATE_ANON` | Global anonymous API rate limit (DRF format). | `60/minute` |
| `API_THROTTLE_RATE_CREATE` | Limit for the create and submit API endpoints. | `20/minute` |
| `THROTTLE_RATE_VIEW` | Per-IP limit for the whisper view page. | `30/minute` |
| `API_THROTTLE_RATE_RECEIVE_ACCESS` | Per-account limit shared by authenticated receive creation and access management, including failed reader-email lookups. | `10/minute` |

Validating reader emails reveals whether an address is eligible. The receive-access limit
is keyed by account, counts invalid addresses, and returns HTTP 429 before any lookup.
This slows account enumeration but does not prevent it.

## Authentication

Authentication uses [django-allauth](https://docs.allauth.org/) and is enabled with
`ENABLE_AUTH=True`.

| Variable | Description | Default |
|---|---|---|
| `ENABLE_AUTH` | Enable allauth, the login-required middleware, and the `/login/` page. | `False` |
| `ENABLE_LOCAL_LOGIN` | Also allow username/password login. Requires `ENABLE_AUTH`. | `False` |
| `SOCIAL_AUTH_PROVIDERS` | Comma-separated allauth providers, e.g. `google,github`. | _empty_ |
| `{PROVIDER}_SOCIAL_AUTH_CONFIG` | JSON configuration per provider, e.g. `GOOGLE_SOCIAL_AUTH_CONFIG`. | `{}` |
| `PSST_FORCE_AUTH_VIEW` | Require sign-in to view every whisper, overriding the per-whisper option. | `False` |
| `PSST_FORCE_AUTH_SUBMIT` | Require sign-in to submit to every receive request, overriding the per-whisper option. | `False` |
| `LOGIN_REQUIRED_EXEMPT_URLS` | Comma-separated regexes for paths that bypass the login requirement (no leading `/`). The view and submit pages and their `api/v1/` endpoints are added unless `PSST_FORCE_AUTH_VIEW` or `PSST_FORCE_AUTH_SUBMIT` is set. | `login/,accounts/.*,i18n/.*,jsi18n/,static/.*` |
| `ACCOUNT_EMAIL_VERIFICATION` | allauth email verification: `mandatory`, `optional`, or `none`. | `none` |
| `ACCOUNT_DEFAULT_HTTP_PROTOCOL` | Protocol allauth uses for absolute URLs in emails. | `https` (`http` in `DEBUG`) |

## Receive reader access

Restricts receive-mode reveals to the creator and approved accounts. Requires
authentication.

| Variable | Description | Default |
|---|---|---|
| `PSST_ENABLE_RECEIVE_ACCESS` | Enable creator-owned receive requests and reader-access controls. | `False` |
| `PSST_RECEIVE_ACCESS_DEFAULT` | Start new requests with **Only me and approved readers** checked; creators can uncheck it. | `False` |
| `PSST_FORCE_RECEIVE_ACCESS` | Make the restriction mandatory. Overrides the default setting. | `False` |

Run `python manage.py migrate` after upgrading. These settings do not change existing
requests.

- **Creators:** while the feature is on, receive requests made by signed-in users record
  their creator. Only the creator can edit access, from the view link, without consuming
  a view. Anonymous users cannot create restricted requests, and older requests without
  a recorded creator cannot be edited.
- **Readers:** add up to 20 existing accounts by verified, unique primary email. Grants
  are tied to account IDs, not to future sign-ups with that email. No invitations are
  sent and no account directory is exposed. Administrators get no bypass.
- **Reveals:** restricted reveals always require sign-in. Readers still need the
  complete view link and any password, and everyone shares the same view limit.
- **Revoking access** blocks future reveals, not content already retrieved. Disabling
  the feature or authentication does not unlock restricted whispers. Deleting the
  creator's account deletes the request metadata; the ciphertext expires by its TTL.

Creator and reader references are stored as metadata in the database and are never used
in statistics.

## Email notifications

Notifies the recipient (send mode) or creator (receive mode) when a whisper is created or
submitted. Emails never contain the link fragment.

| Variable | Description | Default |
|---|---|---|
| `PSST_ENABLE_EMAIL` | Enable email notifications. | `False` |
| `EMAIL_BACKEND` | Backend for `MAILERS["default"]`: `django.core.mail.backends.smtp.EmailBackend` for SMTP or `django_better_azure_communication_email.EmailBackend` for Azure Communication Services. | `django.core.mail.backends.console.EmailBackend` |
| `DEFAULT_FROM_EMAIL` | Sender address for all mail. | `noreply@localhost` |
| `AZURE_COMMUNICATION_CONNECTION_STRING` | Azure Communication Services connection string (Azure backend only). | _empty_ |

## Formatted text

| Variable | Description | Default |
|---|---|---|
| `PSST_ENABLE_RICH_TEXT` | Markdown editor for whisper content on the create and submit pages, rendered on the view page. | `True` |

The editor is a locally bundled [Tiptap](https://tiptap.dev/) build, loaded only when
enabled. Its **Plain text** button switches to a raw text box; the browser remembers
that choice (never the content) in `localStorage`. Markdown is encrypted like any other
text. When viewing, raw HTML, scripts, and images are dropped and only `http`, `https`, and
`mailto` links are kept. **Copy** copies the raw Markdown. With the setting off,
formatted whispers are shown as raw Markdown.

## Statistics

| Variable | Description | Default |
|---|---|---|
| `PSST_ENABLE_STATS` | Collect anonymous statistics and serve the `/stats` page (login required when `ENABLE_AUTH=True`). | `False` |

Run `python manage.py migrate` before enabling. When disabled, nothing is collected,
the navigation link is hidden, and `/stats` returns 404. Collection starts when enabled
and is not backfilled.

**Stored data:** only fixed hourly counters in the database, with no whisper IDs, content,
keys, IP addresses, accounts, or emails, and no third-party analytics. On a quiet
instance, exact totals can still reveal aggregate activity; this is not differential
privacy. Recording is best-effort, so failures can undercount but never block whispers.

**Report:** time ranges from 1 day to 1 year (default 1 week, rounded to UTC hours).
It shows submissions (send vs. completed receive), daily trends, busiest days, burn-after-read
share, expiry choices, and successful reveals. Pending receive requests are not
counted, and a reveal means ciphertext was delivered, not that it was decrypted.

**Retention:** counters older than 365 days are excluded from reports and removed by
the background cleanup, `cleanup_expired`, and stats page loads. Database backups and
infrastructure logs need their own retention policies.

## Branding

| Variable | Description | Default |
|---|---|---|
| `PSST_BRAND_NAME` | Name shown in the navigation bar, tab titles, sign-in page, About page, footer, emails, and API docs. | `psst-secret` |
| `PSST_BRAND_LOGO_URL` | Logo replacing the lock icon in the navigation bar, sign-in page, and email headers. | _(lock icon)_ |
| `PSST_BRAND_FAVICON_URL` | Favicon replacing the default lock icon (drawn in the `400` brand shade). | _(lock icon)_ |
| `BRAND_COLORS` | Tailwind palette as JSON (shade → hex). | Teal |
| `PSST_HIDE_SOCIAL_LINKS` | Hide the footer GitHub link and show the version as plain text. | `False` |
| `PSST_HIDE_FOOTER_TEXT` | Hide the `<name> — Psst! Don't tell anyone.` footer tagline. | `False` |
| `PSST_HIDE_NAV_BRAND_NAME` | Hide the name next to the logo (it stays in tab titles and for screen readers). | `False` |

```bash
PSST_BRAND_NAME="Acme Secrets"
PSST_BRAND_LOGO_URL=https://assets.acme.example/logo.svg
PSST_BRAND_FAVICON_URL=https://assets.acme.example/favicon.ico
PSST_HIDE_SOCIAL_LINKS=True
PSST_HIDE_FOOTER_TEXT=True
PSST_HIDE_NAV_BRAND_NAME=True
BRAND_COLORS='{"50":"#eff6ff","100":"#dbeafe","200":"#bfdbfe","300":"#93c5fd","400":"#60a5fa","500":"#3b82f6","600":"#2563eb","700":"#1d4ed8","800":"#1e40af","900":"#1e3a8a","950":"#172554"}'
```

Logo and favicon values must be an absolute `http(s)` URL, a path starting with `/`, or a
`data:image/` URI; anything else fails startup with system check `whispers.E001`.

- External image hosts can see visitors' IP addresses. Use a same-origin path or a
  `data:` URI to avoid this.
- In emails, absolute URLs are linked directly, `data:` URIs are embedded as inline
  attachments, and root-relative paths are omitted. Many email clients do not render
  SVG, so use PNG for email logos.
