# psst-secret

A zero-knowledge encrypted secret sharing tool. All encryption and decryption happens in the browser — the server never sees your plaintext. Encrypted data is stored only in volatile memory (Redis with persistence disabled) and never touches disk.

## Features

- **Zero-knowledge architecture** — secrets are encrypted client-side with AES-256-GCM using the [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API). The decryption key lives only in the URL fragment (`#key`), which is never sent to the server.
- **In-memory ciphertext storage** — encrypted data (ciphertext, IV, salt) is stored in Redis with persistence disabled (`--save "" --appendonly no`). Ciphertexts never touch disk. If Redis restarts, all pssts are gone — by design.
- **Send mode** — encrypt a secret (text or file) and get a shareable link.
- **Receive mode** — create a request for someone to send you a secret. You get a submit link to share and a view link to retrieve it later.
- **Password protection** — optionally protect secrets with a password (PBKDF2, 600k iterations, SHA-256). In receive mode, the sender's password is validated client-side before submission.
- **Burn after reading** — secrets are permanently erased from memory the moment they are viewed.
- **Auto-expiry** — secrets expire after a configurable duration (5 minutes to 1 month). Redis TTLs evict keys automatically, and a background thread cleans up orphaned DB metadata every 60 seconds.
- **IP/CIDR restriction** — restrict who can view (send mode) or submit (receive mode) a secret by IP address or CIDR range.
- **No-cache headers** — middleware ensures browsers and proxies never cache secret pages.

## How it works

### Send mode

1. You enter a secret (text or file) in the browser.
2. A random AES-256-GCM key is generated client-side.
3. The secret is encrypted in-browser. Only the ciphertext is sent to the server.
4. The key is placed in the URL fragment (`#key`) — never sent to the server per the HTTP spec.
5. You share the link. The recipient's browser decrypts it using the key from the fragment.

### Receive mode

1. You configure options (expiry, password, burn-after-read, IP restriction) and create a request.
2. You get two links: a **submit link** for the sender and a **view link** for yourself.
3. The sender visits the submit link, enters the secret, and it's encrypted in their browser before submission.
4. You visit the view link to decrypt and read the secret.

## Requirements

- Python 3.13+
- Django 5.2+
- Redis 7+ (persistence disabled)

## Quick start

```bash
# Clone and install
git clone <repo-url> && cd psst-secret
pip install -e .  # or: uv sync

# Start Redis (no persistence — ciphertexts stay in RAM only)
docker compose up -d redis

# Run with SQLite (development)
python manage.py migrate
python manage.py runserver
```

Open [http://localhost:8000](http://localhost:8000).

## Architecture

psst-secret uses a split storage model:

| Store | What it holds | Persistence |
|---|---|---|
| **Redis** | Ciphertext, IV, salt, password verification tokens | **In-memory only** — `--save "" --appendonly no` |
| **PostgreSQL** | Metadata: expiry, mode, burn flag, IP restriction | On disk |

This means encrypted data **never touches disk**. If Redis restarts, all ciphertexts are lost (a feature, not a bug). Orphaned DB metadata is cleaned up automatically — the background thread and on-access checks both delete DB rows when their Redis key is gone.

### Expiry: belt and suspenders

1. **Redis TTL** — each key is stored with a TTL matching the psst's expiry. Redis evicts them automatically.
2. **Background thread** — runs every 60s, deletes expired DB rows and their Redis keys (defense-in-depth).
3. **On-access cleanup** — if a user visits a psst whose Redis key has vanished, the orphaned DB row is deleted immediately.

## Database: PostgreSQL

PostgreSQL stores only non-sensitive metadata. SQLite works for development.

```bash
# Start PostgreSQL and Redis
docker compose up -d

# Set the database URL in .env
DATABASE_URL=postgres://user:password@localhost:5432/psstsecret

# Run migrations
python manage.py migrate
```

## Environment variables

| Variable | Description | Default |
|---|---|---|
| `SECRET_KEY` | Django secret key | Insecure default (dev only) |
| `DEBUG` | Debug mode | `False` |
| `DATABASE_URL` | Database connection string | `sqlite:///db.sqlite3` |
| `REDIS_URL` | Redis connection string | `redis://localhost:6379/0` |
| `BRAND_COLORS` | Tailwind brand palette as JSON (shade → hex) | Teal palette |

Example custom brand colors (blue):

```bash
BRAND_COLORS='{"50":"#eff6ff","100":"#dbeafe","200":"#bfdbfe","300":"#93c5fd","400":"#60a5fa","500":"#3b82f6","600":"#2563eb","700":"#1d4ed8","800":"#1e40af","900":"#1e3a8a","950":"#172554"}'
```

## Project structure

```
psst_secret/          Django project config (settings, urls, wsgi, asgi)
pssts/                Main app
├── models.py         Pssts model (metadata only — no ciphertext fields)
├── redis_store.py    Redis helpers for in-memory ciphertext storage
├── views.py          API + page views (send, receive, submit)
├── urls.py           URL routing
├── admin.py          Django admin config
├── middleware.py      No-cache middleware
├── apps.py           App config + background cleanup thread
├── management/       Management commands (cleanup_expired)
└── migrations/       Database migrations
static/js/crypto.js   Client-side AES-256-GCM encryption/decryption
templates/            Django templates (Tailwind CSS)
```

## Security properties

- The server stores ciphertext, IV, and salt **only in Redis memory** — never on disk. Metadata (expiry, mode, flags) lives in PostgreSQL.
- The URL fragment (`#key`) is never sent to the server per the HTTP specification.
- AES-256-GCM provides authenticated encryption — tampering is detected.
- Password-derived keys use PBKDF2 with 600,000 iterations and SHA-256.
- Burn-after-read secrets are erased from Redis and the database immediately upon first retrieval.
- Redis runs with persistence disabled (`--save "" --appendonly no`) — all ciphertexts are lost on restart.
- If Redis evicts a key before the DB row is cleaned up, the next access deletes the orphaned row automatically.

## License

See [LICENSE](LICENSE).