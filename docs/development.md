# Development

## Requirements

- Python 3.14 and [uv](https://docs.astral.sh/uv/)
- Node.js 20+ and npm (frontend builds)
- Redis 7+ with persistence disabled
- PostgreSQL 16+, or SQLite for development

## Local setup

```bash
git clone https://github.com/ch0wm3in/psst-secret.git && cd psst-secret
uv sync
source .venv/bin/activate
# Create .env (at least DEBUG=True and a SECRET_KEY) and load it into your shell
python manage.py tailwind install
python manage.py tailwind build
docker compose up -d redis
python manage.py migrate
python manage.py runserver
```

Open <http://localhost:8000>. See [configuration.md](configuration.md) for all settings.

## Frontend assets

Tailwind, Alpine.js, noble-post-quantum, Tiptap, Heroicons, and esbuild are locked in
`theme/static_src/`. The build also minifies `static/js/` into `theme/static/js/`. Edit
the source files, never the generated assets. Nothing is loaded from a CDN at runtime.

| Command | Use |
|---|---|
| `python manage.py tailwind start` | Watch CSS while editing templates (builds JavaScript once at startup) |
| `npm --prefix theme/static_src run build:custom` | Rebuild after editing a script in `static/js/` |
| `npm --prefix theme/static_src run build:icons` | Rebuild the icon sprite after adding an icon |
| `python manage.py tailwind build` | Rebuild all frontend assets (run before `collectstatic`) |

### Icons

Icons come from [Heroicons](https://heroicons.com). Use the `{% icon %}` tag from
`whispers_extras`:

```django
{% icon "lock-closed" class="w-5 h-5" %}        {# 24px outline (default) #}
{% icon "solid/lock-closed" class="w-5 h-5" %}  {# 24px solid #}
{% icon "mini/x-mark" class="w-4 h-4" %}        {# 20px solid #}
{% icon "micro/x-mark" class="w-3 h-3" %}       {# 16px solid #}
```

The build only includes icons it finds in `{% icon %}` tags under `templates/`, plus
style-prefixed names such as `"outline/lock-closed"` in `whispers/` Python files. It
writes them to `theme/static/icons/heroicons.svg` and fails on unknown names.

### Secret generator

Passwords and passphrases are generated in the browser with `crypto.getRandomValues`
and unbiased rejection sampling, using the [EFF large wordlist](https://www.eff.org/dice)
for passphrases. Other scripts can call
`window.PsstSecretGenerator.generate('password' | 'passphrase' | 'whisperPassword', overrides)`.

## Project structure

```
psst_secret/             Django project settings and URLs
theme/static_src/        Locked frontend build dependencies
theme/static/            Generated CSS, JavaScript, and icons (do not edit)
whispers/                Main app
├── models.py            Whisper metadata (no ciphertext)
├── redis_store.py       Ciphertext storage and atomic reveal/submit transitions
├── views.py             Pages and JSON API
├── serializers.py       API serializers
├── stats.py             Opt-in anonymous hourly counters
├── email.py             Email notifications
├── middleware.py        No-cache and login-required middleware
├── apps.py              Background cleanup thread
├── management/          Management commands (e.g. cleanup_expired)
├── templatetags/        Template tags (icon, settings_value, to_json, …)
└── tests/               Django and Playwright tests
static/js/               Client-side cryptography, secret generator, and helpers
spec/                    OpenAPI schema and encryption format test vectors
templates/               Django templates (Tailwind CSS)
locale/                  Danish, Czech, Swedish, and Filipino translations
docs/                    Documentation
```

## Translations

The UI ships in English, Danish (`da`), Czech (`cs`), Swedish (`sv`), and Filipino
(`fil`). Catalogs live in `locale/<lang>/LC_MESSAGES/`:

| Catalog | Covers | Mark strings with |
|---|---|---|
| `django.po` | Templates (including inline scripts) and Python | `{% trans %}`, `{% blocktrans %}`, `gettext()` |
| `djangojs.po` | Files in `static/js/` | `gettext()`, `interpolate()` |

The JavaScript catalog is served at `/jsi18n/` and loaded before other scripts. Never
build sentences by concatenation, because word order differs between languages:

```js
interpolate(gettext('This whisper will be destroyed after %s views.'), [maxViews]); // good
'This whisper will be destroyed after ' + maxViews + ' views.';                     // bad
```

After changing user-facing strings:

```bash
python manage.py makemessages -l da -l cs -l sv -l fil --ignore='node_modules' --ignore='theme/static_src/*' --ignore='staticfiles/*' --ignore='.venv/*'
python manage.py makemessages -l da -l cs -l sv -l fil -d djangojs --ignore='node_modules' --ignore='theme/*' --ignore='staticfiles/*' --ignore='.venv/*'
# Fill in empty msgstr entries and review any marked #, fuzzy
python scripts/check_translations.py
python manage.py compilemessages -l da -l cs -l sv -l fil
```

The Docker entrypoint compiles messages on startup. To add a language, add it to
`LANGUAGES` in `psst_secret/settings.py` and repeat the commands with `-l <code>`.

## Testing

```bash
pytest -n 4                                  # Django tests (browser tests skipped)
pytest --browser-tests -n 4                  # Django and browser tests
```

Adjust `-n` to your machine, or use `-n 0` to run sequentially. Before committing, run
`pre-commit run --all-files`.

### Browser tests

The Playwright tests in `whispers/tests/browser/` run the real client-side encryption
against an isolated live server, with a fresh fake Redis and test database per test.
No running app or Redis is needed, and they must never target a deployed instance. Set
`DATABASE_URL=sqlite:///:memory:` to run without PostgreSQL.

```bash
playwright install chromium webkit   # once; on Linux also: playwright install-deps
npm ci --prefix theme/static_src
python manage.py tailwind build              # after changing JavaScript or templates
pytest whispers/tests/browser --browser-tests -n 4 --browser chromium --browser webkit # Firefox is left out on purpose, since it's too unstable to run atm.
```

- Debug with `-n 0 --headed` or `-k <test_name>`.
- Add `--tracing=retain-on-failure --screenshot=only-on-failure` to keep artifacts, and
  open traces with `playwright show-trace <trace.zip>`. Artifacts in `test-results/`
  contain test keys and passwords, so treat them as sensitive.
- Browser tests do not cover real SSO providers, email delivery, or production proxy
  setups.

CI runs the Django tests and the Chromium and WebKit browser tests as separate parallel
jobs.

## Format specification and API schema

The [encryption format](format.md) and the `/api/v1/` endpoints are a contract with
third-party clients, so follow the [compatibility policy](format.md#compatibility-policy)
when changing them.

- **OpenAPI schema.** After changing API views or serializers, regenerate
  `spec/openapi.yaml`. The Django tests fail when it is out of date.
- **Test vectors.** `spec/vectors/v1/` is generated from fixed inputs. Regenerate it
  only when adding cases; existing outputs must not change within a format version.
  `whispers/tests/browser/test_format.py` checks `crypto.js` against the vectors.

```bash
python manage.py spectacular --file spec/openapi.yaml
node spec/vectors/generate.mjs               # needs npm ci --prefix theme/static_src
```
