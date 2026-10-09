# psst-secret Copilot instructions

psst-secret is a Django 6 app for zero-knowledge sharing of encrypted secrets, which users call **whispers**. Use "whisper/whispers" in user-facing text and keep the project name `psst-secret`.

## Project layout
- `psst_secret/`: project settings and URLs. Read configuration with `env.*` in `settings.py`.
- `whispers/`: main app with models, views, the Redis store, statistics, middleware, management commands, and tests.
- `templates/`: Django templates using Tailwind classes. Pages extend `base/layout.html`.
- `static/js/`: client-side cryptography and helpers. `crypto.js` uses the Web Crypto API with `gettext()` for translations.
- `theme/static_src/`: locked Tailwind, Alpine.js, and noble-post-quantum builds. Never edit `theme/static/` or `staticfiles/` by hand.
- `locale/da/LC_MESSAGES/`, `locale/cs/LC_MESSAGES/`, `locale/sv/LC_MESSAGES/`, and `locale/fil/LC_MESSAGES/`: Danish, Czech, Swedish, and Filipino (Tagalog) translations for `django.po` and `djangojs.po`, plus compiled `.mo` files.

## Commands
Always run Python through `uv` and load `.env`:
- Tests: `uv run --env-file .env pytest`
- Django: `uv run --env-file .env python manage.py <command>`
- Migrations: `uv run --env-file .env python manage.py makemigrations`. Never edit applied migrations.
- Tailwind: after changing Tailwind classes in templates or JavaScript, run `uv run --env-file .env python manage.py tailwind build`.

Without `DEBUG=True` and a non-default `SECRET_KEY`, settings refuse to start; `.env` supplies both.

## When finished
1. Run the relevant tests, then the full suite.
2. Always run pre-commit: `uv run --env-file .env pre-commit run --files <changed files>` or `uv run --env-file .env pre-commit run --all-files`. If Black or isort modify files, rerun the hooks. `check-untracked-migrations` requires new migrations to be staged.
3. Update `README.md` when adding environment variables, features, API endpoints, or changing security behavior.

## Translations
Whenever user-facing strings are added or changed in templates, Python, or JavaScript:
1. Mark them with `{% trans %}` or `{% blocktrans %}`, `gettext()`, or JavaScript `gettext()`/`interpolate()`. Never concatenate translated sentences.
2. Regenerate both catalogs:
   - `uv run --env-file .env python manage.py makemessages -l da -l cs -l sv -l fil --ignore='node_modules' --ignore='theme/static_src/*' --ignore='staticfiles/*' --ignore='.venv/*'`
   - `uv run --env-file .env python manage.py makemessages -l da -l cs -l sv -l fil -d djangojs --ignore='node_modules' --ignore='theme/*' --ignore='staticfiles/*' --ignore='.venv/*'`
3. Translate each empty `msgstr` into the catalog's language (Danish, Czech, Swedish, or Filipino). Review `#, fuzzy` entries, fix their translations, and remove the fuzzy flag. Preserve format placeholders and HTML markup.
4. Run `uv run --env-file .env python scripts/check_translations.py` and `uv run --env-file .env python manage.py compilemessages -l da -l cs -l sv -l fil`. Commit the `.po` and `.mo` files.

## Security and privacy
- The server must never receive plaintext, decryption keys, private keys, or passwords. Key material stays in URL fragments or is encrypted client-side.
- Store ciphertext and key material only in Redis with TTLs. PostgreSQL/SQLite stores metadata only.
- Never log or store whisper content, keys, IDs, submit tokens, IP addresses, email addresses, or user identifiers in analytics or statistics.
- Use atomic Redis operations, such as `WATCH`/`MULTI`/`EXEC` in `redis_store.py`, for state transitions such as reveals, burns, and submissions.
- Respect `ENABLE_AUTH`, `LOGIN_REQUIRED_EXEMPT_URLS`, `PSST_FORCE_AUTH_VIEW`, and `PSST_FORCE_AUTH_SUBMIT`. New optional features should use an opt-in `PSST_ENABLE_*` setting that defaults to `False`.

## Code and tests
- Follow Black and isort with the Black profile, plus Flake8 using `setup.cfg` and a 110-character maximum line length.
- Read settings through `django.conf.settings`; do not import `psst_secret.settings` directly.
- Tests use Django `TestCase` in `whispers/tests/`. Use `_patch_redis()` for fakeredis. `pytest.ini` sets `ENABLE_AUTH=True`, so tests without auth must remove `LoginRequiredMiddleware` with `_BASE_MIDDLEWARE` or an override. Clear the cache in tests that call throttled APIs.
- Templates use the existing dark theme: `bg-gray-950/900/800`, `border-gray-700/800`, `text-gray-*`, and `brand-*`. Do not add CDNs or frontend dependencies.

## About page
- The about page serves as a brief introduction to the project, its purpose, and key features.
- It should be concise, informative, and easy to understand for new users.
- Whenever features that impact core features are added or changed(whispers in particular), update the about page to reflect the latest information.

## Documentation
- Documentation should be kept up-to-date with the latest changes in the project, in the README and any other relevant documentation files.
- When adding new features or making significant changes, ensure that the documentation reflects these updates accurately.