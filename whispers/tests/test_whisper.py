import json
import re
import uuid
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

import fakeredis
from django.conf import settings
from django.contrib.auth.models import User
from django.test import TestCase, override_settings
from django.utils import timezone

from whispers import redis_store
from whispers.models import Whisper

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Base MIDDLEWARE without LoginRequiredMiddleware so tests run regardless of
# the ENABLE_AUTH env var in the developer's .env file.
_BASE_MIDDLEWARE = [
    m for m in settings.MIDDLEWARE if m != "whispers.middleware.LoginRequiredMiddleware"
]

# Disable effective DRF throttling in tests so rapid-fire requests don't
# get 429s.  We keep the rate keys (required by the per-view throttle
# classes) but set them high enough to never trigger.
_TEST_REST_FRAMEWORK = {
    **settings.REST_FRAMEWORK,
    "DEFAULT_THROTTLE_CLASSES": [],
    "DEFAULT_THROTTLE_RATES": {
        "anon": "10000/minute",
        "whisper_create": "10000/minute",
        "whisper_view": "",
    },
}


def _redis_version_from_compose():
    """Parse the Redis image tag from docker-compose.yml so fakeredis
    emulates the same server version we run in production."""
    compose_path = Path(settings.BASE_DIR) / "docker-compose.yml"
    if not compose_path.exists():
        return None
    match = re.search(r"image:\s*redis:(\d+(?:\.\d+)*)", compose_path.read_text())
    if match:
        parts = [int(p) for p in match.group(1).split(".")]
        return tuple(parts[:3])  # (major, minor, patch)
    return None


_REDIS_VERSION = _redis_version_from_compose()


def _fake_redis_client():
    """Return a fresh fakeredis client (decode_responses=True like prod).
    Targets the Redis version from docker-compose.yml when available."""
    kwargs = {"decode_responses": True}
    if _REDIS_VERSION:
        kwargs["version"] = _REDIS_VERSION
    return fakeredis.FakeRedis(**kwargs)


def _patch_redis():
    """Patch redis_store.get_client to return a fakeredis instance."""
    client = _fake_redis_client()
    return patch.object(redis_store, "get_client", return_value=client), client


# ---------------------------------------------------------------------------
# Model tests
# ---------------------------------------------------------------------------


class WhisperModelTests(TestCase):

    def test_default_fields(self):
        w = Whisper.objects.create()
        self.assertEqual(w.mode, "send")
        self.assertFalse(w.burn_after_read)
        self.assertEqual(w.allowed_cidr, "")
        self.assertEqual(w.expiry_option, "1d")

    def test_uuid_primary_key(self):
        w = Whisper.objects.create()
        self.assertIsInstance(w.id, uuid.UUID)

    def test_is_expired_false_when_future(self):
        w = Whisper(expires_at=timezone.now() + timedelta(hours=1))
        self.assertFalse(w.is_expired)

    def test_is_expired_true_when_past(self):
        w = Whisper(expires_at=timezone.now() - timedelta(seconds=1))
        self.assertTrue(w.is_expired)

    def test_is_expired_false_when_none(self):
        w = Whisper(expires_at=None)
        self.assertFalse(w.is_expired)

    def test_str_representation(self):
        w = Whisper.objects.create()
        self.assertIn(str(w.id), str(w))

    def test_ordering_newest_first(self):
        w1 = Whisper.objects.create()  # noqa: F841
        w2 = Whisper.objects.create()
        ids = list(Whisper.objects.values_list("id", flat=True))
        self.assertEqual(ids[0], w2.id)


# ---------------------------------------------------------------------------
# Redis store tests
# ---------------------------------------------------------------------------


class RedisStoreTests(TestCase):
    """Test redis_store operations using fakeredis — catches regressions from
    redis-py or server version bumps."""

    def setUp(self):
        self.patcher, self.redis = _patch_redis()
        self.patcher.start()

    def tearDown(self):
        self.patcher.stop()
        # Reset the module-level _client so it doesn't leak between tests
        redis_store._client = None

    def test_store_and_get_crypto(self):
        wid = uuid.uuid4()
        redis_store.store_crypto(
            wid,
            3600,
            ciphertext="ct",
            iv="iv_val",
            salt="s",
        )
        data = redis_store.get_crypto(wid)
        self.assertIsNotNone(data)
        self.assertEqual(data["ciphertext"], "ct")
        self.assertEqual(data["iv"], "iv_val")
        self.assertEqual(data["salt"], "s")
        self.assertEqual(data["password_verify_token"], "")
        self.assertEqual(data["password_verify_iv"], "")

    def test_get_crypto_returns_none_when_missing(self):
        self.assertIsNone(redis_store.get_crypto(uuid.uuid4()))

    def test_store_crypto_sets_ttl(self):
        wid = uuid.uuid4()
        redis_store.store_crypto(wid, 120, ciphertext="c", iv="i")
        ttl = self.redis.ttl(f"whisper:{wid}")
        self.assertGreater(ttl, 0)
        self.assertLessEqual(ttl, 120)

    def test_update_crypto_merges_fields(self):
        wid = uuid.uuid4()
        redis_store.store_crypto(wid, 3600, ciphertext="", iv="", salt="s1")
        redis_store.update_crypto(wid, ciphertext="new_ct", iv="new_iv")
        data = redis_store.get_crypto(wid)
        self.assertEqual(data["ciphertext"], "new_ct")
        self.assertEqual(data["iv"], "new_iv")
        self.assertEqual(data["salt"], "s1")  # unchanged

    def test_update_crypto_preserves_ttl(self):
        wid = uuid.uuid4()
        redis_store.store_crypto(wid, 300, ciphertext="c", iv="i")
        ttl_before = self.redis.ttl(f"whisper:{wid}")
        redis_store.update_crypto(wid, ciphertext="c2")
        ttl_after = self.redis.ttl(f"whisper:{wid}")
        self.assertGreater(ttl_after, 0)
        self.assertLessEqual(ttl_after, ttl_before)

    def test_update_crypto_returns_false_when_missing(self):
        result = redis_store.update_crypto(uuid.uuid4(), ciphertext="x")
        self.assertFalse(result)

    def test_delete_crypto(self):
        wid = uuid.uuid4()
        redis_store.store_crypto(wid, 3600, ciphertext="c", iv="i")
        redis_store.delete_crypto(wid)
        self.assertIsNone(redis_store.get_crypto(wid))

    def test_delete_crypto_noop_when_missing(self):
        # Should not raise
        redis_store.delete_crypto(uuid.uuid4())

    def test_store_crypto_password_fields(self):
        wid = uuid.uuid4()
        redis_store.store_crypto(
            wid,
            3600,
            password_verify_token="tok",
            password_verify_iv="piv",
        )
        data = redis_store.get_crypto(wid)
        self.assertEqual(data["password_verify_token"], "tok")
        self.assertEqual(data["password_verify_iv"], "piv")

    def test_stored_data_is_valid_json(self):
        """Guard against serialisation changes in redis-py updates."""
        wid = uuid.uuid4()
        redis_store.store_crypto(wid, 3600, ciphertext="c", iv="i", salt="s")
        raw = self.redis.get(f"whisper:{wid}")
        parsed = json.loads(raw)
        self.assertIn("ciphertext", parsed)

    def test_key_format(self):
        """Ensure the key namespace stays stable across lib upgrades."""
        wid = uuid.uuid4()
        redis_store.store_crypto(wid, 60, ciphertext="c", iv="i")
        self.assertTrue(self.redis.exists(f"whisper:{wid}"))


# ---------------------------------------------------------------------------
# API / View tests
# ---------------------------------------------------------------------------


@override_settings(MIDDLEWARE=_BASE_MIDDLEWARE, REST_FRAMEWORK=_TEST_REST_FRAMEWORK)
class ApiCreateWhisperTests(TestCase):

    def setUp(self):
        self.patcher, self.redis = _patch_redis()
        self.patcher.start()

    def tearDown(self):
        self.patcher.stop()
        redis_store._client = None

    def _post(self, payload):
        return self.client.post(
            "/api/whisper",
            data=json.dumps(payload),
            content_type="application/json",
        )

    # -- happy path --

    def test_create_whisper_returns_200(self):
        resp = self._post({"ciphertext": "ct", "iv": "iv", "salt": "s"})
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("id", data)
        self.assertIn("url", data)

    def test_create_whisper_stores_in_db(self):
        resp = self._post({"ciphertext": "ct", "iv": "iv"})
        wid = resp.json()["id"]
        self.assertTrue(Whisper.objects.filter(id=wid).exists())

    def test_create_whisper_stores_in_redis(self):
        resp = self._post({"ciphertext": "ct", "iv": "iv", "salt": "s"})
        wid = resp.json()["id"]
        data = redis_store.get_crypto(wid)
        self.assertEqual(data["ciphertext"], "ct")

    def test_burn_after_read_flag(self):
        resp = self._post({"ciphertext": "ct", "iv": "iv", "burn_after_read": True})
        wid = resp.json()["id"]
        w = Whisper.objects.get(id=wid)
        self.assertTrue(w.burn_after_read)

    def test_allowed_cidr_stored(self):
        resp = self._post(
            {
                "ciphertext": "ct",
                "iv": "iv",
                "allowed_cidr": "10.0.0.0/24",
            }
        )
        wid = resp.json()["id"]
        w = Whisper.objects.get(id=wid)
        self.assertEqual(w.allowed_cidr, "10.0.0.0/24")

    def test_expiry_options(self):
        for opt in ("5m", "1h", "1d", "1w", "1M"):
            resp = self._post({"ciphertext": "ct", "iv": "iv", "expiry": opt})
            self.assertEqual(resp.status_code, 200, f"Failed for expiry={opt}")

    # -- validation --

    def test_missing_ciphertext(self):
        resp = self._post({"iv": "iv"})
        self.assertEqual(resp.status_code, 400)

    def test_missing_iv(self):
        resp = self._post({"ciphertext": "ct"})
        self.assertEqual(resp.status_code, 400)

    def test_invalid_json(self):
        resp = self.client.post(
            "/api/whisper",
            data="not json",
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 400)

    def test_invalid_expiry(self):
        resp = self._post({"ciphertext": "ct", "iv": "iv", "expiry": "99x"})
        self.assertEqual(resp.status_code, 400)

    def test_invalid_cidr(self):
        resp = self._post(
            {
                "ciphertext": "ct",
                "iv": "iv",
                "allowed_cidr": "not-a-cidr",
            }
        )
        self.assertEqual(resp.status_code, 400)

    def test_get_not_allowed(self):
        resp = self.client.get("/api/whisper")
        self.assertEqual(resp.status_code, 405)


@override_settings(MIDDLEWARE=_BASE_MIDDLEWARE, REST_FRAMEWORK=_TEST_REST_FRAMEWORK)
class ViewWhisperTests(TestCase):

    def setUp(self):
        self.patcher, self.redis = _patch_redis()
        self.patcher.start()

    def tearDown(self):
        self.patcher.stop()
        redis_store._client = None

    def _create_whisper(self, **kwargs):
        defaults = {
            "expiry_option": "1d",
            "expires_at": timezone.now() + timedelta(days=1),
        }
        defaults.update(kwargs)
        w = Whisper.objects.create(**defaults)
        redis_store.store_crypto(
            w.id,
            86400,
            ciphertext="ct",
            iv="iv",
            salt="s",
        )
        return w

    def test_view_existing_whisper(self):
        w = self._create_whisper()
        resp = self.client.get(f"/whisper/{w.id}")
        self.assertEqual(resp.status_code, 200)

    def test_view_nonexistent_whisper(self):
        resp = self.client.get(f"/whisper/{uuid.uuid4()}")
        self.assertEqual(resp.status_code, 404)

    def test_view_expired_whisper(self):
        w = self._create_whisper(expires_at=timezone.now() - timedelta(seconds=1))
        resp = self.client.get(f"/whisper/{w.id}")
        self.assertEqual(resp.status_code, 410)
        self.assertFalse(Whisper.objects.filter(id=w.id).exists())

    def test_burn_after_read_deletes(self):
        w = self._create_whisper(burn_after_read=True)
        # First GET shows confirmation page (not the actual content)
        resp = self.client.get(f"/whisper/{w.id}")
        self.assertEqual(resp.status_code, 200)
        self.assertTemplateUsed(resp, "whispers/confirm_burn.html")
        # Whisper still exists — bot GETs don't burn
        self.assertTrue(Whisper.objects.filter(id=w.id).exists())
        # POST to reveal endpoint burns the whisper
        resp2 = self.client.post(f"/api/whisper/{w.id}/reveal")
        self.assertEqual(resp2.status_code, 200)
        data = resp2.json()
        self.assertIn("ciphertext", data)
        # Whisper is now gone
        self.assertFalse(Whisper.objects.filter(id=w.id).exists())
        # Second reveal should 404
        resp3 = self.client.post(f"/api/whisper/{w.id}/reveal")
        self.assertEqual(resp3.status_code, 404)

    def test_ip_restriction_blocks(self):
        w = self._create_whisper(allowed_cidr="192.168.1.0/24")
        resp = self.client.get(f"/whisper/{w.id}")
        # Test client IP is 127.0.0.1, should be forbidden
        self.assertEqual(resp.status_code, 403)

    def test_ip_restriction_allows(self):
        w = self._create_whisper(allowed_cidr="127.0.0.1/32")
        resp = self.client.get(f"/whisper/{w.id}")
        self.assertEqual(resp.status_code, 200)

    def test_redis_gone_shows_expired(self):
        w = self._create_whisper()
        redis_store.delete_crypto(w.id)
        resp = self.client.get(f"/whisper/{w.id}")
        self.assertEqual(resp.status_code, 410)
        self.assertFalse(Whisper.objects.filter(id=w.id).exists())


# ---------------------------------------------------------------------------
# Receive-mode (request) tests
# ---------------------------------------------------------------------------


@override_settings(MIDDLEWARE=_BASE_MIDDLEWARE, REST_FRAMEWORK=_TEST_REST_FRAMEWORK)
class ApiCreateRequestTests(TestCase):

    def setUp(self):
        self.patcher, self.redis = _patch_redis()
        self.patcher.start()

    def tearDown(self):
        self.patcher.stop()
        redis_store._client = None

    def _post(self, payload):
        return self.client.post(
            "/api/whisper/request",
            data=json.dumps(payload),
            content_type="application/json",
        )

    def test_create_request_returns_urls(self):
        resp = self._post({"salt": "s"})
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("submit_url", data)
        self.assertIn("view_url", data)

    def test_creates_receive_mode_whisper(self):
        resp = self._post({})
        wid = resp.json()["id"]
        w = Whisper.objects.get(id=wid)
        self.assertEqual(w.mode, "receive")

    def test_invalid_expiry(self):
        resp = self._post({"expiry": "bad"})
        self.assertEqual(resp.status_code, 400)

    def test_invalid_cidr(self):
        resp = self._post({"allowed_cidr": "nope"})
        self.assertEqual(resp.status_code, 400)


@override_settings(MIDDLEWARE=_BASE_MIDDLEWARE, REST_FRAMEWORK=_TEST_REST_FRAMEWORK)
class SubmitWhisperFlowTests(TestCase):

    def setUp(self):
        self.patcher, self.redis = _patch_redis()
        self.patcher.start()

    def tearDown(self):
        self.patcher.stop()
        redis_store._client = None

    def _create_request(self, **kwargs):
        defaults = {
            "mode": "receive",
            "expiry_option": "1d",
            "expires_at": timezone.now() + timedelta(days=1),
        }
        defaults.update(kwargs)
        w = Whisper.objects.create(**defaults)
        redis_store.store_crypto(w.id, 86400, salt="s")
        return w

    # -- submit page --

    def test_submit_page_renders(self):
        w = self._create_request()
        resp = self.client.get(f"/submit/{w.id}")
        self.assertEqual(resp.status_code, 200)

    def test_submit_page_expired(self):
        w = self._create_request(expires_at=timezone.now() - timedelta(seconds=1))
        resp = self.client.get(f"/submit/{w.id}")
        self.assertEqual(resp.status_code, 410)

    def test_submit_page_ip_blocked(self):
        w = self._create_request(allowed_cidr="192.168.1.0/24")
        resp = self.client.get(f"/submit/{w.id}")
        self.assertEqual(resp.status_code, 403)

    def test_submit_page_already_submitted(self):
        w = self._create_request()
        redis_store.update_crypto(w.id, ciphertext="ct", iv="iv")
        resp = self.client.get(f"/submit/{w.id}")
        self.assertEqual(resp.status_code, 200)
        self.assertTemplateUsed(resp, "whispers/submitted.html")

    # -- API submit --

    def test_api_submit_success(self):
        w = self._create_request()
        resp = self.client.post(
            f"/api/whisper/submit/{w.id}",
            data=json.dumps({"ciphertext": "ct", "iv": "iv"}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.json()["success"])
        data = redis_store.get_crypto(w.id)
        self.assertEqual(data["ciphertext"], "ct")

    def test_api_submit_missing_fields(self):
        w = self._create_request()
        resp = self.client.post(
            f"/api/whisper/submit/{w.id}",
            data=json.dumps({"ciphertext": "ct"}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 400)

    def test_api_submit_duplicate(self):
        w = self._create_request()
        redis_store.update_crypto(w.id, ciphertext="ct", iv="iv")
        resp = self.client.post(
            f"/api/whisper/submit/{w.id}",
            data=json.dumps({"ciphertext": "ct2", "iv": "iv2"}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 409)

    def test_api_submit_expired(self):
        w = self._create_request(expires_at=timezone.now() - timedelta(seconds=1))
        resp = self.client.post(
            f"/api/whisper/submit/{w.id}",
            data=json.dumps({"ciphertext": "ct", "iv": "iv"}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 410)

    def test_api_submit_ip_blocked(self):
        w = self._create_request(allowed_cidr="192.168.1.0/24")
        resp = self.client.post(
            f"/api/whisper/submit/{w.id}",
            data=json.dumps({"ciphertext": "ct", "iv": "iv"}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 403)

    # -- view after submit --

    def test_view_pending_request(self):
        w = self._create_request()
        resp = self.client.get(f"/whisper/{w.id}")
        self.assertEqual(resp.status_code, 200)
        self.assertTemplateUsed(resp, "whispers/pending.html")

    def test_view_after_submit(self):
        w = self._create_request()
        redis_store.update_crypto(w.id, ciphertext="ct", iv="iv")
        resp = self.client.get(f"/whisper/{w.id}")
        self.assertEqual(resp.status_code, 200)
        self.assertTemplateUsed(resp, "whispers/view.html")


# ---------------------------------------------------------------------------
# Page render tests
# ---------------------------------------------------------------------------


@override_settings(MIDDLEWARE=_BASE_MIDDLEWARE, REST_FRAMEWORK=_TEST_REST_FRAMEWORK)
class PageRenderTests(TestCase):

    def test_create_page(self):
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)

    def test_about_page(self):
        resp = self.client.get("/about")
        self.assertEqual(resp.status_code, 200)


# ---------------------------------------------------------------------------
# Middleware tests
# ---------------------------------------------------------------------------


@override_settings(MIDDLEWARE=_BASE_MIDDLEWARE, REST_FRAMEWORK=_TEST_REST_FRAMEWORK)
class NoCacheMiddlewareTests(TestCase):

    def test_no_cache_headers_present(self):
        resp = self.client.get("/")
        self.assertEqual(
            resp["Cache-Control"], "no-cache, no-store, must-revalidate, private"
        )
        self.assertEqual(resp["Pragma"], "no-cache")
        self.assertEqual(resp["Expires"], "0")


# ---------------------------------------------------------------------------
# Management command tests
# ---------------------------------------------------------------------------


class CleanupExpiredCommandTests(TestCase):

    def setUp(self):
        self.patcher, self.redis = _patch_redis()
        self.patcher.start()

    def tearDown(self):
        self.patcher.stop()
        redis_store._client = None

    def test_deletes_expired_whispers(self):
        from django.core.management import call_command

        w = Whisper.objects.create(
            expiry_option="5m",
            expires_at=timezone.now() - timedelta(minutes=1),
        )
        redis_store.store_crypto(w.id, 60, ciphertext="c", iv="i")
        call_command("cleanup_expired")
        self.assertFalse(Whisper.objects.filter(id=w.id).exists())

    def test_keeps_active_whispers(self):
        from django.core.management import call_command

        w = Whisper.objects.create(
            expiry_option="1d",
            expires_at=timezone.now() + timedelta(days=1),
        )
        redis_store.store_crypto(w.id, 86400, ciphertext="c", iv="i")
        call_command("cleanup_expired")
        self.assertTrue(Whisper.objects.filter(id=w.id).exists())


# ---------------------------------------------------------------------------
# Authentication / login-required tests
# ---------------------------------------------------------------------------

_AUTH_MIDDLEWARE = _BASE_MIDDLEWARE + ["whispers.middleware.LoginRequiredMiddleware"]


@override_settings(
    MIDDLEWARE=_AUTH_MIDDLEWARE,
    REST_FRAMEWORK=_TEST_REST_FRAMEWORK,
    ENABLE_AUTH=True,
    LOGIN_URL="/login/",
    LOGIN_REQUIRED_EXEMPT_URLS=[
        r"login/",
        r"accounts/.*",
        r"admin/.*",
        r"i18n/.*",
        r"static/.*",
        r"submit/.*",
        r"api/whisper/submit/.*",
        r"whisper/.*",
    ],
)
class LoginRequiredMiddlewareTests(TestCase):
    """Verify that the login middleware redirects unauthenticated users
    and allows authenticated users through."""

    def test_unauthenticated_redirects_to_login(self):
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/login/", resp.url)

    def test_unauthenticated_about_redirects(self):
        resp = self.client.get("/about")
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/login/", resp.url)

    def test_authenticated_can_access_create(self):
        User.objects.create_user(username="testuser", password="testpass123")
        self.client.login(username="testuser", password="testpass123")
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)

    def test_authenticated_can_access_about(self):
        User.objects.create_user(username="testuser", password="testpass123")
        self.client.login(username="testuser", password="testpass123")
        resp = self.client.get("/about")
        self.assertEqual(resp.status_code, 200)

    def test_api_whisper_requires_auth(self):
        """API create-whisper endpoint requires authentication."""
        resp = self.client.post(
            "/api/whisper",
            data=json.dumps({"ciphertext": "ct", "iv": "iv"}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/login/", resp.url)

    def test_api_whisper_authenticated(self):
        """Authenticated user can access the API create-whisper endpoint."""
        User.objects.create_user(username="testuser", password="testpass123")
        self.client.login(username="testuser", password="testpass123")
        resp = self.client.post(
            "/api/whisper",
            data=json.dumps({"ciphertext": "ct", "iv": "iv"}),
            content_type="application/json",
        )
        # Should succeed or fail validation, NOT redirect
        self.assertNotEqual(resp.status_code, 302)

    def test_submit_api_exempt_when_not_forced(self):
        """api/whisper/submit/ is exempt when PSST_FORCE_AUTH_SUBMIT is False."""
        resp = self.client.get(f"/api/whisper/submit/{uuid.uuid4()}")
        # Non-existent → 404 (not 302)
        self.assertNotEqual(resp.status_code, 302)

    def test_submit_api_requires_auth_when_forced(self):
        """api/whisper/submit/ requires auth when PSST_FORCE_AUTH_SUBMIT is True."""
        with self.settings(
            LOGIN_REQUIRED_EXEMPT_URLS=[
                r"login/",
                r"accounts/.*",
                r"admin/.*",
                r"i18n/.*",
                r"static/.*",
            ],
        ):
            resp = self.client.post(
                f"/api/whisper/submit/{uuid.uuid4()}",
                data=json.dumps({"ciphertext": "ct", "iv": "iv", "salt": "s"}),
                content_type="application/json",
            )
            self.assertEqual(resp.status_code, 302)
            self.assertIn("/login/", resp.url)

    def test_exempt_url_whisper_view(self):
        """whisper/ is exempt when not force-auth."""
        resp = self.client.get(f"/whisper/{uuid.uuid4()}")
        # Non-existent whisper returns 404, not 302
        self.assertEqual(resp.status_code, 404)

    def test_whisper_view_requires_auth_when_forced(self):
        """whisper/ requires auth when PSST_FORCE_AUTH_VIEW is True."""
        with self.settings(
            LOGIN_REQUIRED_EXEMPT_URLS=[
                r"login/",
                r"accounts/.*",
                r"admin/.*",
                r"i18n/.*",
                r"static/.*",
            ],
        ):
            resp = self.client.get(f"/whisper/{uuid.uuid4()}")
            self.assertEqual(resp.status_code, 302)
            self.assertIn("/login/", resp.url)


@override_settings(
    MIDDLEWARE=_BASE_MIDDLEWARE,
    REST_FRAMEWORK=_TEST_REST_FRAMEWORK,
    ENABLE_AUTH=True,
    ENABLE_LOCAL_LOGIN=True,
)
class LocalLoginTests(TestCase):
    """Verify local username/password login works when enabled."""

    def test_login_success(self):
        User.objects.create_user(username="admin", password="secret123")
        resp = self.client.post(
            "/login/",
            {"username": "admin", "password": "secret123", "next": "/"},
        )
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(resp.url, "/")

    def test_login_failure(self):
        User.objects.create_user(username="admin", password="secret123")
        resp = self.client.post(
            "/login/",
            {"username": "admin", "password": "wrong", "next": "/"},
        )
        self.assertEqual(resp.status_code, 200)  # re-renders login page
        self.assertContains(resp, "Invalid username or password")

    def test_login_rejects_open_redirect(self):
        User.objects.create_user(username="admin", password="secret123")
        resp = self.client.post(
            "/login/",
            {"username": "admin", "password": "secret123", "next": "https://evil.com"},
        )
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(resp.url, "/")  # sanitised to /
