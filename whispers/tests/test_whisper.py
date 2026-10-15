import json
import re
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path
from threading import Barrier
from unittest.mock import patch

import fakeredis
from django.conf import settings
from django.contrib.auth.models import User
from django.core.cache import cache
from django.test import TestCase, override_settings
from django.utils import timezone

from whispers import redis_store
from whispers.models import HourlyWhisperStats, Whisper
from whispers.stats import prune_stats, record_stats, stats_report


class AnonymousStatsTests(TestCase):
    def setUp(self):
        cache.clear()
        self.addCleanup(cache.clear)

    @override_settings(
        PSST_ENABLE_STATS=False,
        ENABLE_AUTH=False,
        MIDDLEWARE=[
            middleware
            for middleware in settings.MIDDLEWARE
            if middleware != "whispers.middleware.LoginRequiredMiddleware"
        ],
    )
    def test_disabled_navigation_is_hidden(self):
        response = self.client.get("/about")
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, 'href="/stats"')

    def test_concurrent_receive_submission_has_one_winner(self):
        patcher, _client = _patch_redis()
        whisper_id = uuid.uuid4()
        barrier = Barrier(2)

        def submit(ciphertext):
            barrier.wait(timeout=5)
            return redis_store.submit_crypto_once(whisper_id, ciphertext=ciphertext)

        with patcher:
            redis_store.store_crypto(whisper_id, 60)
            with ThreadPoolExecutor(max_workers=2) as executor:
                results = list(executor.map(submit, ("first", "second")))
            self.assertCountEqual(results, ["accepted", "submitted"])

    @override_settings(
        PSST_ENABLE_STATS=True,
        ENABLE_AUTH=False,
        MIDDLEWARE=[
            middleware
            for middleware in settings.MIDDLEWARE
            if middleware != "whispers.middleware.LoginRequiredMiddleware"
        ],
    )
    def test_receive_disappears_before_acceptance(self):
        patcher, _client = _patch_redis()
        with patcher:
            whisper = Whisper.objects.create(
                mode="receive",
                submit_token=uuid.uuid4(),
                expires_at=timezone.now() + timedelta(days=1),
            )
            redis_store.store_crypto(whisper.id, 60)
            with patch(
                "whispers.redis_store.submit_crypto_once", return_value="missing"
            ):
                response = self.client.post(
                    f"/api/whisper/submit/{whisper.submit_token}",
                    data=json.dumps(
                        {"ciphertext": "ct", "iv": "iv", "encapsulated_key": "epk"}
                    ),
                    content_type="application/json",
                )
            self.assertEqual(response.status_code, 410)
            self.assertEqual(HourlyWhisperStats.objects.count(), 0)

    def test_utc_boundaries_ties_and_average(self):
        from datetime import datetime
        from datetime import timezone as datetime_timezone

        now = datetime(2026, 10, 8, 0, 30, tzinfo=datetime_timezone.utc)
        HourlyWhisperStats.objects.create(
            bucket_start=now.replace(hour=0, minute=0) - timedelta(days=1),
            sends=2,
            burn_after_read=1,
            expiry_1d=2,
        )
        HourlyWhisperStats.objects.create(
            bucket_start=now.replace(hour=0, minute=0), receives=2, expiry_5m=2
        )
        report = stats_report("1d", now)
        self.assertEqual(report["total"], 4)
        self.assertEqual(len(report["busiest_days"]), 2)
        self.assertEqual(len(report["busiest_weekdays"]), 2)
        self.assertEqual(report["burn_share"], 25)
        self.assertAlmostEqual(report["average"], 4 / (24.5 / 24))
        self.assertEqual(sum(item["count"] for item in report["expiry_choices"]), 4)
        self.assertEqual(sum(item["count"] for item in report["weekdays"]), 4)

    def test_all_range_boundaries_and_retention(self):
        now = timezone.now().replace(minute=30, second=0, microsecond=0)
        oldest = now - timedelta(days=365)
        HourlyWhisperStats.objects.create(
            bucket_start=oldest - timedelta(seconds=1), sends=999
        )
        for preset, days in (
            ("1d", 1),
            ("1w", 7),
            ("1m", 30),
            ("3m", 90),
            ("6m", 180),
            ("1y", 365),
        ):
            report = stats_report(preset, now)
            expected = max((now - timedelta(days=days)).replace(minute=0), oldest)
            self.assertEqual(report["start"], expected)
            self.assertEqual(report["total"], 0)
        self.assertFalse(HourlyWhisperStats.objects.exists())

    @override_settings(
        PSST_ENABLE_STATS=True,
        ENABLE_AUTH=False,
        MIDDLEWARE=[
            middleware
            for middleware in settings.MIDDLEWARE
            if middleware != "whispers.middleware.LoginRequiredMiddleware"
        ],
    )
    def test_public_page_and_presets(self):
        for preset in ("1d", "1w", "1m", "3m", "6m", "1y", "invalid"):
            response = self.client.get("/stats", {"range": preset})
            self.assertEqual(response.status_code, 200)
            self.assertContains(response, "Whisper statistics")
            self.assertIn("no-store", response["Cache-Control"])

    @override_settings(PSST_ENABLE_STATS=True, ENABLE_AUTH=True)
    def test_authenticated_page(self):
        user = User.objects.create_user(username="stats-reader")
        self.client.force_login(user)
        self.assertEqual(self.client.get("/stats").status_code, 200)

    @override_settings(
        PSST_ENABLE_STATS=True,
        ENABLE_AUTH=False,
        MIDDLEWARE=[
            middleware
            for middleware in settings.MIDDLEWARE
            if middleware != "whispers.middleware.LoginRequiredMiddleware"
        ],
    )
    def test_submission_and_reveal_hooks(self):
        patcher, _client = _patch_redis()
        with patcher:
            send = self.client.post(
                "/api/whisper",
                data=json.dumps({"ciphertext": "ct", "iv": "iv", "expiry": "1d"}),
                content_type="application/json",
            )
            self.assertEqual(send.status_code, 200)
            self.assertEqual(
                self.client.post(
                    f"/whisper/{send.json()['id']}",
                    data="{}",
                    content_type="application/json",
                ).status_code,
                200,
            )
            whisper = Whisper.objects.create(
                mode="receive",
                submit_token=uuid.uuid4(),
                expiry_option="5m",
                expires_at=timezone.now() + timedelta(minutes=5),
            )
            redis_store.store_crypto(whisper.id, 300)
            self.assertEqual(HourlyWhisperStats.objects.get().receives, 0)
            payload = json.dumps(
                {"ciphertext": "ct", "iv": "iv", "encapsulated_key": "epk"}
            )
            url = f"/api/whisper/submit/{whisper.submit_token}"
            self.assertEqual(
                self.client.post(
                    url, data=payload, content_type="application/json"
                ).status_code,
                200,
            )
            self.assertEqual(
                self.client.post(
                    url, data=payload, content_type="application/json"
                ).status_code,
                409,
            )
            row = HourlyWhisperStats.objects.get()
            self.assertEqual((row.sends, row.receives, row.reveals), (1, 1, 1))

    def test_atomic_receive_acceptance(self):
        patcher, client = _patch_redis()
        with patcher:
            whisper_id = uuid.uuid4()
            redis_store.store_crypto(whisper_id, 60, public_key="public")
            self.assertEqual(
                redis_store.submit_crypto_once(whisper_id, ciphertext="first"),
                "accepted",
            )
            self.assertEqual(
                redis_store.submit_crypto_once(whisper_id, ciphertext="second"),
                "submitted",
            )
            self.assertEqual(redis_store.get_crypto(whisper_id)["ciphertext"], "first")
            self.assertGreater(client.ttl(redis_store._key(whisper_id)), 0)
            redis_store.delete_crypto(whisper_id)
            self.assertEqual(
                redis_store.submit_crypto_once(whisper_id, ciphertext="third"),
                "missing",
            )

    @override_settings(PSST_ENABLE_STATS=True)
    def test_recording_failure_is_isolated(self):
        with patch(
            "whispers.stats.HourlyWhisperStats.objects.get_or_create",
            side_effect=RuntimeError,
        ):
            record_stats("reveal")
        self.assertEqual(HourlyWhisperStats.objects.count(), 0)

    @override_settings(PSST_ENABLE_STATS=False)
    def test_disabled_does_not_query(self):
        with self.assertNumQueries(0):
            record_stats("submission", mode="send", max_views=1, expiry="1d")

    @override_settings(PSST_ENABLE_STATS=True)
    def test_counters_are_hourly_and_anonymous(self):
        record_stats("submission", mode="send", max_views=1, expiry="1d")
        record_stats("submission", mode="receive", max_views=0, expiry="5m")
        record_stats("reveal")
        row = HourlyWhisperStats.objects.get()
        self.assertEqual(
            (row.sends, row.receives, row.reveals, row.burn_after_read), (1, 1, 1, 1)
        )
        self.assertEqual((row.expiry_1d, row.expiry_5m), (1, 1))
        self.assertEqual(row.bucket_start.minute, 0)
        self.assertFalse(any(field.is_relation for field in row._meta.fields))

    @override_settings(PSST_ENABLE_STATS=False)
    def test_retention_also_applies_when_disabled(self):
        now = timezone.now()
        HourlyWhisperStats.objects.create(
            bucket_start=now - timedelta(days=365, seconds=1)
        )
        HourlyWhisperStats.objects.create(bucket_start=now - timedelta(days=365))
        self.assertEqual(prune_stats(now), 1)
        self.assertEqual(HourlyWhisperStats.objects.count(), 1)

    def test_report_ranges_and_empty_state(self):
        now = timezone.now().replace(minute=0, second=0, microsecond=0)
        HourlyWhisperStats.objects.create(bucket_start=now - timedelta(days=2), sends=3)
        HourlyWhisperStats.objects.create(
            bucket_start=now - timedelta(hours=1), receives=2
        )
        self.assertEqual(stats_report("1d", now)["total"], 2)
        self.assertEqual(stats_report("invalid", now)["total"], 5)
        HourlyWhisperStats.objects.all().delete()
        report = stats_report(now=now)
        self.assertEqual(report["burn_share"], 0)
        self.assertEqual(report["busiest_days"], [])
        self.assertEqual(report["busiest_weekdays"], [])


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
        "whisper_view": "10000/minute",
        "receive_access": "10000/minute",
    },
}


_TEST_RECEIVE_ACCESS_THROTTLING = {
    **_TEST_REST_FRAMEWORK,
    "DEFAULT_THROTTLE_RATES": {
        **_TEST_REST_FRAMEWORK["DEFAULT_THROTTLE_RATES"],
        "receive_access": "2/minute",
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
        # Default policy is burn-after-read (max_views == 1).
        self.assertEqual(w.max_views, 1)
        self.assertTrue(w.burn_after_read)
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
        self.assertEqual(data["wrapped_key"], "")
        self.assertEqual(data["wrapped_key_iv"], "")
        self.assertEqual(data["encapsulated_key"], "")
        self.assertEqual(data["public_key"], "")

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

    def test_store_crypto_wrapped_key_fields(self):
        wid = uuid.uuid4()
        redis_store.store_crypto(
            wid,
            3600,
            wrapped_key="wk",
            wrapped_key_iv="wkiv",
        )
        data = redis_store.get_crypto(wid)
        self.assertEqual(data["wrapped_key"], "wk")
        self.assertEqual(data["wrapped_key_iv"], "wkiv")

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

    def test_max_views_flag(self):
        resp = self._post({"ciphertext": "ct", "iv": "iv", "max_views": 1})
        wid = resp.json()["id"]
        w = Whisper.objects.get(id=wid)
        self.assertEqual(w.max_views, 1)
        self.assertTrue(w.burn_after_read)

    def test_max_views_unlimited(self):
        resp = self._post({"ciphertext": "ct", "iv": "iv", "max_views": 0})
        wid = resp.json()["id"]
        self.assertEqual(Whisper.objects.get(id=wid).max_views, 0)

    def test_max_views_rejects_negative(self):
        resp = self._post({"ciphertext": "ct", "iv": "iv", "max_views": -1})
        self.assertEqual(resp.status_code, 400)

    def test_max_views_rejects_too_large(self):
        resp = self._post({"ciphertext": "ct", "iv": "iv", "max_views": 101})
        self.assertEqual(resp.status_code, 400)

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
        self.assertTemplateUsed(resp, "whispers/confirm.html")

    def test_view_nonexistent_whisper(self):
        resp = self.client.get(f"/whisper/{uuid.uuid4()}")
        self.assertEqual(resp.status_code, 404)
        self.assertTemplateUsed(resp, "whispers/burned.html")

    def test_view_expired_whisper(self):
        w = self._create_whisper(expires_at=timezone.now() - timedelta(seconds=1))
        resp = self.client.get(f"/whisper/{w.id}")
        self.assertEqual(resp.status_code, 410)
        self.assertFalse(Whisper.objects.filter(id=w.id).exists())

    def test_burn_after_read_deletes(self):
        w = self._create_whisper(max_views=1)
        # First GET shows confirmation page (not the actual content)
        resp = self.client.get(f"/whisper/{w.id}")
        self.assertEqual(resp.status_code, 200)
        self.assertTemplateUsed(resp, "whispers/confirm.html")
        # Whisper still exists — bot GETs don't burn
        self.assertTrue(Whisper.objects.filter(id=w.id).exists())
        # POST to reveal endpoint burns the whisper
        resp2 = self.client.post(f"/whisper/{w.id}")
        self.assertEqual(resp2.status_code, 200)
        data = resp2.json()
        self.assertIn("ciphertext", data)
        self.assertEqual(data["view_count"], 1)
        self.assertEqual(data["max_views"], 1)
        self.assertEqual(data["remaining_views"], 0)
        # Whisper is now gone
        self.assertFalse(Whisper.objects.filter(id=w.id).exists())
        # Revisiting the browser URL shows the burned page, not a JSON 404.
        revisit = self.client.get(f"/whisper/{w.id}")
        self.assertEqual(revisit.status_code, 404)
        self.assertTemplateUsed(revisit, "whispers/burned.html")
        self.assertEqual(revisit["Content-Type"], "text/html; charset=utf-8")
        # Second reveal should 404
        resp3 = self.client.post(f"/whisper/{w.id}")
        self.assertEqual(resp3.status_code, 404)

    def test_browser_reveal_renders_large_payload_without_web_storage(self):
        ciphertext = "x" * (6 * 1024 * 1024)
        w = self._create_whisper(max_views=1)
        redis_store.update_crypto(w.id, ciphertext=ciphertext)

        resp = self.client.post(
            f"/whisper/{w.id}?render=1",
            data="",
            content_type="application/x-www-form-urlencoded",
        )

        self.assertEqual(resp.status_code, 200)
        self.assertTemplateUsed(resp, "whispers/view.html")
        self.assertEqual(resp.context["paste_data"]["ciphertext"], ciphertext)
        self.assertNotContains(resp, "sessionStorage")
        self.assertFalse(Whisper.objects.filter(id=w.id).exists())

    def test_browser_reveal_expired_renders_expired_page(self):
        w = self._create_whisper(expires_at=timezone.now() - timedelta(seconds=1))

        resp = self.client.post(f"/whisper/{w.id}?render=1")

        self.assertEqual(resp.status_code, 410)
        self.assertTemplateUsed(resp, "whispers/expired.html")

    def test_api_reveal_expired_returns_json(self):
        w = self._create_whisper(expires_at=timezone.now() - timedelta(seconds=1))

        resp = self.client.post(f"/whisper/{w.id}")

        self.assertEqual(resp.status_code, 410)
        self.assertEqual(resp.json()["error"], "This whisper has expired")

    def test_browser_reveal_requires_auth_redirects_to_login(self):
        w = self._create_whisper(require_auth_view=True)

        resp = self.client.post(f"/whisper/{w.id}?render=1")

        self.assertEqual(resp.status_code, 302)
        self.assertIn(settings.LOGIN_URL, resp.url)
        self.assertIn("next=", resp.url)

    def test_api_reveal_requires_auth_returns_json(self):
        w = self._create_whisper(require_auth_view=True)

        resp = self.client.post(f"/whisper/{w.id}")

        self.assertEqual(resp.status_code, 403)
        self.assertEqual(resp.json()["error"], "Authentication required")

    def test_browser_reveal_ip_denial_renders_forbidden_page(self):
        w = self._create_whisper(allowed_cidr="192.168.1.0/24")

        resp = self.client.post(f"/whisper/{w.id}?render=1")

        self.assertEqual(resp.status_code, 403)
        self.assertTemplateUsed(resp, "whispers/forbidden.html")

    def test_api_reveal_ip_denial_returns_json(self):
        w = self._create_whisper(allowed_cidr="192.168.1.0/24")

        resp = self.client.post(f"/whisper/{w.id}")

        self.assertEqual(resp.status_code, 403)
        self.assertEqual(resp.json()["error"], "Access denied from your IP address")

    def test_browser_reveal_missing_payload_renders_expired_page(self):
        w = self._create_whisper()
        redis_store.delete_crypto(w.id)

        resp = self.client.post(f"/whisper/{w.id}?render=1")

        self.assertEqual(resp.status_code, 410)
        self.assertTemplateUsed(resp, "whispers/expired.html")
        self.assertFalse(Whisper.objects.filter(id=w.id).exists())

    def test_api_reveal_missing_payload_returns_json(self):
        w = self._create_whisper()
        redis_store.delete_crypto(w.id)

        resp = self.client.post(f"/whisper/{w.id}")

        self.assertEqual(resp.status_code, 410)
        self.assertEqual(resp.json()["error"], "This whisper has expired")

    def test_max_views_three_destroys_on_third(self):
        w = self._create_whisper(max_views=3)
        # First two reveals succeed, whisper survives.
        for expected_count in (1, 2):
            resp = self.client.post(f"/whisper/{w.id}")
            self.assertEqual(resp.status_code, 200)
            data = resp.json()
            self.assertEqual(data["view_count"], expected_count)
            self.assertEqual(data["max_views"], 3)
            self.assertEqual(data["remaining_views"], 3 - expected_count)
            self.assertTrue(Whisper.objects.filter(id=w.id).exists())
        # Third reveal is the final one — still returns content, then destroys.
        resp = self.client.post(f"/whisper/{w.id}")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["view_count"], 3)
        self.assertEqual(resp.json()["remaining_views"], 0)
        self.assertFalse(Whisper.objects.filter(id=w.id).exists())
        # Fourth reveal: 404 (whisper gone).
        resp = self.client.post(f"/whisper/{w.id}")
        self.assertEqual(resp.status_code, 404)

    def test_max_views_unlimited_does_not_destroy(self):
        w = self._create_whisper(max_views=0)
        for expected_count in range(1, 5):
            resp = self.client.post(f"/whisper/{w.id}")
            self.assertEqual(resp.status_code, 200)
            data = resp.json()
            self.assertEqual(data["view_count"], expected_count)
            self.assertEqual(data["max_views"], 0)
            self.assertTrue(Whisper.objects.filter(id=w.id).exists())

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
            data=json.dumps({"public_key": "pk", **payload}),
            content_type="application/json",
        )

    def test_public_key_required(self):
        resp = self.client.post(
            "/api/whisper/request", data="{}", content_type="application/json"
        )
        self.assertEqual(resp.status_code, 400)

    def test_submit_page_exposes_public_key(self):
        data = self._post({}).json()
        token = data["submit_url"].rsplit("/", 1)[1]
        resp = self.client.get(f"/submit/{token}")
        self.assertEqual(resp.context["request_data"]["public_key"], "pk")

    def test_create_request_returns_urls(self):
        resp = self._post({})
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("submit_url", data)
        self.assertIn("view_url", data)

    def test_submit_url_does_not_reveal_view_id(self):
        data = self._post({}).json()
        w = Whisper.objects.get(id=data["id"])
        self.assertNotIn(data["id"], data["submit_url"])
        self.assertIn(str(w.submit_token), data["submit_url"])
        self.assertIn(data["id"], data["view_url"])

    def test_password_fields_must_be_provided_together(self):
        self.assertEqual(self._post({"salt": "s"}).status_code, 400)
        resp = self._post({"salt": "s", "wrapped_key": "wk", "wrapped_key_iv": "iv"})
        self.assertEqual(resp.status_code, 200)
        crypto = redis_store.get_crypto(resp.json()["id"])
        self.assertEqual(crypto["wrapped_key"], "wk")

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
            "submit_token": uuid.uuid4(),
            "expiry_option": "1d",
            "expires_at": timezone.now() + timedelta(days=1),
        }
        defaults.update(kwargs)
        w = Whisper.objects.create(**defaults)
        redis_store.store_crypto(w.id, 86400)
        return w

    def _submit(self, w, payload=None):
        if payload is None:
            payload = {"ciphertext": "ct", "iv": "iv", "encapsulated_key": "epk"}
        return self.client.post(
            f"/api/whisper/submit/{w.submit_token}",
            data=json.dumps(payload),
            content_type="application/json",
        )

    # -- submit page --

    def test_submit_page_renders(self):
        w = self._create_request()
        resp = self.client.get(f"/submit/{w.submit_token}")
        self.assertEqual(resp.status_code, 200)
        self.assertNotContains(resp, str(w.id))

    def test_submit_page_rejects_view_id(self):
        w = self._create_request()
        resp = self.client.get(f"/submit/{w.id}")
        self.assertEqual(resp.status_code, 404)

    def test_submit_page_expired(self):
        w = self._create_request(expires_at=timezone.now() - timedelta(seconds=1))
        resp = self.client.get(f"/submit/{w.submit_token}")
        self.assertEqual(resp.status_code, 410)

    def test_submit_page_ip_blocked(self):
        w = self._create_request(allowed_cidr="192.168.1.0/24")
        resp = self.client.get(f"/submit/{w.submit_token}")
        self.assertEqual(resp.status_code, 403)

    def test_submit_page_already_submitted(self):
        w = self._create_request()
        redis_store.update_crypto(w.id, ciphertext="ct", iv="iv")
        resp = self.client.get(f"/submit/{w.submit_token}")
        self.assertEqual(resp.status_code, 200)
        self.assertTemplateUsed(resp, "whispers/submitted.html")

    # -- API submit --

    def test_api_submit_success(self):
        w = self._create_request()
        resp = self._submit(w)
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.json()["success"])
        data = redis_store.get_crypto(w.id)
        self.assertEqual(data["ciphertext"], "ct")
        self.assertEqual(data["encapsulated_key"], "epk")

    def test_api_submit_rejects_view_id(self):
        w = self._create_request()
        resp = self.client.post(
            f"/api/whisper/submit/{w.id}",
            data=json.dumps({"ciphertext": "ct", "iv": "iv", "encapsulated_key": "e"}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 404)

    def test_reveal_rejects_submit_token(self):
        w = self._create_request()
        self._submit(w)
        self.assertEqual(self.client.get(f"/whisper/{w.submit_token}").status_code, 404)
        self.assertEqual(
            self.client.post(f"/whisper/{w.submit_token}").status_code, 404
        )
        self.assertEqual(redis_store.get_crypto(w.id)["ciphertext"], "ct")

    def test_api_submit_missing_fields(self):
        w = self._create_request()
        resp = self._submit(w, {"ciphertext": "ct", "iv": "iv"})
        self.assertEqual(resp.status_code, 400)

    def test_api_submit_duplicate(self):
        w = self._create_request()
        redis_store.update_crypto(w.id, ciphertext="ct", iv="iv")
        resp = self._submit(
            w, {"ciphertext": "ct2", "iv": "iv2", "encapsulated_key": "e2"}
        )
        self.assertEqual(resp.status_code, 409)

    def test_api_submit_expired(self):
        w = self._create_request(expires_at=timezone.now() - timedelta(seconds=1))
        resp = self._submit(w)
        self.assertEqual(resp.status_code, 410)

    def test_api_submit_ip_blocked(self):
        w = self._create_request(allowed_cidr="192.168.1.0/24")
        resp = self._submit(w)
        self.assertEqual(resp.status_code, 403)

    # -- view after submit --

    def test_view_pending_request(self):
        w = self._create_request()
        resp = self.client.get(f"/whisper/{w.id}")
        self.assertEqual(resp.status_code, 200)
        self.assertTemplateUsed(resp, "whispers/pending.html")

    def test_post_reveal_pending_request_does_not_delete_payload(self):
        w = self._create_request(max_views=1)
        resp = self.client.post(f"/whisper/{w.id}")
        self.assertEqual(resp.status_code, 404)

        crypto = redis_store.get_crypto(w.id)
        self.assertIsNotNone(crypto)
        self.assertEqual(crypto["ciphertext"], "")

        submit_resp = self._submit(w)
        self.assertEqual(submit_resp.status_code, 200)

        reveal_resp = self.client.post(f"/whisper/{w.id}")
        self.assertEqual(reveal_resp.status_code, 200)
        self.assertEqual(reveal_resp.json()["ciphertext"], "ct")
        self.assertEqual(reveal_resp.json()["encapsulated_key"], "epk")

    def test_browser_reveal_pending_request_renders_pending_page(self):
        w = self._create_request(max_views=1)

        resp = self.client.post(f"/whisper/{w.id}?render=1")

        self.assertEqual(resp.status_code, 200)
        self.assertTemplateUsed(resp, "whispers/pending.html")
        crypto = redis_store.get_crypto(w.id)
        self.assertIsNotNone(crypto)
        self.assertEqual(crypto["ciphertext"], "")

    def test_view_after_submit(self):
        w = self._create_request()
        redis_store.update_crypto(w.id, ciphertext="ct", iv="iv")
        resp = self.client.get(f"/whisper/{w.id}")
        self.assertEqual(resp.status_code, 200)
        self.assertTemplateUsed(resp, "whispers/confirm.html")

    def test_non_burn_reveal_keeps_whisper(self):
        w = self._create_request(max_views=0)
        redis_store.update_crypto(w.id, ciphertext="ct", iv="iv")
        resp = self.client.post(f"/whisper/{w.id}")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("ciphertext", data)
        # Non-burn whisper should still exist
        self.assertTrue(Whisper.objects.filter(id=w.id).exists())


# ---------------------------------------------------------------------------
# Page render tests
# ---------------------------------------------------------------------------


@override_settings(
    MIDDLEWARE=_BASE_MIDDLEWARE,
    REST_FRAMEWORK=_TEST_REST_FRAMEWORK,
    ENABLE_AUTH=True,
    PSST_ENABLE_RECEIVE_ACCESS=True,
    PSST_RECEIVE_ACCESS_DEFAULT=False,
    PSST_FORCE_RECEIVE_ACCESS=False,
)
class ReceiveAccessTests(TestCase):
    def setUp(self):
        from allauth.account.models import EmailAddress

        cache.clear()
        self.addCleanup(cache.clear)
        self.patcher, self.redis = _patch_redis()
        self.patcher.start()
        self.addCleanup(self.patcher.stop)
        self.addCleanup(setattr, redis_store, "_client", None)
        self.creator = User.objects.create_user("creator", email="creator@example.com")
        self.reader = User.objects.create_user("reader", email="reader@example.com")
        self.other = User.objects.create_user("other", email="other@example.com")
        EmailAddress.objects.create(
            user=self.reader, email=self.reader.email, verified=True, primary=True
        )
        self.client.force_login(self.creator)

    def _create(self, **options):
        return self.client.post(
            "/api/whisper/request",
            data=json.dumps({"public_key": "pk", "max_views": 0, **options}),
            content_type="application/json",
        )

    def _restricted(self):
        response = self._create(creator_only=True)
        self.assertEqual(response.status_code, 200)
        whisper = Whisper.objects.get(pk=response.json()["id"])
        redis_store.update_crypto(whisper.id, ciphertext="ct", iv="iv")
        return whisper

    def _update(self, whisper, **options):
        return self.client.patch(
            f"/api/whisper/{whisper.id}/access",
            data=json.dumps(options),
            content_type="application/json",
        )

    def test_opt_in_and_unrestricted_default(self):
        response = self._create()
        whisper = Whisper.objects.get(pk=response.json()["id"])
        self.assertFalse(whisper.creator_only)
        self.assertEqual(whisper.creator, self.creator)
        self.assertTrue(self._restricted().creator_only)

    @override_settings(REST_FRAMEWORK=_TEST_RECEIVE_ACCESS_THROTTLING)
    def test_authenticated_creation_limits_email_lookups(self):
        with patch(
            "whispers.views._resolve_receive_readers", side_effect=ValueError
        ) as resolve:
            for _attempt in range(2):
                response = self._create(
                    creator_only=True, allowed_reader_emails=["missing@example.com"]
                )
                self.assertEqual(response.status_code, 400)
            response = self._create(
                creator_only=True, allowed_reader_emails=["missing@example.com"]
            )
            self.assertEqual(response.status_code, 429)
            self.assertEqual(resolve.call_count, 2)

    @override_settings(REST_FRAMEWORK=_TEST_RECEIVE_ACCESS_THROTTLING)
    def test_access_updates_share_creation_limit_across_client_ips(self):
        whisper = self._restricted()
        with patch(
            "whispers.views._resolve_receive_readers", side_effect=ValueError
        ) as resolve:
            response = self._update(
                whisper, allowed_reader_emails=["missing@example.com"]
            )
            self.assertEqual(response.status_code, 400)
            response = self.client.patch(
                f"/api/whisper/{whisper.id}/access",
                data=json.dumps({"allowed_reader_emails": ["missing@example.com"]}),
                content_type="application/json",
                REMOTE_ADDR="198.51.100.20",
            )
            self.assertEqual(response.status_code, 429)
            self.assertEqual(resolve.call_count, 1)
        self.assertEqual(whisper.allowed_readers.count(), 0)

    @override_settings(REST_FRAMEWORK=_TEST_RECEIVE_ACCESS_THROTTLING)
    def test_receive_access_limits_are_per_account(self):
        for _attempt in range(2):
            self.assertEqual(self._create().status_code, 200)
        self.assertEqual(self._create().status_code, 429)
        self.client.force_login(self.other)
        self.assertEqual(self._create().status_code, 200)

    @override_settings(REST_FRAMEWORK=_TEST_RECEIVE_ACCESS_THROTTLING)
    def test_anonymous_creation_keeps_existing_throttle(self):
        self.client.logout()
        for _attempt in range(3):
            self.assertEqual(self._create().status_code, 200)

    @override_settings(PSST_RECEIVE_ACCESS_DEFAULT=True)
    def test_default_can_be_disabled(self):
        self.assertTrue(
            Whisper.objects.get(pk=self._create().json()["id"]).creator_only
        )
        response = self._create(creator_only=False)
        self.assertFalse(Whisper.objects.get(pk=response.json()["id"]).creator_only)

    @override_settings(PSST_FORCE_RECEIVE_ACCESS=True)
    def test_force_cannot_be_bypassed(self):
        response = self._create(creator_only=False)
        whisper = Whisper.objects.get(pk=response.json()["id"])
        self.assertTrue(whisper.creator_only)
        self.assertEqual(self._update(whisper, creator_only=False).status_code, 400)

    def test_denied_reads_do_not_touch_redis(self):
        whisper = self._restricted()
        self.client.force_login(self.other)
        with (
            patch("whispers.views.redis_store.get_crypto") as get_crypto,
            patch("whispers.views.redis_store.increment_and_reveal") as reveal,
        ):
            self.assertEqual(self.client.get(f"/whisper/{whisper.id}").status_code, 403)
            for suffix in ("", "?render=1"):
                self.assertEqual(
                    self.client.post(f"/whisper/{whisper.id}{suffix}").status_code, 403
                )
            get_crypto.assert_not_called()
            reveal.assert_not_called()
        self.client.force_login(self.creator)
        self.assertEqual(self.client.post(f"/whisper/{whisper.id}").status_code, 200)

    def test_anonymous_cannot_create_or_reveal_restricted(self):
        whisper = self._restricted()
        self.client.logout()
        self.assertEqual(self._create(creator_only=True).status_code, 403)
        self.assertEqual(self.client.get(f"/whisper/{whisper.id}").status_code, 302)
        self.assertEqual(self.client.post(f"/whisper/{whisper.id}").status_code, 403)

    @override_settings(PSST_ENABLE_RECEIVE_ACCESS=False)
    def test_disabled_feature_rejects_opt_in(self):
        self.assertEqual(self._create(creator_only=True).status_code, 400)
        self.assertEqual(self._create().status_code, 200)

    def test_add_and_revoke_reader_without_consuming_reveal(self):
        whisper = self._restricted()
        response = self._update(whisper, allowed_reader_emails=["READER@example.com"])
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["allowed_reader_emails"], [self.reader.email])
        self.client.force_login(self.reader)
        self.assertEqual(self.client.post(f"/whisper/{whisper.id}").status_code, 200)
        self.assertEqual(self._update(whisper, creator_only=False).status_code, 404)
        self.assertEqual(
            self.client.get(f"/api/whisper/{whisper.id}/access").status_code, 404
        )
        self.client.force_login(self.creator)
        self.assertEqual(
            self._update(whisper, allowed_reader_emails=[]).status_code, 200
        )
        self.client.force_login(self.reader)
        self.assertEqual(self.client.post(f"/whisper/{whisper.id}").status_code, 403)

    def test_emails_validated_before_state_changes(self):
        whisper = self._restricted()
        for email in ("missing@example.com", self.other.email, "not-an-email"):
            self.assertEqual(
                self._update(whisper, allowed_reader_emails=[email]).status_code, 400
            )
        self.assertEqual(whisper.allowed_readers.count(), 0)
        self.assertEqual(
            self._create(
                creator_only=True, allowed_reader_emails=[self.reader.email]
            ).status_code,
            200,
        )

    def test_reader_validation_does_not_expose_exception_details(self):
        whisper = self._restricted()
        private_details = "Internal reader lookup failed at /private/database/path"
        with patch(
            "whispers.views._resolve_receive_readers",
            side_effect=ValueError(private_details),
        ):
            responses = [
                self._create(
                    creator_only=True, allowed_reader_emails=[self.reader.email]
                ),
                self._update(whisper, allowed_reader_emails=[self.reader.email]),
            ]
        for response in responses:
            self.assertEqual(response.status_code, 400)
            self.assertEqual(
                response.json(),
                {
                    "error": "Enter the verified primary email of each additional reader."
                },
            )
            self.assertNotIn(private_details, response.content.decode())
        self.assertEqual(Whisper.objects.count(), 1)
        whisper.refresh_from_db()
        self.assertTrue(whisper.creator_only)
        self.assertEqual(whisper.allowed_readers.count(), 0)

    def test_disable_clears_readers(self):
        whisper = self._restricted()
        self._update(whisper, allowed_reader_emails=[self.reader.email])
        self.assertEqual(self._update(whisper, creator_only=False).status_code, 200)
        whisper.refresh_from_db()
        self.assertFalse(whisper.creator_only)
        self.assertEqual(whisper.allowed_readers.count(), 0)

    def test_expired_or_send_whispers_cannot_be_managed(self):
        whisper = self._restricted()
        whisper.expires_at = timezone.now() - timedelta(seconds=1)
        whisper.save(update_fields=["expires_at"])
        self.assertEqual(self._update(whisper, creator_only=False).status_code, 404)
        whisper = Whisper.objects.create(mode="send", creator=self.creator)
        self.assertEqual(self._update(whisper, creator_only=True).status_code, 404)

    def test_pending_request_can_be_managed(self):
        response = self._create(creator_only=True)
        whisper = Whisper.objects.get(pk=response.json()["id"])
        self.assertEqual(
            self._update(
                whisper, allowed_reader_emails=[self.reader.email]
            ).status_code,
            200,
        )

    def test_management_requires_csrf(self):
        from django.test import Client

        whisper = self._restricted()
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.creator)
        response = client.patch(
            f"/api/whisper/{whisper.id}/access",
            data=json.dumps({"creator_only": False}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 403)

    def test_creator_can_manage_pending_confirm_and_unlimited_reveal(self):
        response = self._create(creator_only=True)
        whisper = Whisper.objects.get(pk=response.json()["id"])
        self.assertContains(
            self.client.get(f"/whisper/{whisper.id}"), 'id="receive-access-form"'
        )
        redis_store.update_crypto(whisper.id, ciphertext="ct", iv="iv")
        self.assertContains(
            self.client.get(f"/whisper/{whisper.id}"), 'id="receive-access-form"'
        )
        self.assertContains(
            self.client.post(f"/whisper/{whisper.id}?render=1"),
            'id="receive-access-form"',
        )
        self._update(whisper, allowed_reader_emails=[self.reader.email])
        self.client.force_login(self.reader)
        self.assertNotContains(
            self.client.get(f"/whisper/{whisper.id}"), 'id="receive-access-form"'
        )

    def test_burned_whisper_has_no_access_editor(self):
        response = self._create(creator_only=True, max_views=1)
        whisper = Whisper.objects.get(pk=response.json()["id"])
        redis_store.update_crypto(whisper.id, ciphertext="ct", iv="iv")
        self.assertNotContains(
            self.client.post(f"/whisper/{whisper.id}?render=1"),
            'id="receive-access-form"',
        )

    @override_settings(PSST_ENABLE_RECEIVE_ACCESS=False)
    def test_existing_restriction_survives_feature_disabled(self):
        whisper = Whisper.objects.create(
            mode="receive", creator=self.creator, creator_only=True
        )
        self.client.force_login(self.other)
        self.assertEqual(self.client.post(f"/whisper/{whisper.id}").status_code, 403)

    def test_creator_controls_render_only_for_signed_in_enabled_feature(self):
        self.assertContains(self.client.get("/"), 'id="creator-only"')
        with override_settings(PSST_ENABLE_RECEIVE_ACCESS=False):
            self.assertNotContains(self.client.get("/"), 'id="creator-only"')
        self.client.logout()
        self.assertNotContains(self.client.get("/"), 'id="creator-only"')

    def test_multiple_reader_emails_render_with_real_newlines(self):
        from allauth.account.models import EmailAddress

        EmailAddress.objects.create(
            user=self.other, email=self.other.email, verified=True, primary=True
        )
        whisper = self._restricted()
        self._update(
            whisper, allowed_reader_emails=[self.reader.email, self.other.email]
        )
        response = self.client.get(f"/whisper/{whisper.id}")
        self.assertContains(response, "other@example.com\nreader@example.com")

    def test_force_can_be_applied_when_editing_older_unrestricted_request(self):
        response = self._create(creator_only=False)
        whisper = Whisper.objects.get(pk=response.json()["id"])
        with override_settings(PSST_FORCE_RECEIVE_ACCESS=True):
            self.assertEqual(
                self._update(whisper, allowed_reader_emails=[]).status_code, 200
            )
        whisper.refresh_from_db()
        self.assertTrue(whisper.creator_only)


@override_settings(MIDDLEWARE=_BASE_MIDDLEWARE, REST_FRAMEWORK=_TEST_REST_FRAMEWORK)
class PageRenderTests(TestCase):

    def test_create_page(self):
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, 'href="/static/css/dist/styles.css"')
        self.assertContains(resp, 'src="/static/js/alpine.min.js"')
        self.assertNotContains(resp, "cdn.tailwindcss.com")
        self.assertNotContains(resp, "cdn.jsdelivr.net")

    def test_about_page(self):
        resp = self.client.get("/about")
        self.assertEqual(resp.status_code, 200)

    def test_referrer_policy_same_origin(self):
        resp = self.client.get("/")
        self.assertEqual(resp["Referrer-Policy"], "same-origin")


_LOGIN_MIDDLEWARE_STACK = [
    *_BASE_MIDDLEWARE,
    "whispers.middleware.LoginRequiredMiddleware",
]
_DEFAULT_EXEMPT_URLS = [
    r"login/",
    r"accounts/.*",
    r"i18n/.*",
    r"jsi18n/",
    r"static/.*",
    r"submit/.*",
    r"api/whisper/submit/.*",
    r"whisper/.*",
]


@override_settings(
    ENABLE_AUTH=True,
    MIDDLEWARE=_LOGIN_MIDDLEWARE_STACK,
    LOGIN_REQUIRED_EXEMPT_URLS=_DEFAULT_EXEMPT_URLS,
    PSST_FORCE_AUTH_VIEW=False,
    PSST_FORCE_AUTH_SUBMIT=False,
    PSST_ENABLE_RECEIVE_ACCESS=False,
    PSST_RECEIVE_ACCESS_DEFAULT=False,
    PSST_FORCE_RECEIVE_ACCESS=False,
    PSST_ENABLE_EMAIL=False,
    PSST_ENABLE_STATS=False,
    ABOUT_PAGE_PERSISTENCE_ENABLED=False,
    ENABLE_LOCAL_LOGIN=False,
    SOCIAL_AUTH_PROVIDERS=[],
    DATA_UPLOAD_MAX_MEMORY_SIZE=10_000_000,
)
class DeploymentFeaturesTests(TestCase):

    def _features(self):
        from django.utils import translation

        from whispers.deployment import deployment_features

        with translation.override("en"):
            return {f["key"]: f for f in deployment_features()}

    def _status(self, key):
        feature = self._features()[key]
        return str(feature["status"]), feature["state"]

    @override_settings(ENABLE_AUTH=False)
    def test_auth_disabled_shows_single_sign_in_row(self):
        features = self._features()
        self.assertEqual(
            list(features),
            ["sign_in", "email", "stats", "upload_limit", "storage"],
        )
        self.assertEqual(self._status("sign_in"), ("Not used", "off"))

    def test_auth_enabled_defaults_allow_link_only_access(self):
        self.assertEqual(self._status("sign_in"), ("Required", "on"))
        self.assertEqual(self._status("view_auth"), ("Link only", "off"))
        self.assertEqual(self._status("submit_auth"), ("Link only", "off"))
        self.assertEqual(self._status("receive_access"), ("Off", "off"))
        self.assertIn(
            "unless its creator requires sign-in",
            self._features()["view_auth"]["description"],
        )

    @override_settings(PSST_FORCE_AUTH_VIEW=True, PSST_FORCE_AUTH_SUBMIT=True)
    def test_forced_auth(self):
        self.assertEqual(self._status("view_auth"), ("Sign-in required", "on"))
        self.assertEqual(self._status("submit_auth"), ("Sign-in required", "on"))

    @override_settings(LOGIN_REQUIRED_EXEMPT_URLS=[r"login/", r"static/.*"])
    def test_login_middleware_exemptions_are_respected(self):
        self.assertEqual(self._status("view_auth"), ("Sign-in required", "on"))
        self.assertEqual(self._status("submit_auth"), ("Sign-in required", "on"))

    @override_settings(LOGIN_REQUIRED_EXEMPT_URLS=[*_DEFAULT_EXEMPT_URLS, r"$"])
    def test_exempt_create_page_alone_keeps_sign_in_required(self):
        self.assertEqual(self._status("sign_in"), ("Required", "on"))

    def test_sign_in_summary_matches_anonymous_creation(self):
        from django.core.cache import cache
        from django.test import Client

        cases = [
            ([r"$"], ("Required", "on"), False, False),
            ([r"$", r"api/whisper$"], ("Partly required", "neutral"), True, False),
            (
                [r"$", r"api/whisper/request$"],
                ("Partly required", "neutral"),
                False,
                True,
            ),
            (
                [r"$", r"api/whisper$", r"api/whisper/request$"],
                ("Optional", "neutral"),
                True,
                True,
            ),
        ]
        for extra, expected, send_open, request_open in cases:
            with override_settings(
                LOGIN_REQUIRED_EXEMPT_URLS=[*_DEFAULT_EXEMPT_URLS, *extra]
            ):
                self.assertEqual(self._status("sign_in"), expected, extra)
                cache.clear()
                client = Client()
                for path, is_open in (
                    ("/api/whisper", send_open),
                    ("/api/whisper/request", request_open),
                ):
                    response = client.post(path, {}, content_type="application/json")
                    self.assertEqual(
                        response.status_code != 302, is_open, (extra, path)
                    )

    def test_receive_access_states(self):
        cases = [
            ({}, ("Optional", "neutral")),
            ({"PSST_RECEIVE_ACCESS_DEFAULT": True}, ("On by default", "on")),
            (
                {
                    "PSST_RECEIVE_ACCESS_DEFAULT": True,
                    "PSST_FORCE_RECEIVE_ACCESS": True,
                },
                ("Always on", "on"),
            ),
        ]
        for extra, expected in cases:
            with override_settings(PSST_ENABLE_RECEIVE_ACCESS=True, **extra):
                self.assertEqual(self._status("receive_access"), expected, extra)
        with override_settings(
            PSST_ENABLE_RECEIVE_ACCESS=True, PSST_FORCE_RECEIVE_ACCESS=True
        ):
            description = self._features()["receive_access"]["description"]
        self.assertIn("New receive requests", description)
        self.assertIn(
            "Existing requests keep their current access setting.", description
        )

    @override_settings(SOCIAL_AUTH_PROVIDERS=["google"], ENABLE_LOCAL_LOGIN=True)
    def test_sign_in_methods(self):
        self.assertEqual(
            self._features()["sign_in"]["detail"],
            "Sign-in options: Google, username and password",
        )

    def test_no_sign_in_methods_omits_detail(self):
        self.assertEqual(self._features()["sign_in"]["detail"], "")

    @override_settings(
        PSST_ENABLE_EMAIL=True,
        PSST_ENABLE_STATS=True,
        ABOUT_PAGE_PERSISTENCE_ENABLED=True,
        DATA_UPLOAD_MAX_MEMORY_SIZE=5 * 1024**2,
    )
    def test_optional_features_enabled(self):
        self.assertEqual(self._status("email"), ("Available", "on"))
        self.assertEqual(self._status("stats"), ("On", "on"))
        self.assertEqual(self._status("storage"), ("Saved to disk", "neutral"))
        self.assertEqual(self._status("upload_limit"), ("5.0 MB", "neutral"))

    def test_optional_features_disabled(self):
        self.assertEqual(self._status("email"), ("Off", "off"))
        self.assertEqual(self._status("stats"), ("Off", "off"))
        self.assertEqual(self._status("storage"), ("Memory only", "neutral"))

    @override_settings(MIDDLEWARE=_BASE_MIDDLEWARE, PSST_FORCE_AUTH_VIEW=True)
    def test_about_page_renders_section(self):
        resp = self.client.get("/about")
        self.assertContains(resp, "Enabled Features for This Deployment")
        self.assertContains(resp, 'data-deployment-feature="view_auth" data-state="on"')
        self.assertContains(resp, "Sign-in required")

    @override_settings(MIDDLEWARE=_BASE_MIDDLEWARE, ENABLE_AUTH=False)
    def test_about_page_section_is_translated(self):
        resp = self.client.get("/about", HTTP_ACCEPT_LANGUAGE="da")
        self.assertContains(resp, 'data-deployment-feature="sign_in" data-state="off"')
        self.assertNotContains(resp, "Enabled Features for This Deployment")
        self.assertNotContains(resp, "No usage statistics are collected.")


@override_settings(MIDDLEWARE=_BASE_MIDDLEWARE, REST_FRAMEWORK=_TEST_REST_FRAMEWORK)
class BrandingTests(TestCase):

    def test_default_branding(self):
        resp = self.client.get("/")
        self.assertContains(resp, "<title>psst-secret — New Whisper</title>", html=True)
        self.assertContains(resp, 'href="/static/favicon.svg"')
        self.assertContains(resp, "🤫")
        self.assertNotContains(resp, "data-brand-logo")
        self.assertContains(resp, "https://github.com/ch0wm3in/psst-secret")
        self.assertContains(resp, "data-footer-text")

    @override_settings(
        PSST_BRAND_NAME="Acme <Vault>",
        PSST_BRAND_LOGO_URL="https://cdn.example.com/logo.svg",
        PSST_BRAND_FAVICON_URL="/media/favicon.ico",
    )
    def test_custom_name_logo_and_favicon(self):
        for path in ("/", "/about", f"/whisper/{uuid.uuid4()}"):
            resp = self.client.get(path)
            content = resp.content.decode()
            self.assertIn("<title>Acme &lt;Vault&gt; — ", content)
            self.assertIn('<link rel="icon" href="/media/favicon.ico">', content)
            self.assertIn('src="https://cdn.example.com/logo.svg"', content)
            self.assertNotIn("🤫", content)
            self.assertNotIn(
                "psst-secret", content.replace("github.com/ch0wm3in/psst-secret", "")
            )
        resp = self.client.get("/about")
        self.assertContains(resp, "About Acme &lt;Vault&gt;")
        self.assertContains(resp, "Acme &lt;Vault&gt; ensures that")

    @override_settings(PSST_BRAND_NAME="Acme Vault", LANGUAGE_CODE="da")
    def test_custom_name_in_translated_about_page(self):
        resp = self.client.get("/about", HTTP_ACCEPT_LANGUAGE="da")
        self.assertContains(resp, "Om Acme Vault")
        self.assertContains(resp, "Acme Vault sikrer, at")

    @override_settings(PSST_HIDE_SOCIAL_LINKS=True, APP_VERSION="v1.2.3")
    def test_hide_social_links(self):
        resp = self.client.get("/")
        self.assertNotContains(resp, "github.com")
        self.assertContains(
            resp, '<span class="text-gray-600">v1.2.3</span>', html=True
        )
        self.assertContains(resp, "data-footer-text")

    def test_about_intro_explains_default_name(self):
        resp = self.client.get("/about")
        self.assertContains(resp, "Psst… wanna hear a secret?")
        self.assertContains(
            resp,
            'That is where the name <strong class="text-white">psst-secret</strong>',
        )
        self.assertContains(resp, "end-to-end encrypted exchange between two people")

    @override_settings(PSST_BRAND_NAME="Acme Vault")
    def test_about_intro_omits_name_origin_for_custom_brand(self):
        resp = self.client.get("/about")
        self.assertContains(resp, "Psst… wanna hear a secret?")
        self.assertNotContains(resp, "That is where the name")

    @override_settings(PSST_HIDE_NAV_BRAND_NAME=True, PSST_BRAND_NAME="Acme")
    def test_hide_nav_brand_name(self):
        resp = self.client.get("/")
        self.assertContains(
            resp, '<span class="sr-only" data-nav-brand-name>Acme</span>', html=True
        )
        self.assertContains(resp, "<title>Acme — New Whisper</title>", html=True)

    def test_nav_brand_name_visible_by_default(self):
        resp = self.client.get("/")
        self.assertContains(
            resp, "<span data-nav-brand-name>psst-secret</span>", html=True
        )

    @override_settings(PSST_HIDE_FOOTER_TEXT=True)
    def test_hide_footer_text(self):
        resp = self.client.get("/")
        self.assertNotContains(resp, "data-footer-text")
        self.assertNotContains(resp, "Don&#x27;t tell anyone")
        self.assertContains(resp, "https://github.com/ch0wm3in/psst-secret")

    def test_asset_url_check(self):
        from whispers.checks import check_branding_urls

        valid = [
            "",
            "/static/logo.svg",
            "https://example.com/logo.png",
            "http://example.com/logo.png",
            "data:image/svg+xml;base64,PHN2Zy8+",
        ]
        invalid = [
            "logo.svg",
            "//evil.example/logo.svg",
            "javascript:alert(1)",
            "https://",
            "http:///logo.svg",
            "https://:443/logo.svg",
            "http://[::1/logo.svg",
            "ftp://example.com/logo.png",
        ]
        for url in valid:
            with override_settings(PSST_BRAND_LOGO_URL=url, PSST_BRAND_FAVICON_URL=url):
                self.assertEqual(check_branding_urls(None), [], url)
        for url in invalid:
            with override_settings(PSST_BRAND_LOGO_URL=url, PSST_BRAND_FAVICON_URL=url):
                errors = check_branding_urls(None)
                self.assertEqual(len(errors), 2, url)
                self.assertEqual(errors[0].id, "whispers.E001")


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
