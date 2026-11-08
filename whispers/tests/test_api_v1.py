import json
import uuid
from datetime import timedelta
from io import StringIO
from pathlib import Path

from django.conf import settings
from django.contrib.auth.models import User
from django.core.cache import cache
from django.core.management import call_command
from django.test import TestCase, override_settings
from django.utils import timezone

from whispers import redis_store
from whispers.models import Whisper
from whispers.tests.test_whisper import (
    _BASE_MIDDLEWARE,
    _DEFAULT_EXEMPT_URLS,
    _LOGIN_MIDDLEWARE_STACK,
    _REVEAL_TOKEN,
    _REVEAL_TOKEN_HASH,
    _TEST_REST_FRAMEWORK,
    _patch_redis,
)


class OpenApiSchemaTests(TestCase):
    def test_committed_schema_is_current(self):
        out = StringIO()
        call_command("spectacular", fail_on_warn=True, stdout=out)
        committed = (Path(settings.BASE_DIR) / "spec" / "openapi.yaml").read_text()
        self.assertEqual(
            out.getvalue().rstrip("\n"),
            committed.rstrip("\n"),
            "spec/openapi.yaml is out of date. Regenerate it with "
            "`python manage.py spectacular --file spec/openapi.yaml`.",
        )


@override_settings(MIDDLEWARE=_BASE_MIDDLEWARE, REST_FRAMEWORK=_TEST_REST_FRAMEWORK)
class ApiV1Tests(TestCase):
    def setUp(self):
        cache.clear()
        self.addCleanup(cache.clear)
        self.patcher, self.redis = _patch_redis()
        self.patcher.start()

    def tearDown(self):
        self.patcher.stop()
        redis_store._client = None

    def _post(self, path, payload):
        return self.client.post(
            path, data=json.dumps(payload), content_type="application/json"
        )

    def _create(self, path="/api/v1/whisper", **payload):
        return self._post(
            path,
            {
                "ciphertext": "ct",
                "iv": "iv",
                "reveal_token_hash": _REVEAL_TOKEN_HASH,
                **payload,
            },
        )

    def _create_request(self, **payload):
        response = self._post(
            "/api/v1/whisper/request",
            {"public_key": "pk", "reveal_token_hash": _REVEAL_TOKEN_HASH, **payload},
        )
        self.assertEqual(response.status_code, 200)
        return Whisper.objects.get(id=response.json()["id"])

    def _reveal(self, whisper_id):
        return self._post(
            f"/api/v1/whisper/{whisper_id}/reveal", {"reveal_token": _REVEAL_TOKEN}
        )

    @override_settings(
        APP_VERSION="v9.8.7",
        PSST_ENABLE_API_TOKENS=False,
        PSST_ENABLE_EMAIL=False,
        PSST_ENABLE_RECEIVE_ACCESS=False,
        PSST_ENABLE_RECEIVE_HISTORY=False,
        PSST_ENABLE_RICH_TEXT=False,
        PSST_FORCE_AUTH_VIEW=False,
        PSST_FORCE_AUTH_SUBMIT=False,
        DATA_UPLOAD_MAX_MEMORY_SIZE=10_000_000,
    )
    def test_info_reports_versions(self):
        response = self.client.get("/api/v1/info")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {
                "server_version": "v9.8.7",
                "api_version": 1,
                "format_versions": [1],
                "auth": {
                    "login_required": False,
                    "loopback_pkce": False,
                    "manual_code": False,
                    "extension_redirect": False,
                    "scopes": [],
                },
                "features": {
                    "email_notifications": False,
                    "receive_access": {
                        "enabled": False,
                        "default": False,
                        "required": False,
                    },
                    "receive_history": False,
                    "rich_text": False,
                },
                "policies": {
                    "view_requires_auth": False,
                    "submit_requires_auth": False,
                },
                "limits": {
                    "max_upload_bytes": 10_000_000,
                    "max_views": 100,
                    "expiry_options": ["5m", "1h", "1d", "1w", "1M"],
                },
            },
        )

    @override_settings(
        ENABLE_AUTH=True,
        PSST_ENABLE_EMAIL=True,
        PSST_ENABLE_RECEIVE_ACCESS=True,
        PSST_RECEIVE_ACCESS_DEFAULT=False,
        PSST_FORCE_RECEIVE_ACCESS=True,
        PSST_ENABLE_RECEIVE_HISTORY=True,
        PSST_ENABLE_RICH_TEXT=True,
        PSST_FORCE_AUTH_VIEW=True,
        PSST_FORCE_AUTH_SUBMIT=False,
    )
    def test_info_reports_enabled_features_and_policies(self):
        data = self.client.get("/api/v1/info").json()
        self.assertEqual(
            data["features"],
            {
                "email_notifications": True,
                "receive_access": {"enabled": True, "default": True, "required": True},
                "receive_history": True,
                "rich_text": True,
            },
        )
        self.assertEqual(
            data["policies"],
            {"view_requires_auth": True, "submit_requires_auth": False},
        )

    @override_settings(
        ENABLE_AUTH=True,
        MIDDLEWARE=_LOGIN_MIDDLEWARE_STACK,
        LOGIN_REQUIRED_EXEMPT_URLS=[r"api/v1/info$", r"whisper/.*"],
        PSST_FORCE_AUTH_VIEW=False,
        PSST_FORCE_AUTH_SUBMIT=False,
    )
    def test_info_policies_follow_login_exemptions(self):
        data = self.client.get("/api/v1/info").json()
        self.assertEqual(
            data["policies"],
            {"view_requires_auth": False, "submit_requires_auth": True},
        )
        self.assertTrue(data["auth"]["login_required"])

    def test_format_version_is_stored_and_returned_on_reveal(self):
        for path, payload, expected in (
            ("/api/v1/whisper", {"v": 1}, 1),
            ("/api/whisper", {}, 0),
        ):
            with self.subTest(path=path):
                whisper_id = self._create(path, **payload).json()["id"]
                self.assertEqual(redis_store.get_crypto(whisper_id)["v"], expected)
                response = self._reveal(whisper_id)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.json()["v"], expected)
                self.assertEqual(response.json()["ciphertext"], "ct")

    def test_reveal_of_payload_without_version_returns_legacy_version(self):
        whisper_id = self._create().json()["id"]
        crypto = redis_store.get_crypto(whisper_id)
        del crypto["v"]
        self.redis.set(redis_store._key(whisper_id), json.dumps(crypto), keepttl=True)
        self.assertEqual(self._reveal(whisper_id).json()["v"], 0)

    def test_unsupported_format_versions_are_rejected(self):
        whisper = self._create_request()
        for value in (0, 2, "x", None):
            with self.subTest(value=value):
                self.assertEqual(self._create(v=value).status_code, 400)
                response = self._post(
                    "/api/v1/whisper/request",
                    {
                        "public_key": "pk",
                        "reveal_token_hash": _REVEAL_TOKEN_HASH,
                        "v": value,
                    },
                )
                self.assertEqual(response.status_code, 400)
                response = self._post(
                    f"/api/v1/whisper/submit/{whisper.submit_token}",
                    {
                        "ciphertext": "ct",
                        "iv": "iv",
                        "encapsulated_key": "ek",
                        "v": value,
                    },
                )
                self.assertEqual(response.status_code, 400)
        self.assertEqual(Whisper.objects.count(), 1)
        self.assertEqual(redis_store.get_crypto(whisper.id)["ciphertext"], "")

    def test_reveal_endpoint_is_json_only(self):
        whisper_id = self._create().json()["id"]
        self.assertEqual(
            self.client.get(f"/api/v1/whisper/{whisper_id}/reveal").status_code, 405
        )
        response = self._post(
            f"/api/v1/whisper/{whisper_id}/reveal?render=1",
            {"reveal_token": _REVEAL_TOKEN},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/json")
        self.assertFalse(Whisper.objects.exists())

    def test_reveal_endpoint_requires_reveal_token(self):
        whisper_id = self._create().json()["id"]
        response = self._post(f"/api/v1/whisper/{whisper_id}/reveal", {})
        self.assertEqual(response.status_code, 403)
        self.assertNotIn("ciphertext", response.json())
        self.assertEqual(redis_store.get_view_count(whisper_id), 0)

    def test_receive_round_trip(self):
        whisper = self._create_request(v=1)
        url = f"/api/v1/whisper/submit/{whisper.submit_token}"
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"public_key": "pk", "v": 1})
        response = self._post(
            url, {"ciphertext": "ct", "iv": "iv", "encapsulated_key": "ek", "v": 1}
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.client.get(url).status_code, 409)
        data = self._reveal(whisper.id).json()
        self.assertEqual((data["v"], data["encapsulated_key"]), (1, "ek"))

    def test_submit_key_lookup_checks_request(self):
        self.assertEqual(
            self.client.get(f"/api/v1/whisper/submit/{uuid.uuid4()}").status_code, 404
        )
        whisper = self._create_request(allowed_cidr="192.0.2.0/24")
        response = self.client.get(f"/api/v1/whisper/submit/{whisper.submit_token}")
        self.assertEqual(response.status_code, 403)
        self.assertNotIn("public_key", response.json())
        Whisper.objects.filter(pk=whisper.pk).update(
            expires_at=timezone.now() - timedelta(seconds=1)
        )
        response = self.client.get(f"/api/v1/whisper/submit/{whisper.submit_token}")
        self.assertEqual(response.status_code, 410)
        self.assertIsNone(redis_store.get_crypto(whisper.id))

    def test_submit_page_exposes_request_version(self):
        whisper = self._create_request(v=1)
        response = self.client.get(f"/submit/{whisper.submit_token}")
        self.assertEqual(response.context["request_data"]["v"], 1)

    def test_view_id_cannot_fetch_submit_key(self):
        whisper = self._create_request()
        response = self.client.get(f"/api/v1/whisper/submit/{whisper.id}")
        self.assertEqual(response.status_code, 404)


@override_settings(
    ENABLE_AUTH=True,
    MIDDLEWARE=_LOGIN_MIDDLEWARE_STACK,
    REST_FRAMEWORK=_TEST_REST_FRAMEWORK,
    LOGIN_URL="/login/",
    LOGIN_REQUIRED_EXEMPT_URLS=_DEFAULT_EXEMPT_URLS,
)
class ApiV1LoginRequiredTests(TestCase):
    def test_default_exemptions_cover_link_holder_endpoints(self):
        missing = uuid.uuid4()
        for method, path, exempt in (
            ("post", f"/api/v1/whisper/{missing}/reveal", True),
            ("get", f"/api/v1/whisper/submit/{missing}", True),
            ("post", f"/api/v1/whisper/submit/{missing}", True),
            ("get", "/api/v1/info", True),
            ("post", "/api/v1/cli/token", True),
            ("post", "/api/v1/whisper", False),
            ("post", "/api/v1/whisper/request", False),
            ("get", f"/api/v1/whisper/{missing}/access", False),
            ("get", f"/api/v1/whisper/{missing}/status", True),
        ):
            with self.subTest(method=method, path=path):
                response = getattr(self.client, method)(path)
                # API clients get a JSON 401 instead of a redirect to the login page.
                self.assertEqual(response.status_code == 401, not exempt)
                self.assertNotEqual(response.status_code, 302)

    @override_settings(
        PSST_FORCE_AUTH_VIEW=True,
        LOGIN_REQUIRED_EXEMPT_URLS=[
            p for p in _DEFAULT_EXEMPT_URLS if p != r"whisper/.*"
        ],
    )
    def test_status_follows_the_view_exemption(self):
        response = self.client.get(f"/api/v1/whisper/{uuid.uuid4()}/status")
        self.assertEqual(response.status_code, 401)


@override_settings(
    MIDDLEWARE=_BASE_MIDDLEWARE,
    REST_FRAMEWORK=_TEST_REST_FRAMEWORK,
    PSST_FORCE_AUTH_VIEW=False,
)
class WhisperStatusTests(TestCase):
    def setUp(self):
        cache.clear()
        self.addCleanup(cache.clear)
        self.patcher, self.redis = _patch_redis()
        self.patcher.start()

    def tearDown(self):
        self.patcher.stop()
        redis_store._client = None

    def _post(self, path, payload):
        return self.client.post(
            path, data=json.dumps(payload), content_type="application/json"
        )

    def _request(self, **payload):
        response = self._post(
            "/api/v1/whisper/request",
            {"public_key": "pk", "reveal_token_hash": _REVEAL_TOKEN_HASH, **payload},
        )
        self.assertEqual(response.status_code, 200)
        return Whisper.objects.get(id=response.json()["id"])

    def _submit(self, whisper):
        response = self._post(
            f"/api/v1/whisper/submit/{whisper.submit_token}",
            {"ciphertext": "ct", "iv": "iv", "encapsulated_key": "ek"},
        )
        self.assertEqual(response.status_code, 200)

    def _status(self, whisper_id, client=None):
        return (client or self.client).get(f"/api/v1/whisper/{whisper_id}/status")

    def _reveal(self, whisper_id):
        return self._post(
            f"/api/v1/whisper/{whisper_id}/reveal", {"reveal_token": _REVEAL_TOKEN}
        )

    def test_request_response_includes_expiry(self):
        response = self._post(
            "/api/v1/whisper/request",
            {
                "public_key": "pk",
                "reveal_token_hash": _REVEAL_TOKEN_HASH,
                "expiry": "1h",
            },
        )
        whisper = Whisper.objects.get()
        self.assertEqual(
            response.json()["expires_at"],
            whisper.expires_at.isoformat().replace("+00:00", "Z"),
        )

    def test_available_regardless_of_receive_history(self):
        whisper = self._request()
        for enabled in (False, True):
            with (
                self.subTest(enabled=enabled),
                self.settings(PSST_ENABLE_RECEIVE_HISTORY=enabled),
            ):
                response = self._status(whisper.id)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.json()["status"], "pending")

    def test_pending_then_submitted_without_consuming_views(self):
        whisper = self._request(max_views=1)
        response = self._status(whisper.id)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {
                "status": "pending",
                "expires_at": whisper.expires_at.isoformat().replace("+00:00", "Z"),
                "view_count": 0,
                "max_views": 1,
                "remaining_views": 1,
            },
        )
        self._submit(whisper)
        stored = redis_store.get_crypto(whisper.id)
        for _ in range(3):
            response = self._status(whisper.id)
            self.assertEqual(response.json()["status"], "submitted")
            self.assertNotIn("ciphertext", response.content.decode())
            self.assertNotIn("ek", response.json().values())
        self.assertEqual(redis_store.get_view_count(whisper.id), 0)
        self.assertEqual(redis_store.get_crypto(whisper.id), stored)
        self.assertEqual(self._reveal(whisper.id).status_code, 200)

    def test_reports_views_and_gone_after_final_reveal(self):
        whisper = self._request(max_views=2)
        self._submit(whisper)
        self._reveal(whisper.id)
        data = self._status(whisper.id).json()
        self.assertEqual(
            (data["view_count"], data["remaining_views"], data["max_views"]), (1, 1, 2)
        )
        self._reveal(whisper.id)
        response = self._status(whisper.id)
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json(), {"status": "gone"})

    def test_unlimited_views_report_zero_remaining(self):
        whisper = self._request(max_views=0)
        self._submit(whisper)
        self._reveal(whisper.id)
        data = self._status(whisper.id).json()
        self.assertEqual((data["view_count"], data["remaining_views"]), (1, 0))

    def test_submitted_status_does_not_read_the_payload(self):
        whisper = self._request()
        self._submit(whisper)
        marker = redis_store._submitted_key(whisper.id)
        self.assertGreater(self.redis.pttl(marker), 0)
        self.assertAlmostEqual(
            self.redis.pttl(marker),
            self.redis.pttl(redis_store._key(whisper.id)),
            delta=1000,
        )
        # Any read of the payload would fail to parse it.
        self.redis.set(redis_store._key(whisper.id), "not json", keepttl=True)
        self.assertEqual(self._status(whisper.id).json()["status"], "submitted")

    def test_submission_without_marker_is_reported_and_marked(self):
        whisper = self._request()
        redis_store.update_crypto(whisper.id, ciphertext="ct", iv="iv")
        marker = redis_store._submitted_key(whisper.id)
        self.assertFalse(self.redis.exists(marker))
        self.assertEqual(self._status(whisper.id).json()["status"], "submitted")
        self.assertGreater(self.redis.pttl(marker), 0)

    def test_marker_is_removed_with_the_whisper(self):
        burned = self._request(max_views=1)
        self._submit(burned)
        self._reveal(burned.id)
        deleted = self._request()
        self._submit(deleted)
        redis_store.delete_crypto(deleted.id)
        for whisper in (burned, deleted):
            with self.subTest(whisper=whisper.pk):
                self.assertFalse(
                    self.redis.exists(redis_store._submitted_key(whisper.id))
                )

    def test_expired_and_evicted_requests_are_gone_and_cleaned_up(self):
        expired = self._request()
        Whisper.objects.filter(pk=expired.pk).update(
            expires_at=timezone.now() - timedelta(seconds=1)
        )
        evicted = self._request()
        redis_store.delete_crypto(evicted.id)
        for whisper in (expired, evicted):
            with self.subTest(whisper=whisper.pk):
                response = self._status(whisper.id)
                self.assertEqual(response.status_code, 410)
                self.assertEqual(response.json(), {"status": "gone"})
                self.assertFalse(Whisper.objects.filter(pk=whisper.pk).exists())
                self.assertIsNone(redis_store.get_crypto(whisper.id))

    def test_unknown_ids_and_send_whispers_are_gone(self):
        response = self._post(
            "/api/v1/whisper",
            {"ciphertext": "ct", "iv": "iv", "reveal_token_hash": _REVEAL_TOKEN_HASH},
        )
        for whisper_id in (uuid.uuid4(), response.json()["id"]):
            with self.subTest(whisper_id=whisper_id):
                response = self._status(whisper_id)
                self.assertEqual(response.status_code, 404)
                self.assertEqual(response.json(), {"status": "gone"})

    def test_submit_token_cannot_be_used_as_view_id(self):
        whisper = self._request()
        self.assertEqual(self._status(whisper.submit_token).status_code, 404)

    def test_per_whisper_view_auth_is_required(self):
        whisper = self._request(require_auth_view=True)
        response = self._status(whisper.id)
        self.assertEqual(response.status_code, 403)
        self.assertNotIn("status", response.json())
        self.client.force_login(User.objects.create_user("viewer"))
        self.assertEqual(self._status(whisper.id).status_code, 200)

    @override_settings(PSST_FORCE_AUTH_VIEW=True)
    def test_forced_view_auth_is_required(self):
        whisper = self._request()
        self.assertEqual(self._status(whisper.id).status_code, 403)

    def test_reader_access_is_enforced(self):
        creator = User.objects.create_user("creator")
        reader = User.objects.create_user("reader")
        stranger = User.objects.create_user("stranger")
        whisper = self._request()
        Whisper.objects.filter(pk=whisper.pk).update(creator=creator, creator_only=True)
        whisper.allowed_readers.add(reader)
        self.assertEqual(self._status(whisper.id).status_code, 403)
        for user, allowed in ((stranger, False), (creator, True), (reader, True)):
            with self.subTest(user=user.username):
                self.client.force_login(user)
                response = self._status(whisper.id)
                self.assertEqual(response.status_code, 200 if allowed else 403)
                self.assertEqual("status" in response.json(), allowed)
        self.assertTrue(Whisper.objects.filter(pk=whisper.pk).exists())

    def test_status_is_read_only(self):
        whisper = self._request()
        for method in ("post", "put", "patch", "delete"):
            with self.subTest(method=method):
                response = getattr(self.client, method)(
                    f"/api/v1/whisper/{whisper.id}/status"
                )
                self.assertEqual(response.status_code, 405)

    @override_settings(
        REST_FRAMEWORK={
            **_TEST_REST_FRAMEWORK,
            "DEFAULT_THROTTLE_RATES": {
                **_TEST_REST_FRAMEWORK["DEFAULT_THROTTLE_RATES"],
                "whisper_status": "2/minute",
            },
        }
    )
    def test_status_has_its_own_rate_limit(self):
        from whispers.views import WhisperStatusThrottle

        whisper = self._request()
        original = WhisperStatusThrottle.THROTTLE_RATES
        WhisperStatusThrottle.THROTTLE_RATES = settings.REST_FRAMEWORK[
            "DEFAULT_THROTTLE_RATES"
        ]
        self.addCleanup(setattr, WhisperStatusThrottle, "THROTTLE_RATES", original)
        codes = [self._status(whisper.id).status_code for _ in range(3)]
        self.assertEqual(codes, [200, 200, 429])
        self.assertEqual(
            self._reveal(whisper.id).status_code, 404, "reveal limit is separate"
        )

    @override_settings(
        REST_FRAMEWORK={
            **_TEST_REST_FRAMEWORK,
            "DEFAULT_THROTTLE_RATES": {
                **_TEST_REST_FRAMEWORK["DEFAULT_THROTTLE_RATES"],
                "whisper_status": "2/minute",
            },
        }
    )
    def test_status_rate_limit_applies_to_authenticated_users(self):
        from whispers.views import WhisperStatusThrottle

        whisper = self._request()
        self.client.force_login(User.objects.create_user("status-reader"))

        original = WhisperStatusThrottle.THROTTLE_RATES
        WhisperStatusThrottle.THROTTLE_RATES = settings.REST_FRAMEWORK[
            "DEFAULT_THROTTLE_RATES"
        ]
        self.addCleanup(setattr, WhisperStatusThrottle, "THROTTLE_RATES", original)
        codes = [self._status(whisper.id).status_code for _ in range(3)]
        self.assertEqual(codes, [200, 200, 429])
