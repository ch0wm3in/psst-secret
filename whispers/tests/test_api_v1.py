import json
import uuid
from datetime import timedelta
from io import StringIO
from pathlib import Path

from django.conf import settings
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

    @override_settings(APP_VERSION="v9.8.7")
    def test_info_reports_versions(self):
        response = self.client.get("/api/v1/info")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {"server_version": "v9.8.7", "api_version": 1, "format_versions": [1]},
        )

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
            ("get", "/api/v1/info", False),
            ("post", "/api/v1/whisper", False),
            ("post", "/api/v1/whisper/request", False),
            ("get", f"/api/v1/whisper/{missing}/access", False),
        ):
            with self.subTest(method=method, path=path):
                response = getattr(self.client, method)(path)
                self.assertEqual(response.status_code == 302, not exempt)
