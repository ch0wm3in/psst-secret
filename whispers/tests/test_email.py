import json
import uuid
from datetime import timedelta
from unittest.mock import patch

import fakeredis
from django.conf import settings
from django.core import mail
from django.test import TestCase, override_settings
from django.utils import timezone

from whispers import redis_store
from whispers.models import Whisper

# ---------------------------------------------------------------------------
# Helpers (mirror test_whisper.py setup)
# ---------------------------------------------------------------------------

_BASE_MIDDLEWARE = [
    m for m in settings.MIDDLEWARE if m != "whispers.middleware.LoginRequiredMiddleware"
]

_TEST_REST_FRAMEWORK = {
    **settings.REST_FRAMEWORK,
    "DEFAULT_THROTTLE_CLASSES": [],
    "DEFAULT_THROTTLE_RATES": {
        "anon": "10000/minute",
        "whisper_create": "10000/minute",
        "whisper_view": "",
    },
}


def _fake_redis_client():
    return fakeredis.FakeRedis(decode_responses=True)


def _patch_redis():
    client = _fake_redis_client()
    return patch.object(redis_store, "get_client", return_value=client), client


# ---------------------------------------------------------------------------
# Email notification tests
# ---------------------------------------------------------------------------


@override_settings(
    MIDDLEWARE=_BASE_MIDDLEWARE,
    REST_FRAMEWORK=_TEST_REST_FRAMEWORK,
    EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",
    PSST_ENABLE_EMAIL=True,
    DEFAULT_FROM_EMAIL="test@example.com",
)
class SendModeEmailTests(TestCase):
    """Test email notifications when creating whispers in send mode."""

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

    def test_email_sent_on_create_with_notify_email(self):
        resp = self._post({
            "ciphertext": "ct",
            "iv": "iv",
            "notify_email": "recipient@example.com",
        })
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(mail.outbox), 1)
        msg = mail.outbox[0]
        self.assertEqual(msg.to, ["recipient@example.com"])
        self.assertIn("psst", msg.subject.lower())
        self.assertIn("/whisper/", msg.body)
        # Email must warn about incomplete link
        self.assertIn("NOT contain the decryption key", msg.body)

    def test_no_email_when_notify_email_empty(self):
        resp = self._post({
            "ciphertext": "ct",
            "iv": "iv",
            "notify_email": "",
        })
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(mail.outbox), 0)

    def test_no_email_when_notify_email_absent(self):
        resp = self._post({
            "ciphertext": "ct",
            "iv": "iv",
        })
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(mail.outbox), 0)

    def test_invalid_notify_email_rejected(self):
        resp = self._post({
            "ciphertext": "ct",
            "iv": "iv",
            "notify_email": "not-an-email",
        })
        self.assertEqual(resp.status_code, 400)

    def test_notify_email_stored_in_model(self):
        resp = self._post({
            "ciphertext": "ct",
            "iv": "iv",
            "notify_email": "user@example.com",
        })
        wid = resp.json()["id"]
        w = Whisper.objects.get(id=wid)
        self.assertEqual(w.notify_email, "user@example.com")

    def test_email_url_does_not_contain_fragment(self):
        """The emailed URL must NOT include the decryption key (fragment)."""
        resp = self._post({
            "ciphertext": "ct",
            "iv": "iv",
            "notify_email": "recipient@example.com",
        })
        self.assertEqual(resp.status_code, 200)
        msg = mail.outbox[0]
        wid = resp.json()["id"]
        # The whisper URL should appear in the email
        self.assertIn(f"/whisper/{wid}", msg.body)
        # The URL line should not have a '#' fragment appended
        for line in msg.body.splitlines():
            if f"/whisper/{wid}" in line:
                self.assertFalse(
                    line.strip().endswith("#") or "#" in line.split(f"/whisper/{wid}")[1],
                    f"URL line contains a fragment: {line}",
                )


@override_settings(
    MIDDLEWARE=_BASE_MIDDLEWARE,
    REST_FRAMEWORK=_TEST_REST_FRAMEWORK,
    EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",
    PSST_ENABLE_EMAIL=False,
    DEFAULT_FROM_EMAIL="test@example.com",
)
class SendModeEmailDisabledTests(TestCase):
    """Test that emails are NOT sent when PSST_ENABLE_EMAIL is False."""

    def setUp(self):
        self.patcher, self.redis = _patch_redis()
        self.patcher.start()

    def tearDown(self):
        self.patcher.stop()
        redis_store._client = None

    def test_no_email_when_disabled(self):
        resp = self.client.post(
            "/api/whisper",
            data=json.dumps({
                "ciphertext": "ct",
                "iv": "iv",
                "notify_email": "recipient@example.com",
            }),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(mail.outbox), 0)


@override_settings(
    MIDDLEWARE=_BASE_MIDDLEWARE,
    REST_FRAMEWORK=_TEST_REST_FRAMEWORK,
    EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",
    PSST_ENABLE_EMAIL=True,
    DEFAULT_FROM_EMAIL="test@example.com",
)
class ReceiveModeEmailTests(TestCase):
    """Test email notifications for receive-mode whisper requests."""

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

    def test_email_sent_on_create_request_with_notify_email(self):
        """Creating a receive request should NOT immediately send email."""
        resp = self.client.post(
            "/api/whisper/request",
            data=json.dumps({
                "salt": "s",
                "notify_email": "creator@example.com",
            }),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 200)
        # Email is only sent when someone submits, not on creation
        self.assertEqual(len(mail.outbox), 0)

    def test_email_sent_on_submit(self):
        """Submitting to a receive request should notify the creator."""
        w = self._create_request(notify_email="creator@example.com")
        resp = self.client.post(
            f"/api/whisper/submit/{w.id}",
            data=json.dumps({"ciphertext": "ct", "iv": "iv"}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(mail.outbox), 1)
        msg = mail.outbox[0]
        self.assertEqual(msg.to, ["creator@example.com"])
        self.assertIn("submitted", msg.subject.lower())
        self.assertIn(f"/whisper/{w.id}", msg.body)
        # Email must warn about incomplete link
        self.assertIn("NOT contain the decryption key", msg.body)

    def test_no_email_on_submit_when_no_notify_email(self):
        """No email if notify_email is empty."""
        w = self._create_request(notify_email="")
        resp = self.client.post(
            f"/api/whisper/submit/{w.id}",
            data=json.dumps({"ciphertext": "ct", "iv": "iv"}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(mail.outbox), 0)

    def test_notify_email_stored_in_receive_mode(self):
        resp = self.client.post(
            "/api/whisper/request",
            data=json.dumps({
                "salt": "s",
                "notify_email": "creator@example.com",
            }),
            content_type="application/json",
        )
        wid = resp.json()["id"]
        w = Whisper.objects.get(id=wid)
        self.assertEqual(w.notify_email, "creator@example.com")

    def test_submit_email_url_does_not_contain_fragment(self):
        """The emailed URL must NOT include the decryption key (fragment)."""
        w = self._create_request(notify_email="creator@example.com")
        resp = self.client.post(
            f"/api/whisper/submit/{w.id}",
            data=json.dumps({"ciphertext": "ct", "iv": "iv"}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 200)
        msg = mail.outbox[0]
        # The URL line should not have a '#' fragment appended
        for line in msg.body.splitlines():
            if f"/whisper/{w.id}" in line:
                self.assertFalse(
                    line.strip().endswith("#") or "#" in line.split(f"/whisper/{w.id}")[1],
                    f"URL line contains a fragment: {line}",
                )


@override_settings(
    MIDDLEWARE=_BASE_MIDDLEWARE,
    REST_FRAMEWORK=_TEST_REST_FRAMEWORK,
    PSST_ENABLE_EMAIL=True,
)
class CreatePageEmailContextTests(TestCase):
    """Test that the create page passes email context correctly."""

    def test_create_page_includes_enable_email(self):
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.context["enable_email"])

    @override_settings(PSST_ENABLE_EMAIL=False)
    def test_create_page_email_disabled(self):
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(resp.context["enable_email"])
