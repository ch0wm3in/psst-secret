import base64
import email
import email.policy
import json
import uuid
import warnings
from datetime import timedelta
from unittest.mock import patch

import fakeredis
from django.conf import settings
from django.core import mail
from django.test import TestCase, override_settings
from django.utils import timezone

from whispers import redis_store
from whispers.email import send_whisper_created_email, send_whisper_submitted_email
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
        "whisper_view": "10000/minute",
        "receive_access": "10000/minute",
    },
}

_TEST_MAILERS = {
    "default": {"BACKEND": "django.core.mail.backends.locmem.EmailBackend"}
}

_PNG_BYTES = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR-test-logo"


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
    MAILERS=_TEST_MAILERS,
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
        resp = self._post(
            {
                "ciphertext": "ct",
                "iv": "iv",
                "notify_email": "recipient@example.com",
            }
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(mail.outbox), 1)
        msg = mail.outbox[0]
        self.assertEqual(msg.to, ["recipient@example.com"])
        self.assertIn("whisper", msg.subject.lower())
        self.assertIn("/whisper/", msg.body)
        # Email must warn about incomplete link
        self.assertIn("NOT contain the decryption key", msg.body)

    def test_no_email_when_notify_email_empty(self):
        resp = self._post(
            {
                "ciphertext": "ct",
                "iv": "iv",
                "notify_email": "",
            }
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(mail.outbox), 0)

    def test_no_email_when_notify_email_absent(self):
        resp = self._post(
            {
                "ciphertext": "ct",
                "iv": "iv",
            }
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(mail.outbox), 0)

    def test_invalid_notify_email_rejected(self):
        resp = self._post(
            {
                "ciphertext": "ct",
                "iv": "iv",
                "notify_email": "not-an-email",
            }
        )
        self.assertEqual(resp.status_code, 400)

    def test_notify_email_stored_in_model(self):
        resp = self._post(
            {
                "ciphertext": "ct",
                "iv": "iv",
                "notify_email": "user@example.com",
            }
        )
        wid = resp.json()["id"]
        w = Whisper.objects.get(id=wid)
        self.assertEqual(w.notify_email, "user@example.com")

    def test_email_url_does_not_contain_fragment(self):
        """The emailed URL must NOT include the decryption key (fragment)."""
        resp = self._post(
            {
                "ciphertext": "ct",
                "iv": "iv",
                "notify_email": "recipient@example.com",
            }
        )
        self.assertEqual(resp.status_code, 200)
        msg = mail.outbox[0]
        wid = resp.json()["id"]
        # The whisper URL should appear in the email
        self.assertIn(f"/whisper/{wid}", msg.body)
        # The URL line should not have a '#' fragment appended
        for line in msg.body.splitlines():
            if f"/whisper/{wid}" in line:
                self.assertFalse(
                    line.strip().endswith("#")
                    or "#" in line.split(f"/whisper/{wid}")[1],
                    f"URL line contains a fragment: {line}",
                )


@override_settings(
    MIDDLEWARE=_BASE_MIDDLEWARE,
    REST_FRAMEWORK=_TEST_REST_FRAMEWORK,
    MAILERS=_TEST_MAILERS,
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
            data=json.dumps(
                {
                    "ciphertext": "ct",
                    "iv": "iv",
                    "notify_email": "recipient@example.com",
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(mail.outbox), 0)


@override_settings(
    MIDDLEWARE=_BASE_MIDDLEWARE,
    REST_FRAMEWORK=_TEST_REST_FRAMEWORK,
    MAILERS=_TEST_MAILERS,
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
            "submit_token": uuid.uuid4(),
            "expiry_option": "1d",
            "expires_at": timezone.now() + timedelta(days=1),
        }
        defaults.update(kwargs)
        w = Whisper.objects.create(**defaults)
        redis_store.store_crypto(w.id, 86400)
        return w

    def _submit(self, w):
        return self.client.post(
            f"/api/whisper/submit/{w.submit_token}",
            data=json.dumps({"ciphertext": "ct", "iv": "iv", "encapsulated_key": "e"}),
            content_type="application/json",
        )

    def test_email_sent_on_create_request_with_notify_email(self):
        """Creating a receive request should NOT immediately send email."""
        resp = self.client.post(
            "/api/whisper/request",
            data=json.dumps(
                {"public_key": "pk", "notify_email": "creator@example.com"}
            ),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 200)
        # Email is only sent when someone submits, not on creation
        self.assertEqual(len(mail.outbox), 0)

    def test_email_sent_on_submit(self):
        """Submitting to a receive request should notify the creator."""
        w = self._create_request(notify_email="creator@example.com")
        resp = self._submit(w)
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
        resp = self._submit(w)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(mail.outbox), 0)

    def test_notify_email_stored_in_receive_mode(self):
        resp = self.client.post(
            "/api/whisper/request",
            data=json.dumps(
                {"public_key": "pk", "notify_email": "creator@example.com"}
            ),
            content_type="application/json",
        )
        wid = resp.json()["id"]
        w = Whisper.objects.get(id=wid)
        self.assertEqual(w.notify_email, "creator@example.com")

    def test_submit_email_url_does_not_contain_fragment(self):
        """The emailed URL must NOT include the decryption key (fragment)."""
        w = self._create_request(notify_email="creator@example.com")
        resp = self._submit(w)
        self.assertEqual(resp.status_code, 200)
        msg = mail.outbox[0]
        # The URL line should not have a '#' fragment appended
        for line in msg.body.splitlines():
            if f"/whisper/{w.id}" in line:
                self.assertFalse(
                    line.strip().endswith("#")
                    or "#" in line.split(f"/whisper/{w.id}")[1],
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


@override_settings(
    MAILERS=_TEST_MAILERS,
    PSST_ENABLE_EMAIL=True,
    DEFAULT_FROM_EMAIL="test@example.com",
)
class EmailBrandingTests(TestCase):
    """Test that notification emails respect white-label settings."""

    def _html(self, msg):
        return msg.alternatives[0][0]

    def test_default_branding(self):
        send_whisper_created_email("r@example.com", "https://x.example/whisper/1")
        msg = mail.outbox[0]
        self.assertIn("via psst-secret!", msg.body)
        self.assertIn("psst-secret</h1>", self._html(msg))
        self.assertNotIn("🤫", self._html(msg))
        self.assertIn("Sent by psst-secret", self._html(msg))

    @override_settings(
        PSST_BRAND_NAME="Acme & Co",
        PSST_BRAND_LOGO_URL="https://cdn.example.com/logo.png",
    )
    def test_custom_name_and_absolute_logo(self):
        send_whisper_created_email("r@example.com", "https://x.example/whisper/1")
        send_whisper_submitted_email("r@example.com", "https://x.example/whisper/2")
        self.assertIn("via Acme & Co!", mail.outbox[0].body)
        for msg in mail.outbox:
            html = self._html(msg)
            self.assertIn('src="https://cdn.example.com/logo.png"', html)
            self.assertIn("Sent by Acme &amp; Co", html)
            self.assertNotIn("psst-secret", html)
            self.assertNotIn("🤫", html)

    @override_settings(PSST_BRAND_NAME="Acme", PSST_BRAND_LOGO_URL="/static/logo.png")
    def test_relative_logo_omitted_from_email(self):
        send_whisper_submitted_email("r@example.com", "https://x.example/whisper/2")
        html = self._html(mail.outbox[0])
        self.assertNotIn("<img", html)
        self.assertNotIn("🤫", html)
        self.assertIn("Sent by Acme", html)

    def _logo_parts(self, msg):
        parsed = email.message_from_bytes(
            msg.message().as_bytes(), policy=email.policy.default
        )
        return parsed, [
            part
            for part in parsed.walk()
            if part.get("Content-ID") == "<brand-logo@psst-secret>"
        ]

    @override_settings(
        PSST_BRAND_NAME="Acme",
        PSST_BRAND_LOGO_URL="data:image/png;base64,"
        + base64.b64encode(_PNG_BYTES).decode(),
    )
    def test_data_logo_attached_inline_with_cid(self):
        send_whisper_created_email("r@example.com", "https://x.example/whisper/1")
        send_whisper_submitted_email("r@example.com", "https://x.example/whisper/2")
        self.assertEqual(len(mail.outbox), 2)
        for msg in mail.outbox:
            html = self._html(msg)
            self.assertIn('src="cid:brand-logo@psst-secret"', html)
            self.assertNotIn("data:image", html)
            self.assertNotIn("🤫", html)
            self.assertEqual(msg.attachments, [])
            parsed, logos = self._logo_parts(msg)
            self.assertEqual(
                [part.get_content_type() for part in parsed.walk()],
                [
                    "multipart/alternative",
                    "text/plain",
                    "multipart/related",
                    "text/html",
                    "image/png",
                ],
            )
            self.assertEqual(len(logos), 1)
            self.assertEqual(logos[0].get_content_disposition(), "inline")
            self.assertEqual(logos[0].get_filename(), "logo.png")
            self.assertEqual(logos[0].get_content(), _PNG_BYTES)

    @override_settings(
        PSST_BRAND_LOGO_URL="data:image/svg+xml,%3Csvg%20xmlns%3D%22x%22%2F%3E"
    )
    def test_percent_encoded_data_logo(self):
        send_whisper_created_email("r@example.com", "https://x.example/whisper/1")
        _, (logo,) = self._logo_parts(mail.outbox[0])
        self.assertEqual(logo.get_content_type(), "image/svg+xml")
        self.assertEqual(logo.get_filename(), "logo.svg")
        self.assertEqual(logo.get_content(), b'<svg xmlns="x"/>')

    @override_settings(
        PSST_BRAND_NAME="Acme", PSST_BRAND_LOGO_URL="data:image/png;base64,***"
    )
    def test_invalid_data_logo_omitted(self):
        send_whisper_created_email("r@example.com", "https://x.example/whisper/1")
        msg = mail.outbox[0]
        self.assertEqual(self._logo_parts(msg)[1], [])
        self.assertNotIn("<img", self._html(msg))
        self.assertNotIn("🤫", self._html(msg))


@override_settings(
    MAILERS={
        "default": {"BACKEND": "django_better_azure_communication_email.EmailBackend"}
    },
    PSST_ENABLE_EMAIL=True,
    DEFAULT_FROM_EMAIL="test@example.com",
    PSST_BRAND_LOGO_URL="data:image/png;base64,"
    + base64.b64encode(_PNG_BYTES).decode(),
)
class AzureEmailLogoTests(TestCase):
    """The Azure backend needs legacy MIME parts and a bare contentId."""

    def test_data_logo_converted_to_azure_inline_attachment(self):
        from django_better_azure_communication_email.backend import ACEmailBackend

        from whispers.email import _build_message

        with warnings.catch_warnings():
            # Fail on Django's MIMEBase deprecation warning.
            warnings.simplefilter("error")
            msg = _build_message(
                "r@example.com",
                "Subject",
                "whisper_created",
                {"whisper_url": "https://x.example/whisper/1"},
            )
        self.assertIn('src="cid:brand-logo@psst-secret"', msg.alternatives[0][0])
        payload = ACEmailBackend().convert_message(msg)
        self.assertEqual(
            payload["attachments"],
            [
                {
                    "name": "logo.png",
                    "contentType": "image/png",
                    "contentInBase64": base64.b64encode(_PNG_BYTES).decode(),
                    "contentId": "brand-logo@psst-secret",
                }
            ],
        )
