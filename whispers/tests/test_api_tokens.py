import base64
import hashlib
import json
import secrets
import uuid
from datetime import timedelta
from unittest import mock
from urllib.parse import parse_qs, urlencode, urlsplit

from django.contrib.auth.models import User
from django.core.cache import cache
from django.core.exceptions import ImproperlyConfigured
from django.test import Client, TestCase, override_settings
from django.utils import timezone

from whispers import redis_store
from whispers.api_tokens import (
    AUTH_SCHEME,
    authenticate_token,
    delete_expired,
    extension_redirect_uris,
    hash_secret,
)
from whispers.models import ApiAuthorizationCode, ApiToken, Whisper
from whispers.tests.test_whisper import (
    _BASE_MIDDLEWARE,
    _DEFAULT_EXEMPT_URLS,
    _REVEAL_TOKEN,
    _REVEAL_TOKEN_HASH,
    _TEST_REST_FRAMEWORK,
    _patch_redis,
)

_TOKEN_MIDDLEWARE = "whispers.middleware.ApiTokenMiddleware"
_LOGIN_MIDDLEWARE = "whispers.middleware.LoginRequiredMiddleware"
_MIDDLEWARE = [m for m in _BASE_MIDDLEWARE if m != _TOKEN_MIDDLEWARE] + [
    _TOKEN_MIDDLEWARE,
    _LOGIN_MIDDLEWARE,
]
_REDIRECT_URI = "http://127.0.0.1:53682/callback"
_CHROME_REDIRECT_URI = "https://" + "abcdefghijklmnop" * 2 + ".chromiumapp.org/callback"
_FIREFOX_REDIRECT_URI = (
    "https://" + "0123456789abcdef0123" * 2 + ".extensions.allizom.org/"
)
_PASSWORD = "Local-login-password-42!"


def _pkce():
    verifier = secrets.token_urlsafe(48)
    digest = hashlib.sha256(verifier.encode()).digest()
    return verifier, base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


@override_settings(
    ENABLE_AUTH=True,
    PSST_ENABLE_API_TOKENS=True,
    PSST_ENABLE_API_TOKEN_MANUAL_CODE=False,
    PSST_API_TOKEN_TTL=3600,
    PSST_API_TOKEN_EXTENSION_REDIRECT_URIS=[],
    PSST_FORCE_AUTH_VIEW=False,
    PSST_FORCE_AUTH_SUBMIT=False,
    PSST_ENABLE_RECEIVE_ACCESS=False,
    ENABLE_LOCAL_LOGIN=True,
    MIDDLEWARE=_MIDDLEWARE,
    REST_FRAMEWORK=_TEST_REST_FRAMEWORK,
    LOGIN_URL="/login/",
    LOGIN_REQUIRED_EXEMPT_URLS=_DEFAULT_EXEMPT_URLS,
)
class ApiTokenTestCase(TestCase):
    def setUp(self):
        cache.clear()
        self.addCleanup(cache.clear)
        self.patcher, self.redis = _patch_redis()
        self.patcher.start()
        self.user = User.objects.create_user("cli-user", "cli@example.com", _PASSWORD)

    def tearDown(self):
        self.patcher.stop()
        redis_store._client = None

    def _params(self, challenge, **overrides):
        params = {
            "response_type": "code",
            "redirect_uri": _REDIRECT_URI,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": "state-123",
            "client_name": "psst CLI",
        }
        params.update(overrides)
        return {key: value for key, value in params.items() if value is not None}

    def _authorize(self, client=None, action="approve", **overrides):
        """Sign-in flow up to the redirect. Returns ``(response, verifier)``."""
        client = client or self.client
        verifier, challenge = _pkce()
        params = self._params(challenge, **overrides)
        response = client.post("/cli/authorize", {**params, "action": action})
        return response, verifier

    def _code(self, response):
        return parse_qs(urlsplit(response["Location"]).query)["code"][0]

    def _exchange(self, code, verifier, redirect_uri=_REDIRECT_URI, client=None):
        return (client or Client()).post(
            "/api/v1/cli/token",
            data=json.dumps(
                {"code": code, "code_verifier": verifier, "redirect_uri": redirect_uri}
            ),
            content_type="application/json",
        )

    def _token(self, user=None, **overrides):
        self.client.force_login(user or self.user)
        response, verifier = self._authorize(**overrides)
        self.client.logout()
        exchange = self._exchange(self._code(response), verifier)
        self.assertEqual(exchange.status_code, 200, exchange.content)
        return exchange.json()["access_token"]

    def _api(self, method, path, token, payload=None, client=None):
        client = client or Client(enforce_csrf_checks=True)
        kwargs = {"HTTP_AUTHORIZATION": f"{AUTH_SCHEME} {token}"}
        if payload is not None:
            kwargs.update(data=json.dumps(payload), content_type="application/json")
        return getattr(client, method)(path, **kwargs)

    def _create_whisper(self, token, client=None):
        return self._api(
            "post",
            "/api/v1/whisper",
            token,
            {"ciphertext": "ct", "iv": "iv", "reveal_token_hash": _REVEAL_TOKEN_HASH},
            client=client,
        )


class AuthorizeEndpointTests(ApiTokenTestCase):
    def test_disabled_feature_returns_404(self):
        self.client.force_login(self.user)
        _verifier, challenge = _pkce()
        for overrides in ({"PSST_ENABLE_API_TOKENS": False}, {"ENABLE_AUTH": False}):
            with self.subTest(overrides=overrides), self.settings(**overrides):
                response = self.client.get("/cli/authorize", self._params(challenge))
                self.assertEqual(response.status_code, 404)
                response = Client().post(
                    "/api/v1/cli/token",
                    {"code": "x", "code_verifier": "y", "redirect_uri": "z"},
                )
                self.assertEqual(response.status_code, 404)

    def test_anonymous_user_is_sent_to_login_with_the_full_request(self):
        _verifier, challenge = _pkce()
        params = self._params(challenge)
        response = self.client.get("/cli/authorize", params)
        self.assertEqual(response.status_code, 302)
        location = urlsplit(response["Location"])
        self.assertEqual(location.path, "/login/")
        next_url = urlsplit(parse_qs(location.query)["next"][0])
        self.assertEqual(next_url.path, "/cli/authorize")
        next_params = parse_qs(next_url.query)
        for name in ("redirect_uri", "code_challenge", "state", "client_name"):
            self.assertEqual(next_params[name], [params[name]])

    def test_local_login_user_can_approve(self):
        _verifier, challenge = _pkce()
        params = self._params(challenge)
        next_url = "/cli/authorize?" + urlencode(params)
        response = self.client.post(
            "/login/",
            {"username": "cli-user", "password": _PASSWORD, "next": next_url},
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, next_url)
        page = self.client.get(response.url)
        self.assertEqual(page.status_code, 200)
        response, verifier = self._authorize()
        self.assertEqual(
            self._exchange(self._code(response), verifier).status_code, 200
        )

    def test_social_login_user_can_approve(self):
        # Social accounts sign in through allauth and have no usable password; the
        # flow only depends on the browser session.
        social = User.objects.create_user(username="sso-user", email="sso@example.com")
        social.set_unusable_password()
        social.save()
        token = self._token(user=social)
        self.assertEqual(ApiToken.objects.get().user, social)
        self.assertEqual(self._create_whisper(token).status_code, 200)

    def test_approval_page_shows_client_scopes_and_redirect_host(self):
        self.client.force_login(self.user)
        _verifier, challenge = _pkce()
        response = self.client.get(
            "/cli/authorize",
            self._params(
                challenge, client_name="<b>Evil</b> CLI", scope="whisper:read"
            ),
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "&lt;b&gt;Evil&lt;/b&gt; CLI")
        self.assertNotContains(response, "<b>Evil</b>")
        self.assertContains(response, "127.0.0.1:53682")
        self.assertContains(response, "whisper:read")
        self.assertNotContains(response, "whisper:create")
        self.assertIn("no-store", response["Cache-Control"])
        self.assertEqual(response["X-Frame-Options"], "DENY")

    def test_blank_client_name_is_allowed(self):
        self.client.force_login(self.user)
        _verifier, challenge = _pkce()
        for client_name in (None, "", "   "):
            with self.subTest(client_name=client_name):
                params = self._params(challenge, client_name=client_name)
                page = self.client.get("/cli/authorize", params)
                self.assertContains(page, "An unnamed client wants to use")
                response, verifier = self._authorize(client_name=client_name)
                self.assertEqual(response.status_code, 302)
                exchange = self._exchange(self._code(response), verifier)
                self.assertEqual(exchange.status_code, 200)
        self.assertEqual(
            set(ApiToken.objects.values_list("client_name", flat=True)), {""}
        )

    def test_invalid_requests_show_an_error_page_and_never_redirect(self):
        self.client.force_login(self.user)
        _verifier, challenge = _pkce()
        cases = [
            {"redirect_uri": "https://evil.example/callback"},
            {"redirect_uri": "http://evil.example:8080/callback"},
            {"redirect_uri": "http://localhost:8080/callback"},
            {"redirect_uri": "http://127.0.0.1/callback"},
            {"redirect_uri": "http://127.0.0.1:99999/callback"},
            {"redirect_uri": "http://127.0.0.1:080/callback"},
            {"redirect_uri": "http://127.0.0.1:8080" + chr(64) + "evil.example/"},
            {"redirect_uri": "http://127.0.0.1:8080/cb?next=https://evil.example"},
            {"redirect_uri": "http://127.0.0.1:8080/cb#fragment"},
            {"redirect_uri": "https://127.0.0.1:8080/callback"},
            {"redirect_uri": "http://[::2]:8080/callback"},
            {"redirect_uri": "urn:ietf:wg:oauth:2.0:oob"},
            {"redirect_uri": None},
            {"code_challenge_method": "plain"},
            {"code_challenge_method": None},
            {"code_challenge": None},
            {"code_challenge": "too-short"},
            {"state": None},
            {"state": "has space"},
            {"scope": "whisper:read admin"},
            {"response_type": "token"},
            {"client_name": "x" * 65},
            {"redirect_uri": "http://127.0.0.1:8080/" + "a" * 234},
        ]
        for overrides in cases:
            with self.subTest(overrides=overrides):
                params = self._params(challenge, **overrides)
                for method in ("get", "post"):
                    response = getattr(self.client, method)(
                        "/cli/authorize", {**params, "action": "approve"}
                    )
                    self.assertEqual(response.status_code, 400)
                    self.assertNotIn("Location", response)
                    self.assertEqual(response["Referrer-Policy"], "no-referrer")
                    self.assertIn("no-store", response["Cache-Control"])
        self.assertFalse(ApiAuthorizationCode.objects.exists())

    def test_ipv6_loopback_and_any_port_are_accepted(self):
        self.client.force_login(self.user)
        for redirect_uri in (
            "http://[::1]:1/callback",
            "http://127.0.0.1:65535",
            "http://127.0.0.1:8080/",
        ):
            with self.subTest(redirect_uri=redirect_uri):
                response, verifier = self._authorize(redirect_uri=redirect_uri)
                self.assertEqual(response.status_code, 302)
                self.assertTrue(response["Location"].startswith(redirect_uri + "?"))
                exchange = self._exchange(self._code(response), verifier, redirect_uri)
                self.assertEqual(exchange.status_code, 200)

    def test_approval_redirects_with_hashed_single_use_code(self):
        self.client.force_login(self.user)
        response, _verifier = self._authorize()
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response["Referrer-Policy"], "no-referrer")
        self.assertIn("no-store", response["Cache-Control"])
        location = urlsplit(response["Location"])
        self.assertEqual(
            f"{location.scheme}://{location.netloc}{location.path}", _REDIRECT_URI
        )
        query = parse_qs(location.query)
        self.assertEqual(query["state"], ["state-123"])
        code = query["code"][0]
        stored = ApiAuthorizationCode.objects.get()
        self.assertEqual(stored.code_hash, hash_secret(code))
        self.assertNotIn(
            code, json.dumps(list(ApiAuthorizationCode.objects.values()), default=str)
        )
        self.assertEqual(stored.user, self.user)
        self.assertEqual(stored.redirect_uri, _REDIRECT_URI)
        self.assertEqual(stored.scopes, "whisper:create whisper:read request:manage")
        self.assertLessEqual(stored.expires_at - timezone.now(), timedelta(seconds=60))

    def test_denial_redirects_with_error_and_issues_no_code(self):
        self.client.force_login(self.user)
        response, _verifier = self._authorize(action="deny")
        self.assertEqual(response.status_code, 302)
        query = parse_qs(urlsplit(response["Location"]).query)
        self.assertEqual(query, {"error": ["access_denied"], "state": ["state-123"]})
        self.assertFalse(ApiAuthorizationCode.objects.exists())

    def test_approval_requires_csrf_token(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.user)
        response, _verifier = self._authorize(client=client)
        self.assertEqual(response.status_code, 403)
        self.assertFalse(ApiAuthorizationCode.objects.exists())

    def test_session_expired_before_approval_returns_to_login(self):
        response, _verifier = self._authorize()
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response["Location"].startswith("/login/?next="))
        self.assertFalse(ApiAuthorizationCode.objects.exists())


@override_settings(
    PSST_API_TOKEN_EXTENSION_REDIRECT_URIS=[
        _CHROME_REDIRECT_URI,
        _FIREFOX_REDIRECT_URI,
    ]
)
class ExtensionRedirectTests(ApiTokenTestCase):
    def test_allowed_extension_redirect_round_trip(self):
        self.client.force_login(self.user)
        for redirect_uri in (_CHROME_REDIRECT_URI, _FIREFOX_REDIRECT_URI):
            with self.subTest(redirect_uri=redirect_uri):
                response, verifier = self._authorize(redirect_uri=redirect_uri)
                self.assertEqual(response.status_code, 302)
                self.assertTrue(response["Location"].startswith(redirect_uri + "?"))
                exchange = self._exchange(self._code(response), verifier, redirect_uri)
                self.assertEqual(exchange.status_code, 200)
                token = exchange.json()["access_token"]
                self.assertEqual(self._create_whisper(token).status_code, 200)

    def test_approval_page_names_the_extension_host(self):
        self.client.force_login(self.user)
        _verifier, challenge = _pkce()
        response = self.client.get(
            "/cli/authorize", self._params(challenge, redirect_uri=_CHROME_REDIRECT_URI)
        )
        self.assertContains(response, urlsplit(_CHROME_REDIRECT_URI).netloc)
        self.assertContains(response, "(a browser extension)")
        self.assertNotContains(response, "(a program on this device)")

    def test_unlisted_extension_redirects_are_rejected(self):
        self.client.force_login(self.user)
        for redirect_uri in (
            "https://" + "p" * 32 + ".chromiumapp.org/callback",
            _CHROME_REDIRECT_URI + "/other",
            _CHROME_REDIRECT_URI.replace("/callback", "/"),
            _CHROME_REDIRECT_URI + "?x=1",
            _CHROME_REDIRECT_URI.replace("https://", "http://"),
            _FIREFOX_REDIRECT_URI + "callback",
        ):
            with self.subTest(redirect_uri=redirect_uri):
                response, _verifier = self._authorize(redirect_uri=redirect_uri)
                self.assertEqual(response.status_code, 400)
                self.assertNotIn("Location", response)
        with self.settings(PSST_API_TOKEN_EXTENSION_REDIRECT_URIS=[]):
            response, _verifier = self._authorize(redirect_uri=_CHROME_REDIRECT_URI)
            self.assertEqual(response.status_code, 400)
        self.assertFalse(ApiAuthorizationCode.objects.exists())

    def test_exchange_with_a_different_redirect_uri_is_rejected(self):
        self.client.force_login(self.user)
        for other in (_FIREFOX_REDIRECT_URI, _REDIRECT_URI):
            with self.subTest(other=other):
                response, verifier = self._authorize(redirect_uri=_CHROME_REDIRECT_URI)
                exchange = self._exchange(self._code(response), verifier, other)
                self.assertEqual(exchange.status_code, 400)
        self.assertFalse(ApiToken.objects.exists())

    def test_invalid_setting_entries_are_refused(self):
        self.assertEqual(
            extension_redirect_uris(),
            {_CHROME_REDIRECT_URI, _FIREFOX_REDIRECT_URI},
        )
        for entry in (
            "https://evil.example/callback",
            "https://evil.example/.chromiumapp.org/callback",
            "https://" + "a" * 32 + ".chromiumapp.org.evil.example/callback",
            "https://" + "z" * 32 + ".chromiumapp.org/callback",
            "https://" + "a" * 31 + ".chromiumapp.org/callback",
            "https://" + "g" * 40 + ".extensions.allizom.org/",
            "https://" + "a" * 32 + ".chromiumapp.org",
            "https://*.chromiumapp.org/callback",
            "http://" + "a" * 32 + ".chromiumapp.org/callback",
            _CHROME_REDIRECT_URI + "?next=https://evil.example",
            _CHROME_REDIRECT_URI + "#fragment",
            "https://" + "a" * 32 + ".chromiumapp.org/" + "a" * 250,
            _REDIRECT_URI,
        ):
            with (
                self.subTest(entry=entry),
                self.settings(
                    PSST_API_TOKEN_EXTENSION_REDIRECT_URIS=[_CHROME_REDIRECT_URI, entry]
                ),
            ):
                with self.assertRaises(ImproperlyConfigured):
                    extension_redirect_uris()

    def test_info_advertises_extension_redirect(self):
        info = Client().get("/api/v1/info").json()["auth"]
        self.assertTrue(info["extension_redirect"])
        for overrides in (
            {"PSST_API_TOKEN_EXTENSION_REDIRECT_URIS": []},
            {"PSST_ENABLE_API_TOKENS": False},
        ):
            with self.subTest(overrides=overrides), self.settings(**overrides):
                info = Client().get("/api/v1/info").json()["auth"]
                self.assertFalse(info["extension_redirect"])


class TokenEndpointTests(ApiTokenTestCase):
    def setUp(self):
        super().setUp()
        self.client.force_login(self.user)

    def test_exchange_returns_prefixed_token_stored_only_as_hash(self):
        response, verifier = self._authorize()
        exchange = self._exchange(self._code(response), verifier)
        self.assertEqual(exchange.status_code, 200)
        data = exchange.json()
        token = data["access_token"]
        self.assertRegex(token, r"^psst_[A-Za-z0-9]{40}$")
        self.assertEqual(data["token_type"], AUTH_SCHEME)
        self.assertEqual(data["scope"], "whisper:create whisper:read request:manage")
        self.assertTrue(0 < data["expires_in"] <= 3600)
        self.assertIn("no-store", exchange["Cache-Control"])
        stored = ApiToken.objects.get()
        self.assertEqual(stored.token_hash, hash_secret(token))
        self.assertEqual(stored.client_name, "psst CLI")
        self.assertNotIn(
            token, json.dumps(list(ApiToken.objects.values()), default=str)
        )

    def test_form_encoded_exchange_is_accepted(self):
        response, verifier = self._authorize()
        exchange = Client().post(
            "/api/v1/cli/token",
            urlencode(
                {
                    "grant_type": "authorization_code",
                    "code": self._code(response),
                    "code_verifier": verifier,
                    "redirect_uri": _REDIRECT_URI,
                }
            ),
            content_type="application/x-www-form-urlencoded",
        )
        self.assertEqual(exchange.status_code, 200)

    def test_pkce_mismatch_is_rejected_and_consumes_the_code(self):
        response, verifier = self._authorize()
        code = self._code(response)
        other_verifier, _challenge = _pkce()
        self.assertEqual(self._exchange(code, other_verifier).status_code, 400)
        self.assertEqual(self._exchange(code, verifier).status_code, 400)
        self.assertFalse(ApiToken.objects.exists())

    def test_invalid_verifier_format_is_rejected_and_consumes_the_code(self):
        response, verifier = self._authorize()
        code = self._code(response)
        exchange = self._exchange(code, "short")
        self.assertEqual(exchange.status_code, 400)
        self.assertIn("code verifier", exchange.content.decode())
        self.assertEqual(self._exchange(code, verifier).status_code, 400)
        self.assertFalse(ApiToken.objects.exists())

    def test_reused_code_with_invalid_verifier_revokes_the_issued_token(self):
        response, verifier = self._authorize()
        code = self._code(response)
        token = self._exchange(code, verifier).json()["access_token"]
        self.assertEqual(self._exchange(code, "short").status_code, 400)
        self.assertFalse(ApiToken.objects.exists())
        self.assertEqual(self._create_whisper(token).status_code, 401)

    def test_redirect_uri_must_match_exactly(self):
        for redirect_uri in (
            "http://127.0.0.1:53683/callback",
            "http://127.0.0.1:53682/callback/",
            "http://[::1]:53682/callback",
        ):
            with self.subTest(redirect_uri=redirect_uri):
                response, verifier = self._authorize()
                exchange = self._exchange(self._code(response), verifier, redirect_uri)
                self.assertEqual(exchange.status_code, 400)
        self.assertFalse(ApiToken.objects.exists())

    def test_reused_code_revokes_the_issued_token(self):
        response, verifier = self._authorize()
        code = self._code(response)
        token = self._exchange(code, verifier).json()["access_token"]
        self.assertEqual(self._create_whisper(token).status_code, 200)
        self.assertEqual(self._exchange(code, verifier).status_code, 400)
        self.assertFalse(ApiToken.objects.exists())
        self.assertEqual(self._create_whisper(token).status_code, 401)

    def test_expired_code_is_rejected(self):
        response, verifier = self._authorize()
        ApiAuthorizationCode.objects.update(expires_at=timezone.now())
        self.assertEqual(
            self._exchange(self._code(response), verifier).status_code, 400
        )
        self.assertFalse(ApiToken.objects.exists())

    def test_unknown_code_is_rejected(self):
        verifier, _challenge = _pkce()
        self.assertEqual(self._exchange("psstc_unknown", verifier).status_code, 400)
        self.assertEqual(self._exchange("other", verifier).status_code, 400)

    def test_inactive_user_cannot_exchange(self):
        response, verifier = self._authorize()
        User.objects.filter(pk=self.user.pk).update(is_active=False)
        self.assertEqual(
            self._exchange(self._code(response), verifier).status_code, 400
        )

    @override_settings(
        REST_FRAMEWORK={
            **_TEST_REST_FRAMEWORK,
            "DEFAULT_THROTTLE_RATES": {
                **_TEST_REST_FRAMEWORK["DEFAULT_THROTTLE_RATES"],
                "api_token_exchange": "2/minute",
            },
        }
    )
    def test_exchange_is_rate_limited(self):
        verifier, _challenge = _pkce()
        statuses = [self._exchange("psstc_x", verifier).status_code for _ in range(3)]
        self.assertEqual(statuses, [400, 400, 429])


class TokenAuthenticationTests(ApiTokenTestCase):
    def test_token_authenticates_api_requests_without_csrf(self):
        token = self._token()
        response = self._create_whisper(token)
        self.assertEqual(response.status_code, 200, response.content)
        self.assertIsNotNone(ApiToken.objects.get().last_used_at)

    def test_last_used_update_is_skipped_after_a_concurrent_write(self):
        raw_token = self._token()
        stale = timezone.now() - timedelta(hours=1)
        concurrent = timezone.now() - timedelta(seconds=5)
        ApiToken.objects.update(last_used_at=stale)

        def write_concurrently():
            ApiToken.objects.update(last_used_at=concurrent)
            return False

        with mock.patch.object(
            ApiToken, "is_expired", new_callable=mock.PropertyMock
        ) as is_expired:
            is_expired.side_effect = write_concurrently
            token = authenticate_token(raw_token)
        self.assertEqual(token.last_used_at, stale)
        self.assertEqual(ApiToken.objects.get().last_used_at, concurrent)

    def test_session_requests_still_need_csrf(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.user)
        response = client.post(
            "/api/v1/whisper",
            data=json.dumps(
                {
                    "ciphertext": "ct",
                    "iv": "iv",
                    "reveal_token_hash": _REVEAL_TOKEN_HASH,
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 403)

    def test_missing_auth_returns_json_401_instead_of_login_redirect(self):
        response = Client().post(
            "/api/v1/whisper", data="{}", content_type="application/json"
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response["WWW-Authenticate"], AUTH_SCHEME)
        self.assertIn("error", response.json())

    def test_invalid_token_returns_json_401(self):
        self._token()
        for token in ("psst_not-a-real-token", "garbage", ""):
            with self.subTest(token=token):
                response = self._create_whisper(token)
                self.assertEqual(response.status_code, 401)
                self.assertIn('error="invalid_token"', response["WWW-Authenticate"])
                self.assertIn("error", response.json())

    def test_token_is_ignored_outside_the_versioned_api(self):
        token = self._token()
        response = Client().get("/", HTTP_AUTHORIZATION=f"{AUTH_SCHEME} {token}")
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response["Location"].startswith("/login/"))

    def test_expired_token_is_rejected(self):
        token = self._token()
        ApiToken.objects.update(expires_at=timezone.now())
        self.assertEqual(self._create_whisper(token).status_code, 401)

    def test_inactive_user_token_is_rejected(self):
        token = self._token()
        User.objects.filter(pk=self.user.pk).update(is_active=False)
        self.assertEqual(self._create_whisper(token).status_code, 401)

    def test_token_disabled_feature_falls_back_to_login_requirement(self):
        token = self._token()
        with self.settings(PSST_ENABLE_API_TOKENS=False):
            self.assertEqual(self._create_whisper(token).status_code, 401)
            self.assertFalse(
                self._api("get", "/api/v1/info", token).json()["auth"]["loopback_pkce"]
            )

    def test_scopes_limit_endpoints(self):
        token = self._token(scope="whisper:read")
        self.assertEqual(self._create_whisper(token).status_code, 403)
        response = self._api("post", "/api/v1/whisper/request", token, {})
        self.assertEqual(response.status_code, 403)
        whisper_id = self._create_whisper(self._token()).json()["id"]
        response = self._api(
            "post",
            f"/api/v1/whisper/{whisper_id}/reveal",
            token,
            {"reveal_token": _REVEAL_TOKEN},
        )
        self.assertEqual(response.status_code, 200)

    @override_settings(PSST_ENABLE_RECEIVE_HISTORY=True)
    def test_status_endpoint_requires_read_scope(self):
        whisper_id = self._api(
            "post",
            "/api/v1/whisper/request",
            self._token(),
            {"public_key": "pk", "reveal_token_hash": _REVEAL_TOKEN_HASH},
        ).json()["id"]
        path = f"/api/v1/whisper/{whisper_id}/status"
        response = self._api("get", path, self._token(scope="whisper:create"))
        self.assertEqual(response.status_code, 403)
        response = self._api("get", path, self._token(scope="whisper:read"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "pending")

    @override_settings(
        PSST_FORCE_AUTH_VIEW=True,
        PSST_FORCE_AUTH_SUBMIT=True,
        LOGIN_REQUIRED_EXEMPT_URLS=[r"login/", r"accounts/.*", r"static/.*"],
    )
    def test_forced_auth_settings_see_the_token_user(self):
        token = self._token()
        whisper_id = self._create_whisper(token).json()["id"]
        self.assertTrue(Whisper.objects.get(id=whisper_id).require_auth_view)
        reveal_path = f"/api/v1/whisper/{whisper_id}/reveal"
        response = Client().post(
            reveal_path,
            data=json.dumps({"reveal_token": _REVEAL_TOKEN}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 401)
        response = self._api(
            "post", reveal_path, token, {"reveal_token": _REVEAL_TOKEN}
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["ciphertext"], "ct")
        response = self._api("get", f"/api/v1/whisper/submit/{uuid.uuid4()}", token)
        self.assertEqual(response.status_code, 404)

    @override_settings(
        REST_FRAMEWORK={
            **_TEST_REST_FRAMEWORK,
            "DEFAULT_THROTTLE_RATES": {
                **_TEST_REST_FRAMEWORK["DEFAULT_THROTTLE_RATES"],
                "api_token_user": "2/minute",
            },
        }
    )
    def test_token_requests_are_throttled_per_user(self):
        token = self._token()
        statuses = [self._create_whisper(token).status_code for _ in range(3)]
        self.assertEqual(statuses, [200, 200, 429])
        other = User.objects.create_user(username="other")
        self.assertEqual(self._create_whisper(self._token(user=other)).status_code, 200)

    def test_info_advertises_token_sign_in(self):
        response = Client().get("/api/v1/info")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json()["auth"],
            {
                "login_required": True,
                "loopback_pkce": True,
                "manual_code": False,
                "extension_redirect": False,
                "scopes": ["whisper:create", "whisper:read", "request:manage"],
            },
        )
        with self.settings(PSST_ENABLE_API_TOKEN_MANUAL_CODE=True):
            self.assertTrue(Client().get("/api/v1/info").json()["auth"]["manual_code"])


class TokenRevocationTests(ApiTokenTestCase):
    def test_logout_endpoint_revokes_the_presented_token(self):
        token = self._token()
        other = self._token()
        response = self._api("post", "/api/v1/cli/revoke", token)
        self.assertEqual(response.status_code, 204)
        self.assertEqual(self._create_whisper(token).status_code, 401)
        self.assertEqual(self._create_whisper(other).status_code, 200)
        self.assertEqual(
            self._api("post", "/api/v1/cli/revoke", token).status_code, 401
        )

    def test_logout_endpoint_without_token_is_rejected(self):
        self.assertEqual(Client().post("/api/v1/cli/revoke").status_code, 401)
        self.client.force_login(self.user)
        self.assertEqual(self.client.post("/api/v1/cli/revoke").status_code, 401)

    def test_user_can_list_and_revoke_own_tokens(self):
        token = self._token()
        other_user = User.objects.create_user(username="other")
        self._token(user=other_user, client_name="Other CLI")
        mine = ApiToken.objects.get(user=self.user)
        theirs = ApiToken.objects.get(user=other_user)

        self.client.force_login(self.user)
        page = self.client.get("/cli/tokens")
        self.assertEqual(page.status_code, 200)
        self.assertContains(page, "psst CLI")
        self.assertNotContains(page, "Other CLI")
        self.assertNotContains(page, token)

        response = self.client.post(f"/cli/tokens/{theirs.pk}/revoke")
        self.assertEqual(response.status_code, 302)
        self.assertTrue(ApiToken.objects.filter(pk=theirs.pk).exists())
        self.client.post(f"/cli/tokens/{mine.pk}/revoke")
        self.assertFalse(ApiToken.objects.filter(pk=mine.pk).exists())
        self.assertEqual(self._create_whisper(token).status_code, 401)
        self.assertContains(self.client.get("/cli/tokens"), "data-no-api-tokens")

    def test_token_page_requires_login_and_feature(self):
        response = Client().get("/cli/tokens")
        self.assertEqual(response.status_code, 302)
        self.client.force_login(self.user)
        with self.settings(PSST_ENABLE_API_TOKENS=False):
            self.assertEqual(self.client.get("/cli/tokens").status_code, 404)
            self.assertNotContains(self.client.get("/about"), 'href="/cli/tokens"')
        self.assertContains(self.client.get("/about"), 'href="/cli/tokens"')

    def test_admin_lists_tokens_without_hashes(self):
        self._token()
        admin = User.objects.create_superuser("admin", "admin@example.com", "pw")
        self.client.force_login(admin)
        response = self.client.get("/admin/whispers/apitoken/")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "psst CLI")
        token = ApiToken.objects.get()
        detail = self.client.get(f"/admin/whispers/apitoken/{token.pk}/change/")
        self.assertEqual(detail.status_code, 200)
        self.assertNotContains(detail, token.token_hash)

    def test_cleanup_deletes_expired_tokens_and_stale_codes(self):
        self._token()
        self._token()
        ApiToken.objects.filter(pk=ApiToken.objects.first().pk).update(
            expires_at=timezone.now()
        )
        ApiAuthorizationCode.objects.update(
            expires_at=timezone.now() - timedelta(hours=2)
        )
        self.assertEqual(delete_expired(), 1)
        self.assertEqual(ApiToken.objects.count(), 1)
        remaining = ApiAuthorizationCode.objects.get()
        self.assertEqual(remaining.token, ApiToken.objects.get())

    def test_replay_after_cleanup_still_revokes_the_token(self):
        self.client.force_login(self.user)
        response, verifier = self._authorize()
        code = self._code(response)
        token = self._exchange(code, verifier).json()["access_token"]
        ApiAuthorizationCode.objects.update(
            expires_at=timezone.now() - timedelta(days=1)
        )
        self.assertEqual(delete_expired(), 0)
        self.assertEqual(self._exchange(code, verifier).status_code, 400)
        self.assertFalse(ApiToken.objects.exists())
        self.assertEqual(self._create_whisper(token).status_code, 401)
        delete_expired()
        self.assertFalse(ApiAuthorizationCode.objects.exists())


class ManualCodeTests(ApiTokenTestCase):
    _OOB = "urn:ietf:wg:oauth:2.0:oob"

    @override_settings(PSST_ENABLE_API_TOKEN_MANUAL_CODE=True)
    def test_manual_code_is_shown_and_exchanged_with_pkce(self):
        self.client.force_login(self.user)
        verifier, challenge = _pkce()
        params = self._params(challenge, redirect_uri=self._OOB)
        page = self.client.get("/cli/authorize", params)
        self.assertEqual(page.status_code, 200)
        self.assertNotContains(page, "data-redirect-host")
        response = self.client.post("/cli/authorize", {**params, "action": "approve"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Referrer-Policy"], "no-referrer")
        self.assertIn("no-store", response["Cache-Control"])
        code = response.context["code"]
        self.assertContains(response, code)
        wrong, _challenge = _pkce()
        self.assertEqual(self._exchange(code, wrong, self._OOB).status_code, 400)

        response = self.client.post("/cli/authorize", {**params, "action": "approve"})
        code = response.context["code"]
        self.assertEqual(self._exchange(code, verifier, self._OOB).status_code, 200)

    @override_settings(PSST_ENABLE_API_TOKEN_MANUAL_CODE=True)
    def test_manual_denial_shows_a_page(self):
        self.client.force_login(self.user)
        _verifier, challenge = _pkce()
        params = self._params(challenge, redirect_uri=self._OOB)
        response = self.client.post("/cli/authorize", {**params, "action": "deny"})
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("Location", response)
        self.assertFalse(ApiAuthorizationCode.objects.exists())

    def test_manual_code_is_off_by_default(self):
        self.client.force_login(self.user)
        _verifier, challenge = _pkce()
        params = self._params(challenge, redirect_uri=self._OOB)
        self.assertEqual(self.client.get("/cli/authorize", params).status_code, 400)
