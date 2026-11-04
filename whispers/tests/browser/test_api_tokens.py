import base64
import hashlib
import json
import secrets
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlencode, urlsplit

import pytest
from playwright.sync_api import expect

from whispers.api_tokens import AUTH_SCHEME
from whispers.tests.test_whisper import _REVEAL_TOKEN_HASH

pytestmark = [
    pytest.mark.browser,
    pytest.mark.browser_settings(
        ENABLE_AUTH=True, ENABLE_LOCAL_LOGIN=True, PSST_ENABLE_API_TOKENS=True
    ),
]


@pytest.fixture
def loopback():
    """A stand-in for the CLI's temporary callback listener on 127.0.0.1."""
    received = {}
    done = threading.Event()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            received.update(parse_qs(urlsplit(self.path).query))
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Signed in. You can close this tab.")
            done.set()

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/callback", received, done
    finally:
        server.shutdown()
        server.server_close()


def _pkce():
    verifier = secrets.token_urlsafe(48)
    digest = hashlib.sha256(verifier.encode()).digest()
    return verifier, base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def _api(url, payload=None, token=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"{AUTH_SCHEME} {token}"
    data = json.dumps(payload).encode() if payload is not None else None
    request = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=10) as response:  # nosec B310
            body = response.read()
            return response.status, json.loads(body) if body else None
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read() or b"null")


def _start_sign_in(page, app_url, redirect_uri, user=None):
    verifier, challenge = _pkce()
    params = {
        "redirect_uri": redirect_uri,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": "browser-state",
        "client_name": "psst CLI",
    }
    page.goto(app_url + "/cli/authorize?" + urlencode(params))
    if user is not None:
        page.locator("#username").fill(user.username)
        page.locator("#password").fill("Browser-login-password-42!")
        page.get_by_role("button", name="Sign in", exact=True).click()
    expect(page.get_by_role("heading", name="Approve sign-in")).to_be_visible()
    expect(page.locator("[data-client-name]")).to_have_text("psst CLI")
    expect(page.locator("[data-redirect-host]")).to_have_text(
        urlsplit(redirect_uri).netloc
    )
    return verifier


def test_loopback_sign_in_issues_token_that_can_be_revoked(
    page, app_url, verified_user, loopback
):
    redirect_uri, received, done = loopback
    user = verified_user()
    verifier = _start_sign_in(page, app_url, redirect_uri, user)
    page.get_by_role("button", name="Approve", exact=True).click()
    assert done.wait(10)
    expect(page.get_by_text("Signed in. You can close this tab.")).to_be_visible()
    assert received["state"] == ["browser-state"]

    exchange = {
        "code": received["code"][0],
        "code_verifier": verifier,
        "redirect_uri": redirect_uri,
    }
    status, body = _api(app_url + "/api/v1/cli/token", exchange)
    assert status == 200
    token = body["access_token"]
    assert token.startswith("psst_")
    whisper = {"ciphertext": "ct", "iv": "iv", "reveal_token_hash": _REVEAL_TOKEN_HASH}
    assert _api(app_url + "/api/v1/whisper", whisper, token)[0] == 200
    assert _api(app_url + "/api/v1/cli/token", exchange)[0] == 400

    status, _body = _api(app_url + "/api/v1/whisper", whisper, token)
    assert status == 401

    verifier = _start_sign_in(page, app_url, redirect_uri)
    done.clear()
    page.get_by_role("button", name="Approve", exact=True).click()
    assert done.wait(10)
    exchange.update(code=received["code"][0], code_verifier=verifier)
    token = _api(app_url + "/api/v1/cli/token", exchange)[1]["access_token"]

    page.goto(app_url + "/cli/tokens")
    tokens = page.locator("[data-api-token]")
    expect(tokens).to_have_count(1)
    expect(tokens.first).to_contain_text("psst CLI")
    tokens.first.get_by_role("button", name="Revoke", exact=True).click()
    expect(page.locator("[data-no-api-tokens]")).to_be_visible()
    assert _api(app_url + "/api/v1/whisper", whisper, token)[0] == 401


def test_denied_sign_in_reports_access_denied(page, app_url, verified_user, loopback):
    redirect_uri, received, done = loopback
    _start_sign_in(page, app_url, redirect_uri, verified_user())
    page.get_by_role("button", name="Deny", exact=True).click()
    assert done.wait(10)
    assert received == {"error": ["access_denied"], "state": ["browser-state"]}


def test_non_loopback_redirect_shows_error_without_redirecting(
    page, app_url, verified_user
):
    user = verified_user()
    _verifier, challenge = _pkce()
    params = {
        "redirect_uri": "https://example.com/callback",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": "browser-state",
    }
    page.goto(app_url + "/login/")
    page.locator("#username").fill(user.username)
    page.locator("#password").fill("Browser-login-password-42!")
    page.get_by_role("button", name="Sign in", exact=True).click()
    response = page.goto(app_url + "/cli/authorize?" + urlencode(params))
    assert response.status == 400
    assert response.headers["referrer-policy"] == "no-referrer"
    expect(page).to_have_url(app_url + "/cli/authorize?" + urlencode(params))
    expect(page.locator("[data-cli-error]")).to_contain_text("loopback")
