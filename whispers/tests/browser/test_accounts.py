import pytest
from django.conf import settings as django_settings
from playwright.sync_api import expect

from whispers import redis_store
from whispers.models import Whisper
from whispers.tests.browser.test_flows import _reveal, _submit

pytestmark = [
    pytest.mark.browser,
    pytest.mark.browser_settings(ENABLE_AUTH=True, ENABLE_LOCAL_LOGIN=True),
]


@pytest.mark.browser_settings(
    ENABLE_AUTH=True, ENABLE_LOCAL_LOGIN=True, MIDDLEWARE=django_settings.MIDDLEWARE
)
def test_login_required_invalid_credentials_and_logout(page, app_url, verified_user):
    user = verified_user()
    page.goto(app_url)
    expect(page.locator("#username")).to_be_visible()
    page.locator("#username").fill(user.username)
    page.locator("#password").fill("wrong-password")
    page.get_by_role("button", name="Sign in", exact=True).click()
    expect(page.get_by_text("Invalid username or password.")).to_be_visible()
    page.locator("#username").fill(user.username)
    page.locator("#password").fill("Browser-login-password-42!")
    page.get_by_role("button", name="Sign in", exact=True).click()
    expect(page.locator("#whisper")).to_be_visible()
    page.get_by_title(user.username, exact=True).click()
    page.get_by_role("button", name="Sign out", exact=True).click()
    page.goto(app_url)
    expect(page.locator("#username")).to_be_visible()


def test_login_rejects_external_next_url(page, app_url, verified_user):
    user = verified_user()
    page.goto(app_url + "/login/?next=https://example.com/steal")
    page.locator("#username").fill(user.username)
    page.locator("#password").fill("Browser-login-password-42!")
    page.get_by_role("button", name="Sign in", exact=True).click()
    expect(page).to_have_url(app_url + "/")


@pytest.mark.browser_settings(
    ENABLE_AUTH=True, ENABLE_LOCAL_LOGIN=False, SOCIAL_AUTH_PROVIDERS=[]
)
def test_local_login_can_be_disabled(page, app_url):
    page.goto(app_url + "/login/")
    expect(page.locator("#username")).to_have_count(0)
    expect(page.get_by_text("No sign-in methods configured.")).to_be_visible()


@pytest.mark.parametrize("forced", [False, True])
def test_authentication_required_to_reveal(
    page, create_whisper, verified_user, sign_in, settings, forced
):
    user = verified_user()
    settings.PSST_FORCE_AUTH_VIEW = forced
    url = create_whisper(**({} if forced else {"require_auth_view": True}))
    page.context.clear_cookies()
    page.goto(url)
    expect(page.locator("#username")).to_be_visible()
    assert redis_store.get_view_count(Whisper.objects.get().id) == 0
    sign_in(user)
    _reveal(page, url)
    expect(page.locator("#decrypted-content")).to_be_visible()


@pytest.mark.parametrize("forced", [False, True])
def test_authentication_required_to_submit(
    page, create_whisper, verified_user, sign_in, settings, forced
):
    user = verified_user()
    settings.PSST_FORCE_AUTH_SUBMIT = forced
    submit_url, view_url = create_whisper(
        kind="receive", **({} if forced else {"require_auth_submit": True})
    )
    page.context.clear_cookies()
    page.goto(submit_url)
    expect(page.locator("#username")).to_be_visible()
    stored = redis_store.get_crypto(Whisper.objects.get().id)
    assert stored is not None
    assert not stored["ciphertext"]
    sign_in(user)
    _submit(page, submit_url)
    _reveal(page, view_url)
    expect(page.locator("#decrypted-content")).to_be_visible()


@pytest.mark.browser_settings(
    ENABLE_AUTH=True, ENABLE_LOCAL_LOGIN=True, PSST_ENABLE_RECEIVE_ACCESS=True
)
def test_approved_readers_and_revocation(page, create_whisper, verified_user, sign_in):
    creator = verified_user("creator")
    reader = verified_user("approved-reader")
    stranger = verified_user("stranger")
    sign_in(creator)
    submit_url, view_url = create_whisper(
        kind="receive",
        max_views=0,
        creator_only=True,
        allowed_reader_emails=reader.email,
    )
    whisper = Whisper.objects.get()
    assert whisper.creator == creator
    assert list(whisper.allowed_readers.all()) == [reader]
    page.context.clear_cookies()
    page.goto(view_url)
    expect(page.locator("#username")).to_be_visible()
    _submit(page, submit_url)
    sign_in(stranger)
    response = page.goto(view_url)
    assert response.status == 403
    expect(page.locator("#receive-access-form")).to_have_count(0)
    assert redis_store.get_view_count(whisper.id) == 0
    page.context.clear_cookies()
    sign_in(reader)
    _reveal(page, view_url)
    expect(page.locator("#decrypted-content")).to_be_visible()
    expect(page.locator("#receive-access-form")).to_have_count(0)
    page.context.clear_cookies()
    sign_in(creator)
    page.goto(view_url)
    page.locator("#access-emails").fill("")
    page.get_by_role("button", name="Save access", exact=True).click()
    expect(page.locator("#access-status")).to_have_text("Access updated.")
    assert not whisper.allowed_readers.exists()
    page.context.clear_cookies()
    sign_in(reader)
    assert page.goto(view_url).status == 403
    assert redis_store.get_view_count(whisper.id) == 1


@pytest.mark.browser_settings(
    ENABLE_AUTH=True,
    ENABLE_LOCAL_LOGIN=True,
    PSST_ENABLE_RECEIVE_ACCESS=True,
    PSST_RECEIVE_ACCESS_DEFAULT=True,
)
def test_manage_pending_access_validation_and_disable(
    page, create_whisper, verified_user, sign_in
):
    creator = verified_user("creator")
    reader = verified_user("reader")
    sign_in(creator)
    _, view_url = create_whisper(kind="receive")
    page.goto(view_url)
    expect(page.locator("#access-creator-only")).to_be_checked()
    page.locator("#access-emails").fill("unknown@example.com")
    page.get_by_role("button", name="Save access", exact=True).click()
    expect(page.locator("#access-status")).to_contain_text("verified primary email")
    expect(page.get_by_role("button", name="Save access", exact=True)).to_be_enabled()
    page.locator("#access-emails").fill(reader.email)
    page.get_by_role("button", name="Save access", exact=True).click()
    expect(page.locator("#access-status")).to_have_text("Access updated.")
    assert Whisper.objects.get().allowed_readers.filter(pk=reader.pk).exists()
    page.locator("#access-creator-only").uncheck()
    expect(page.locator("#access-emails")).to_be_disabled()
    page.get_by_role("button", name="Save access", exact=True).click()
    expect(page.locator("#access-status")).to_have_text("Access updated.")
    whisper = Whisper.objects.get()
    assert not whisper.creator_only
    assert not whisper.allowed_readers.exists()
    assert redis_store.get_view_count(whisper.id) == 0
    page.context.clear_cookies()
    page.goto(view_url)
    expect(page.locator("h1")).to_contain_text("Waiting")


@pytest.mark.browser_settings(
    ENABLE_AUTH=True,
    ENABLE_LOCAL_LOGIN=True,
    PSST_ENABLE_RECEIVE_ACCESS=True,
    PSST_FORCE_RECEIVE_ACCESS=True,
)
def test_mandatory_reader_restriction_controls(
    page, create_whisper, verified_user, sign_in
):
    sign_in(verified_user())
    _, view_url = create_whisper(kind="receive")
    assert Whisper.objects.get().creator_only
    page.goto(view_url)
    expect(page.locator("#access-creator-only")).to_be_checked()
    expect(page.locator("#access-creator-only")).to_be_disabled()


@pytest.mark.browser_settings(
    ENABLE_AUTH=True, ENABLE_LOCAL_LOGIN=True, PSST_ENABLE_RECEIVE_ACCESS=True
)
def test_access_network_failure_preserves_edits(
    page, create_whisper, verified_user, sign_in
):
    sign_in(verified_user())
    reader = verified_user("reader")
    _, view_url = create_whisper(kind="receive", creator_only=True)
    page.goto(view_url)
    page.locator("#access-emails").fill(reader.email)
    page.route(
        "**/api/whisper/*/access",
        lambda route: route.fulfill(status=503, body="Unavailable"),
    )
    page.get_by_role("button", name="Save access", exact=True).click()
    expect(page.locator("#access-status")).to_have_text("Could not update access.")
    expect(page.locator("#access-emails")).to_have_value(reader.email)
    expect(page.locator("#access-emails")).to_be_enabled()
    page.unroute("**/api/whisper/*/access")
    page.get_by_role("button", name="Save access", exact=True).click()
    expect(page.locator("#access-status")).to_have_text("Access updated.")


def test_authenticated_api_requires_csrf(page, app_url, verified_user, sign_in):
    sign_in(verified_user())
    response = page.request.post(
        app_url + "/api/whisper",
        data={"ciphertext": "encrypted", "iv": "nonce", "expiry": "1d"},
    )
    assert response.status == 403
    assert not Whisper.objects.exists()


def test_session_cookie_is_http_only(page, verified_user, sign_in):
    sign_in(verified_user())
    session = next(
        cookie for cookie in page.context.cookies() if cookie["name"] == "sessionid"
    )
    assert session["httpOnly"]
    assert "sessionid" not in page.evaluate("document.cookie")
