import json
import uuid
from urllib.parse import urlsplit

import pytest
from django.utils import translation
from django.utils.translation.trans_real import DjangoTranslation
from playwright.sync_api import expect

from whispers.models import HourlyWhisperStats
from whispers.tests.browser.test_flows import _reveal, _submit

pytestmark = pytest.mark.browser


def test_navigation_optional_features_and_not_found(page, app_url):
    response = page.goto(app_url)
    assert "no-store" in response.headers["cache-control"]
    expect(page.locator("#creator-only")).to_have_count(0)
    expect(page.locator("#notify-email")).to_have_count(0)
    expect(page.get_by_role("link", name="Statistics", exact=True)).to_have_count(0)
    page.get_by_role("link", name="About", exact=True).click()
    expect(page).to_have_url(app_url + "/about")
    expect(page.locator("main")).to_contain_text("psst-secret")
    assert page.goto(app_url + "/stats").status == 404
    assert page.goto(app_url + "/does-not-exist").status == 404
    assert page.goto(app_url + f"/whisper/{uuid.uuid4()}").status == 404
    expect(page.locator("h1")).to_contain_text("burned")
    assert page.goto(app_url + f"/submit/{uuid.uuid4()}").status == 404


@pytest.mark.parametrize("language", ["en", "da", "cs", "sv", "fil"])
def test_language_switching_translates_html_and_javascript(page, app_url, language):
    page.goto(app_url)
    page.locator('select[name="language"]').select_option(language)
    expect(page.locator("html")).to_have_attribute("lang", language)
    with translation.override(language):
        heading = translation.gettext("Share a whisper")
    expect(page.locator("h1")).to_have_text(heading)
    page.locator("#encrypt-btn").click()
    message = "Please enter some content or select a file to encrypt."
    error = DjangoTranslation(language, domain="djangojs").gettext(message)
    expect(page.locator("#error")).to_have_text(error)
    page.reload()
    expect(page.locator("html")).to_have_attribute("lang", language)


@pytest.mark.browser_settings(PSST_ENABLE_STATS=True)
def test_statistics_live_totals_and_all_ranges(page, app_url, create_whisper):
    page.goto(app_url + "/stats")
    expect(page.get_by_text("No whispers submitted in this period.")).to_be_visible()
    send_url = create_whisper()
    _reveal(page, send_url)
    submit_url, receive_url = create_whisper(kind="receive")
    page.goto(app_url + "/stats")
    expect(page.locator("dl").first.locator("dd")).to_have_text(["1", "1", "0", "1"])
    _submit(page, submit_url)
    _reveal(page, receive_url)
    page.goto(app_url + "/stats")
    expect(page.locator("dl").first.locator("dd")).to_have_text(["2", "1", "1", "2"])
    for preset in ("1d", "1w", "1m", "3m", "6m", "1y"):
        page.locator("#stats-range").select_option(preset)
        expect(page).to_have_url(app_url + "/stats?range=" + preset)
        expect(page.locator("dl").first.locator("dd")).to_have_text(
            ["2", "1", "1", "2"]
        )
    page.get_by_text("Daily totals", exact=True).last.click()
    expect(page.locator("table")).to_be_visible()
    page.goto(app_url + "/stats?range=invalid")
    expect(page.locator("#stats-range")).to_have_value("1w")
    assert HourlyWhisperStats.objects.count() == 1


@pytest.mark.browser_settings(
    PSST_ENABLE_EMAIL=True,
    MAILERS={"default": {"BACKEND": "django.core.mail.backends.locmem.EmailBackend"}},
)
@pytest.mark.parametrize("kind", ["send", "receive"])
def test_email_notifications_exclude_keys_and_plaintext(
    page, create_whisper, mailoutbox, kind
):
    plaintext = "EMAIL-PRIVACY-CANARY-32918"
    result = create_whisper(
        kind=kind, content=plaintext, notify_email="notification@example.com"
    )
    if kind == "receive":
        assert not mailoutbox
        submit_url, view_url = result
        _submit(page, submit_url, content=plaintext)
    else:
        view_url = result
    assert len(mailoutbox) == 1
    message = mailoutbox[0]
    assert message.to == ["notification@example.com"]
    body = message.body + "".join(
        alternative.content for alternative in message.alternatives
    )
    assert view_url.split("#")[0] in body
    assert urlsplit(view_url).fragment not in body
    assert plaintext not in body


@pytest.mark.parametrize("width,height", [(390, 844), (1280, 800)])
def test_responsive_round_trip_and_assets(page, create_whisper, width, height):
    page.set_viewport_size({"width": width, "height": height})
    errors = []
    assets = []
    page.on("pageerror", lambda error: errors.append(str(error)))
    page.on(
        "response",
        lambda response: (
            assets.append(response) if "/static/" in response.url else None
        ),
    )
    url = create_whisper(content="Responsive browser whisper")
    _reveal(page, url)
    expect(page.locator("#decrypted-content")).to_have_text(
        "Responsive browser whisper"
    )
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
    assert assets
    assert all(response.status == 200 for response in assets)
    assert not errors


def test_create_another_whisper(page, create_whisper, app_url):
    create_whisper()
    page.get_by_role("button", name="Create another whisper", exact=True).click()
    expect(page).to_have_url(app_url + "/")
    expect(page.locator("#whisper")).to_have_value("")
    expect(page.locator("#result")).to_be_hidden()


@pytest.mark.parametrize("kind", ["send", "receive"])
def test_clipboard_links_and_decrypted_content(
    page, create_whisper, browser_name, kind
):
    if browser_name != "chromium":
        pytest.skip("Clipboard read permissions are only supported by Chromium")
    page.context.grant_permissions(["clipboard-read", "clipboard-write"])
    result = create_whisper(kind=kind)
    if kind == "receive":
        submit_url, view_url = result
        for button, url in (
            ("#copy-submit-btn", submit_url),
            ("#copy-view-btn", view_url),
        ):
            page.locator(button).click()
            expect(page.locator(button)).to_have_text("Copied!")
            assert page.evaluate("navigator.clipboard.readText()") == url
        _submit(page, submit_url)
        content = "A reply encrypted in the sender's browser"
    else:
        view_url = result
        page.locator("#copy-btn").click()
        expect(page.locator("#copy-btn")).to_have_text("Copied!")
        assert page.evaluate("navigator.clipboard.readText()") == view_url
        content = "A private browser-only whisper"
    _reveal(page, view_url)
    expect(page.locator("#decrypted-content")).to_have_text(content)
    page.get_by_role("button", name="Copy", exact=True).click()
    assert page.evaluate("navigator.clipboard.readText()") == content


@pytest.mark.parametrize("payload", ["Legacy plaintext", '{"unexpected": "envelope"}'])
def test_legacy_text_envelopes(page, app_url, payload):
    page.goto(app_url)
    encrypted = page.evaluate(
        """async plaintext => {
        const key = await generateKey();
        const encrypted = await encryptContent(plaintext, key);
        const response = await fetch('/api/whisper', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({...encrypted, expiry: '1d'})
        });
        const data = await response.json();
        return data.url + '#' + key;
    }""",
        payload,
    )
    _reveal(page, encrypted)
    expect(page.locator("#decrypted-content")).to_have_text(payload)


def test_legacy_file_sanitizes_filename(page, create_whisper):
    url = create_whisper()
    _reveal(page, url)
    expect(page.locator("#decrypted-content")).to_be_visible()
    page.evaluate(
        "handleDecrypted",
        json.dumps(
            {
                "type": "file",
                "filename": "../../private.txt",
                "mimetype": "text/plain",
                "data": "cHJpdmF0ZQ==",
            }
        ),
    )
    with page.expect_download() as download_info:
        page.locator("#decrypted-file-list button").click()
    assert download_info.value.suggested_filename == "_.._private.txt"


def test_encrypted_html_is_rendered_as_text(page, create_whisper):
    content = '<img src=x onerror="window.whisperXss=true"><script>window.whisperXss=true</script>'
    url = create_whisper(content=content)
    _reveal(page, url)
    expect(page.locator("#decrypted-content")).to_have_text(content)
    expect(
        page.locator("#decrypted-content img, #decrypted-content script")
    ).to_have_count(0)
    assert page.evaluate("window.whisperXss === undefined")
