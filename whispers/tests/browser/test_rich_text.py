import re

import pytest
from playwright.sync_api import expect

from whispers.tests.browser.test_flows import _reveal

pytestmark = [
    pytest.mark.browser,
    pytest.mark.browser_settings(PSST_ENABLE_RICH_TEXT=True),
]

UNSAFE_MARKDOWN = (
    "[js](javascript:window.pwned=1) "
    '<img src=x onerror="window.pwned=1"> '
    "<script>window.pwned=1</script> "
    '<a href="javascript:window.pwned=1">html link</a> '
    "[ok](https://example.com)"
)


def _editor(page):
    return page.locator("[data-rich-editor] .psst-editor")


def test_markdown_whisper_round_trip(page, app_url):
    page.goto(app_url)
    expect(page.locator("#whisper")).to_be_hidden()
    expect(page.locator("[data-rich-editor-count]")).to_have_text("0 characters")
    _editor(page).click()
    page.get_by_role("button", name="Heading 1").click()
    page.keyboard.type("Server access")
    page.keyboard.press("Enter")
    bold = page.get_by_role("button", name="Bold", exact=True)
    bold.click()
    expect(bold).to_have_attribute("aria-pressed", "true")
    page.keyboard.type("password")
    bold.click()
    expect(bold).to_have_attribute("aria-pressed", "false")
    page.keyboard.type(" below")
    expect(page.locator("#whisper")).to_have_value(
        "# Server access\n\n**password** below"
    )
    expect(page.locator("[data-rich-editor-count]")).to_have_text(
        re.compile(r"^[1-9]\d* characters$")
    )
    page.locator("#encrypt-btn").click()
    expect(page.locator("#result")).to_be_visible()
    _reveal(page, page.locator("#result-url").input_value())
    rendered = page.locator("#decrypted-rendered")
    expect(rendered.locator("h1")).to_have_text("Server access")
    expect(rendered.locator("strong")).to_have_text("password")
    expect(rendered.locator("[contenteditable=true]")).to_have_count(0)
    expect(page.locator("#decrypted-content")).to_be_hidden()
    expect(page.locator("#decrypted-content")).to_have_text(
        "# Server access\n\n**password** below"
    )


def test_markdown_special_characters_survive_round_trip(page, app_url):
    secret = "p*ss_w`rd [x] # <b>1</b> \\ ~~no~~"
    page.goto(app_url)
    page.evaluate("v => document.getElementById('whisper').insertSecret(v)", secret)
    page.locator("#encrypt-btn").click()
    expect(page.locator("#result")).to_be_visible()
    _reveal(page, page.locator("#result-url").input_value())
    rendered = page.locator("#decrypted-rendered")
    expect(rendered).to_have_text(secret)
    expect(rendered.locator("b, strong, s, code, h1, a")).to_have_count(0)


def test_markdown_rendering_blocks_unsafe_content(page, app_url):
    page.goto(app_url)
    html = page.evaluate(
        """markdown => {
            const el = document.createElement('div');
            document.body.appendChild(el);
            window.PsstRichText.render(el, markdown);
            return el.innerHTML;
        }""",
        UNSAFE_MARKDOWN,
    )
    assert "<img" not in html
    assert "<script" not in html
    assert "javascript:" not in html
    assert "onerror" not in html
    assert 'href="https://example.com"' in html
    assert 'rel="noopener noreferrer nofollow"' in html
    assert page.evaluate("window.pwned") is None


def test_link_dialog_rejects_unsafe_urls(page, app_url):
    page.goto(app_url)
    _editor(page).click()
    page.keyboard.type("docs")
    page.keyboard.press("ControlOrMeta+a")
    page.get_by_role("button", name="Link", exact=True).click()
    dialog = page.get_by_role("dialog", name="Insert link")
    expect(dialog).to_be_visible()
    expect(dialog.get_by_label("Link text")).to_be_hidden()
    url = dialog.get_by_label("URL")
    expect(url).to_be_focused()
    url.fill("javascript:alert(1)")
    dialog.get_by_role("button", name="Save link").click()
    expect(dialog.get_by_role("alert")).to_be_visible()
    expect(url).to_have_attribute("aria-invalid", "true")
    expect(page.locator("#whisper")).to_have_value("docs")
    url.fill("example.com/help")
    expect(dialog.get_by_role("alert")).to_be_hidden()
    url.press("Enter")
    expect(dialog).to_be_hidden()
    expect(page.locator("#whisper")).to_have_value("[docs](https://example.com/help)")

    page.get_by_role("button", name="Link", exact=True).click()
    expect(url).to_have_value("https://example.com/help")
    dialog.get_by_role("button", name="Remove link").click()
    expect(dialog).to_be_hidden()
    expect(page.locator("#whisper")).to_have_value("docs")


def test_link_dialog_inserts_text_and_cancels(page, app_url):
    page.goto(app_url)
    _editor(page).click()
    link = page.get_by_role("button", name="Link", exact=True)
    link.click()
    dialog = page.get_by_role("dialog", name="Insert link")
    dialog.get_by_label("URL").fill("https://example.com")
    dialog.get_by_role("button", name="Cancel").click()
    expect(dialog).to_be_hidden()
    expect(page.locator("#whisper")).to_have_value("")
    link.click()
    dialog.get_by_label("URL").fill("mailto:team@example.com")
    dialog.get_by_label("Link text").fill("Email us")
    dialog.get_by_role("button", name="Save link").click()
    expect(page.locator("#whisper")).to_have_value(
        "[Email us](mailto:team@example.com)"
    )
    expect(_editor(page)).to_be_focused()


def test_secret_generator_inserts_into_editor(page, app_url):
    page.goto(app_url)
    page.locator("#generate-secret-btn").click()
    expect(_editor(page)).not_to_have_text("")
    expect(page.locator("#whisper")).not_to_have_value("")


def test_markdown_submission_to_receive_request(page, create_whisper):
    submit_url, view_url = create_whisper(kind="receive")
    page.goto(submit_url)
    _editor(page).click()
    page.get_by_role("button", name="Bulleted list").click()
    page.keyboard.type("first")
    page.keyboard.press("Enter")
    page.keyboard.type("second")
    page.locator("#submit-btn").click()
    expect(page.locator("#submit-success")).to_be_visible()
    _reveal(page, view_url)
    expect(page.locator("#decrypted-rendered li")).to_have_text(["first", "second"])


def test_plain_text_mode_sends_raw_content(page, app_url):
    page.goto(app_url)
    _editor(page).click()
    page.get_by_role("button", name="Bold", exact=True).click()
    page.keyboard.type("formatted")
    toggle = page.get_by_role("button", name="Plain text")
    toggle.click()
    expect(toggle).to_have_attribute("aria-pressed", "true")
    expect(_editor(page)).to_be_hidden()
    expect(page.get_by_role("button", name="Bold", exact=True)).to_be_hidden()
    whisper = page.locator("#whisper")
    expect(whisper).to_be_visible()
    expect(whisper).to_have_value("**formatted**")
    whisper.fill("**not bold** <b>raw</b>")
    expect(page.locator("[data-rich-editor-count]")).to_have_text("23 characters")
    page.locator("#encrypt-btn").click()
    expect(page.locator("#result")).to_be_visible()
    _reveal(page, page.locator("#result-url").input_value())
    expect(page.locator("#decrypted-rendered")).to_be_hidden()
    expect(page.locator("#decrypted-content")).to_have_text("**not bold** <b>raw</b>")


def test_plain_text_mode_is_remembered_and_reversible(page, app_url):
    page.goto(app_url)
    page.get_by_role("button", name="Plain text").click()
    page.reload()
    toggle = page.get_by_role("button", name="Plain text")
    expect(toggle).to_have_attribute("aria-pressed", "true")
    page.locator("#generate-secret-btn").click()
    expect(page.locator("#whisper")).not_to_have_value("")
    page.locator("#whisper").fill("**bold** text")
    toggle.click()
    expect(toggle).to_have_attribute("aria-pressed", "false")
    expect(page.locator("#whisper")).to_be_hidden()
    expect(_editor(page).locator("strong")).to_have_text("bold")
    expect(page.locator("#whisper")).to_have_value("**bold** text")
