import json
from urllib.parse import urlsplit

import pytest
from django.utils import translation
from django.utils.translation.trans_real import DjangoTranslation
from playwright.sync_api import expect

from whispers import redis_store
from whispers.models import Whisper

pytestmark = [
    pytest.mark.browser,
    pytest.mark.browser_settings(PSST_ENABLE_RECEIVE_HISTORY=True),
]
STORAGE_KEY = "psst.receiveHistory"
LABEL = "AWS creds from Bob"
TITLE, PENDING, VIEW = "Saved receive requests", "Waiting for sender", "View whisper"


def _stored(page):
    raw = page.evaluate(f"localStorage.getItem({json.dumps(STORAGE_KEY)})")
    return json.loads(raw) if raw else None


def _opt_in(page, app_url):
    page.goto(app_url)
    page.locator("#tab-receive").click()
    page.locator("#receive-history-enabled").check()
    expect(page.locator("#receive-label")).to_be_visible()


def _create_saved(page, app_url, label=LABEL, **fields):
    _opt_in(page, app_url)
    page.locator("#receive-label").fill(label)
    for name, value in fields.items():
        if name == "max_views":
            page.locator("#max-views").select_option(str(value))
        else:
            page.locator("#advanced-options").evaluate("e => e.open = true")
            page.locator("#" + name.replace("_", "-")).fill(str(value))
    page.locator("#request-btn").click()
    expect(page.locator("#receive-result")).to_be_visible()
    expect(page.locator("#receive-history-saved")).to_be_visible()
    return (
        page.locator("#submit-url").input_value(),
        page.locator("#view-url").input_value(),
    )


def _submit(page, url, content="Saved receive reply"):
    page.goto(url)
    page.locator("#whisper").fill(content)
    page.locator("#submit-btn").click()
    expect(page.locator("#submit-success")).to_be_visible()


def _card(page):
    return page.locator("#receive-history-list > li")


@pytest.mark.browser_settings(PSST_ENABLE_RECEIVE_HISTORY=False)
def test_disabled_instance_has_no_history_ui(page, app_url, create_whisper):
    create_whisper(kind="receive")
    expect(page.locator("[data-receive-history-toggle]")).to_have_count(0)
    expect(page.locator("#receive-drawer")).to_have_count(0)
    assert page.evaluate("localStorage.length") == 0
    assert page.goto(app_url + "/receives").status == 404


def test_history_is_opt_in_and_writes_nothing_by_default(page, app_url, create_whisper):
    page.goto(app_url)
    page.locator("#tab-receive").click()
    expect(page.locator("#receive-history-enabled")).not_to_be_checked()
    expect(page.locator("#receive-history-tradeoff")).to_contain_text(
        "anyone with access to this browser profile"
    )
    expect(page.locator("#receive-label")).to_be_hidden()
    create_whisper(kind="receive")
    expect(page.locator("#receive-history-saved")).to_be_hidden()
    page.goto(app_url)
    expect(page.locator("#receive-drawer")).to_be_hidden()
    page.goto(app_url + "/receives")
    expect(page.locator("#receive-history-empty")).to_contain_text(
        "No saved receive requests"
    )
    assert page.evaluate("[localStorage.length, sessionStorage.length]") == [0, 0]


def test_send_mode_hides_history_options(page, app_url):
    page.goto(app_url)
    expect(page.locator("#receive-history-options")).to_be_hidden()
    page.locator("#tab-receive").click()
    expect(page.locator("#receive-history-options")).to_be_visible()


def test_saved_request_label_stays_in_browser(page, app_url):
    bodies = []
    page.on(
        "request",
        lambda request: bodies.append(request.url + (request.post_data or "")),
    )
    submit_url, view_url = _create_saved(page, app_url)
    whisper = Whisper.objects.get()
    assert not any(LABEL in body for body in bodies)
    assert LABEL not in json.dumps(redis_store.get_crypto(whisper.id))
    stored = _stored(page)
    assert stored["version"] == 1 and stored["enabled"] is True
    [entry] = stored["entries"]
    assert entry["id"] == str(whisper.id)
    assert (entry["viewUrl"], entry["submitUrl"]) == (view_url, submit_url)
    assert entry["label"] == LABEL
    assert entry["status"] == "pending"
    assert abs(entry["expiresAt"] / 1000 - whisper.expires_at.timestamp()) < 1


def test_drawer_lists_entries_and_is_keyboard_accessible(page, app_url):
    _create_saved(page, app_url)
    page.goto(app_url + "/about")
    drawer = page.locator("#receive-drawer")
    toggle = page.locator("#receive-drawer-toggle")
    expect(drawer).to_be_visible()
    expect(page.locator("#receive-drawer-count")).to_have_text("1")
    expect(toggle).to_have_attribute("aria-expanded", "false")
    expect(page.locator("#receive-drawer-panel")).to_be_hidden()
    toggle.focus()
    page.keyboard.press("Enter")
    expect(toggle).to_have_attribute("aria-expanded", "true")
    panel = page.locator("#receive-drawer-panel")
    expect(panel).to_contain_text(LABEL)
    expect(panel).to_contain_text("Waiting for sender")
    expect(panel).to_contain_text("Expires in")
    page.keyboard.press("Escape")
    expect(panel).to_be_hidden()
    expect(toggle).to_be_focused()
    toggle.click()
    page.get_by_role("link", name="Open full list").click()
    expect(page).to_have_url(app_url + "/receives")
    expect(page.locator("#receive-drawer")).to_have_count(0)
    expect(_card(page)).to_have_count(1)


def test_drawer_fits_mobile_viewport(page, app_url):
    _create_saved(page, app_url)
    page.set_viewport_size({"width": 360, "height": 640})
    page.goto(app_url + "/about")
    page.locator("#receive-drawer-toggle").click()
    box = page.locator("#receive-drawer-panel").bounding_box()
    assert box["x"] >= 0 and box["x"] + box["width"] <= 360


def test_submission_updates_status_without_consuming_a_view(page, app_url):
    submit_url, _ = _create_saved(page, app_url)
    whisper = Whisper.objects.get()
    page.goto(app_url + "/receives")
    card = _card(page)
    expect(card).to_have_attribute("data-status", "pending")
    expect(card.locator('input[aria-label="Submit link"]')).to_have_value(submit_url)
    page.locator('[data-receive-filter="completed"]').click()
    expect(_card(page)).to_have_count(0)
    expect(page.locator("#receive-history-empty")).to_contain_text("match this filter")

    _submit(page, submit_url)
    page.goto(app_url + "/receives")
    expect(card).to_have_attribute("data-status", "submitted")
    expect(card).to_contain_text("Ready to view")
    page.locator('[data-receive-filter="pending"]').click()
    expect(_card(page)).to_have_count(0)
    page.locator('[data-receive-filter="completed"]').click()
    expect(_card(page)).to_have_count(1)
    assert redis_store.get_view_count(whisper.id) == 0
    assert redis_store.get_crypto(whisper.id)["ciphertext"]


def test_view_whisper_decrypts_locally_and_burn_removes_entry(page, app_url):
    submit_url, _ = _create_saved(page, app_url)
    _submit(page, submit_url, content="Burn after reading reply")
    page.goto(app_url + "/receives")
    page.get_by_role("button", name="View whisper").click()
    page.locator("#reveal-btn").click()
    expect(page.locator("#decrypted-content")).to_have_text("Burn after reading reply")
    assert _stored(page)["entries"] == []
    stored = page.evaluate(f"localStorage.getItem({json.dumps(STORAGE_KEY)})")
    assert "Burn after reading reply" not in stored
    expect(page.locator("#receive-drawer")).to_be_hidden()


def test_multi_view_reveal_marks_entry_viewed(page, app_url):
    submit_url, _ = _create_saved(page, app_url, max_views=3)
    _submit(page, submit_url, content="Multi-view reply")
    page.goto(app_url + "/receives")
    page.get_by_role("button", name="View whisper").click()
    page.locator("#reveal-btn").click()
    expect(page.locator("#decrypted-content")).to_have_text("Multi-view reply")
    [entry] = _stored(page)["entries"]
    assert (entry["status"], entry["remainingViews"]) == ("revealed", 2)
    assert "Multi-view reply" not in json.dumps(entry)
    page.goto(app_url + "/receives")
    expect(_card(page)).to_contain_text("Viewed")
    expect(_card(page)).to_contain_text("2 views remaining")


def test_password_protected_entry_keeps_no_key(page, app_url):
    password = "A-strong-browser-password-42!"
    submit_url, view_url = _create_saved(page, app_url, password=password)
    [entry] = _stored(page)["entries"]
    assert entry["passwordProtected"] is True
    assert "key=" not in urlsplit(entry["viewUrl"]).fragment
    assert password not in json.dumps(_stored(page))
    _submit(page, submit_url, content="Password reply")
    page.goto(app_url + "/receives")
    expect(_card(page)).to_contain_text("Password-protected")
    page.get_by_role("button", name="View whisper").click()
    page.locator("#reveal-btn").click()
    page.locator("#view-password").fill(password)
    page.get_by_role("button", name="Decrypt", exact=True).click()
    expect(page.locator("#decrypted-content")).to_have_text("Password reply")


def test_edit_and_clear_label(page, app_url):
    _create_saved(page, app_url)
    page.goto(app_url + "/receives")
    page.get_by_role("button", name="Edit label").click()
    field = page.locator("[data-label-input]")
    expect(field).to_be_focused()
    field.fill("Database password from Alice")
    page.keyboard.press("Enter")
    expect(page.locator("[data-entry-label]")).to_have_text(
        "Database password from Alice"
    )
    assert _stored(page)["entries"][0]["label"] == "Database password from Alice"
    page.get_by_role("button", name="Edit label").click()
    page.locator("[data-label-input]").fill("")
    page.get_by_role("button", name="Save").click()
    expect(page.locator("[data-entry-label]")).to_have_text("No label")
    assert _stored(page)["entries"][0]["label"] == ""


def test_label_draft_survives_background_refresh(page, app_url):
    _create_saved(page, app_url)
    page.goto(app_url + "/receives")
    page.get_by_role("button", name="Edit label").click()
    field = page.locator("[data-label-input]")
    field.fill("Half-typed label")
    with page.expect_response("**/status"):
        page.evaluate("PsstReceiveHistory.refresh(true)")
    expect(field).to_have_value("Half-typed label")
    expect(field).to_be_focused()
    assert _stored(page)["entries"][0]["label"] == LABEL


def test_remove_and_clear_all(page, app_url):
    for label in ("First", "Second", "Third"):
        _create_saved(page, app_url, label=label)
    page.goto(app_url + "/receives")
    expect(_card(page)).to_have_count(3)
    _card(page).filter(has_text="Second").get_by_role("button", name="Remove").click()
    expect(_card(page)).to_have_count(2)
    page.once("dialog", lambda dialog: dialog.dismiss())
    page.locator("#receive-history-clear").click()
    expect(_card(page)).to_have_count(2)
    page.once("dialog", lambda dialog: dialog.accept())
    page.locator("#receive-history-clear").click()
    expect(_card(page)).to_have_count(0)
    assert _stored(page) == {"version": 1, "enabled": True, "entries": []}


def test_turning_off_can_keep_or_delete_entries(page, app_url):
    _create_saved(page, app_url)
    page.goto(app_url + "/receives")
    toggle = page.locator("#receive-history-enabled")
    page.once("dialog", lambda dialog: dialog.dismiss())
    toggle.uncheck()
    expect(toggle).not_to_be_checked()
    stored = _stored(page)
    assert stored["enabled"] is False and len(stored["entries"]) == 1
    page.goto(app_url)
    expect(page.locator("#receive-drawer")).to_be_hidden()
    page.goto(app_url + "/receives")
    toggle.check()
    messages = []

    def accept(dialog):
        messages.append(dialog.message)
        dialog.accept()

    page.once("dialog", accept)
    toggle.uncheck()
    expect(toggle).not_to_be_checked()
    assert "delete" in messages[0]
    assert page.evaluate("[localStorage.length, sessionStorage.length]") == [0, 0]


def test_expired_entries_are_removed_without_asking_the_server(page, app_url):
    _create_saved(page, app_url)
    whisper_id = str(Whisper.objects.get().id)
    page.evaluate(f"""() => {{
        const data = JSON.parse(localStorage.getItem({json.dumps(STORAGE_KEY)}));
        data.entries[0].expiresAt = Date.now() - 1000;
        localStorage.setItem({json.dumps(STORAGE_KEY)}, JSON.stringify(data));
    }}""")
    status_requests = []
    page.on(
        "request",
        lambda request: (
            status_requests.append(request.url) if "/status" in request.url else None
        ),
    )
    page.goto(app_url + "/receives")
    expect(page.locator("#receive-history-empty")).to_be_visible()
    assert _stored(page)["entries"] == []
    assert not [url for url in status_requests if whisper_id in url]


def test_countdown_expiry_removes_entry_while_page_is_open(page, app_url):
    _create_saved(page, app_url)
    page.route("**/api/v1/whisper/*/status", lambda route: route.abort())
    page.goto(app_url + "/receives")
    expect(_card(page)).to_have_count(1)
    page.evaluate(f"""() => {{
        const data = JSON.parse(localStorage.getItem({json.dumps(STORAGE_KEY)}));
        data.entries[0].expiresAt = Date.now() + 1500;
        localStorage.setItem({json.dumps(STORAGE_KEY)}, JSON.stringify(data));
    }}""")
    page.reload()
    expect(_card(page)).to_have_count(1)
    expect(_card(page)).to_have_count(0, timeout=5000)
    assert _stored(page)["entries"] == []


@pytest.mark.parametrize("reason", ["evicted", "burned_elsewhere"])
def test_server_gone_removes_entry(page, app_url, reason):
    submit_url, view_url = _create_saved(page, app_url)
    whisper = Whisper.objects.get()
    if reason == "evicted":
        redis_store.delete_crypto(whisper.id)
    else:
        _submit(page, submit_url)
        response = page.request.post(
            view_url.split("#")[0],
            data={"reveal_token": view_url.split("reveal=")[1].split("&")[0]},
        )
        assert response.status == 200
        assert not Whisper.objects.exists()
    page.goto(app_url + "/receives")
    expect(page.locator("#receive-history-empty")).to_be_visible()
    assert _stored(page)["entries"] == []


def test_opening_a_gone_view_link_removes_entry(page, app_url):
    _, view_url = _create_saved(page, app_url)
    whisper = Whisper.objects.get()
    redis_store.delete_crypto(whisper.id)
    page.route("**/api/v1/whisper/*/status", lambda route: route.abort())
    page.goto(view_url)
    expect(page.locator("h1")).to_contain_text("expired")
    assert _stored(page)["entries"] == []


def test_entries_sync_between_tabs(page, app_url, context):
    _create_saved(page, app_url)
    other = context.new_page()
    other.goto(app_url + "/receives")
    expect(other.locator("#receive-history-list > li")).to_have_count(1)
    page.goto(app_url + "/receives")
    page.get_by_role("button", name="Remove").click()
    expect(other.locator("#receive-history-list > li")).to_have_count(0)


@pytest.mark.parametrize("language", ["da", "cs", "sv", "fil"])
def test_history_is_translated(page, app_url, language):
    _create_saved(page, app_url)
    page.context.add_cookies(
        [{"name": "django_language", "value": language, "url": app_url}]
    )
    errors = []
    page.on("pageerror", lambda error: errors.append(str(error)))
    page.goto(app_url + "/receives")
    with translation.override(language):
        heading = translation.gettext(TITLE)
    javascript = DjangoTranslation(language, domain="djangojs")
    expect(page.locator("h1")).to_contain_text(heading)
    expect(_card(page)).to_contain_text(javascript.gettext(PENDING))
    expect(page.get_by_role("button", name=javascript.gettext(VIEW))).to_be_visible()
    assert heading != TITLE
    assert not errors
