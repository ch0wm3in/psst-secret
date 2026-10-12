import base64
import json
from datetime import timedelta
from pathlib import Path
from urllib.parse import urlsplit

import pytest
from django.utils import timezone
from playwright.sync_api import expect

from whispers import redis_store
from whispers.constants import EXPIRY_DELTAS
from whispers.models import Whisper

pytestmark = pytest.mark.browser
PASSWORD = "A-strong-browser-password-42!"


def _reveal(page, url):
    page.goto(url)
    page.locator("#reveal-btn").click()


def _submit(page, url, content="A reply encrypted in the sender's browser", files=None):
    page.goto(url)
    if files:
        page.locator("#tab-file").click()
        page.locator("#file-input").set_input_files(files)
    else:
        page.locator("#whisper").fill(content)
    page.locator("#submit-btn").click()
    expect(page.locator("#submit-success")).to_be_visible()


def test_text_round_trip_and_burn(page, app_url):
    page.goto(app_url)
    page.locator("#whisper").fill("A private browser-only whisper")
    page.locator("#encrypt-btn").click()
    expect(page.locator("#result")).to_be_visible()
    url = page.locator("#result-url").input_value()
    assert "#" in url
    page.goto(url)
    page.locator("#reveal-btn").click()
    expect(page.locator("#decrypted-content")).to_have_text(
        "A private browser-only whisper"
    )
    page.goto(url)
    expect(page.locator("#reveal-btn")).to_have_count(0)
    expect(page.locator("h1")).to_contain_text("burned")


def test_confirmation_does_not_consume_a_view(page, create_whisper):
    url = create_whisper()
    for _ in range(2):
        page.goto(url)
        expect(page.locator("#reveal-btn")).to_be_visible()
    assert redis_store.get_view_count(Whisper.objects.get().id) == 0
    _reveal(page, url)
    expect(page.locator("#decrypted-content")).to_be_visible()


@pytest.mark.parametrize("limit", ["3", "5", "10", "custom", "0"])
def test_view_limits(page, create_whisper, limit):
    fields = {"max_views": limit}
    if limit == "custom":
        fields["max_views_custom"] = 2
    url = create_whisper(**fields)
    max_views = 2 if limit == "custom" else int(limit)
    reveals = max_views or 3
    for count in range(1, reveals + 1):
        _reveal(page, url)
        expect(page.locator("#decrypted-content")).to_be_visible()
        expect(page.locator("#view-count-banner-text")).to_contain_text(str(count))
    if max_views:
        expect(page.locator("#view-count-banner-text")).to_contain_text("Final view")
        assert not Whisper.objects.exists()
        page.goto(url)
        expect(page.locator("h1")).to_contain_text("burned")
    else:
        expect(page.locator("#view-count-banner-text")).to_contain_text("unlimited")
        assert redis_store.get_view_count(Whisper.objects.get().id) == reveals


@pytest.mark.parametrize("expiry", list(EXPIRY_DELTAS))
def test_expiry_choices(create_whisper, browser_app, expiry):
    create_whisper(expiry=expiry, max_views=0)
    whisper = Whisper.objects.get()
    assert whisper.expiry_option == expiry
    assert whisper.expires_at is not None
    assert (
        abs(
            (
                whisper.expires_at - timezone.now() - EXPIRY_DELTAS[expiry]
            ).total_seconds()
        )
        < 10
    )
    assert (
        0
        < browser_app.ttl(redis_store._key(whisper.id))
        <= EXPIRY_DELTAS[expiry].total_seconds()
    )


@pytest.mark.parametrize("kind", ["send", "receive"])
def test_password_round_trip_and_wrong_password(page, create_whisper, kind):
    result = create_whisper(kind=kind, password=PASSWORD)
    if kind == "receive":
        submit_url, url = result
        _submit(page, submit_url, content="Password-wrapped request reply")
        plaintext = "Password-wrapped request reply"
    else:
        url = result
        plaintext = "A private browser-only whisper"
    assert not urlsplit(url).fragment
    _reveal(page, url)
    expect(page.locator("#password-prompt")).to_be_visible()
    page.locator("#view-password").fill("Incorrect-password-42!")
    page.get_by_role("button", name="Decrypt", exact=True).click()
    expect(page.locator("#password-error")).to_contain_text("Wrong password")
    page.locator("#view-password").fill(PASSWORD)
    page.get_by_role("button", name="Decrypt", exact=True).click()
    expect(page.locator("#decrypted-content")).to_have_text(plaintext)


def test_receive_pending_submission_and_duplicate(page, create_whisper):
    submit_url, view_url = create_whisper(kind="receive")
    assert (
        urlsplit(submit_url).path.split("/")[-1]
        != urlsplit(view_url).path.split("/")[-1]
    )
    page.goto(view_url)
    expect(page.locator("h1")).to_contain_text("Waiting")
    assert redis_store.get_view_count(Whisper.objects.get().id) == 0
    _submit(page, submit_url)
    page.goto(submit_url)
    page.reload()
    expect(page.locator("#submit-btn")).to_have_count(0)
    expect(page.locator("h1")).to_contain_text("submitted")
    _reveal(page, view_url)
    expect(page.locator("#decrypted-content")).to_have_text(
        "A reply encrypted in the sender's browser"
    )


@pytest.mark.parametrize("kind", ["send", "receive"])
def test_multiple_files_download_exact_bytes(page, create_whisper, kind):
    files = [
        {
            "name": "private.txt",
            "mimeType": "text/plain",
            "buffer": b"Private file contents\n",
        },
        {
            "name": "binary.bin",
            "mimeType": "application/octet-stream",
            "buffer": bytes(range(256)),
        },
    ]
    if kind == "receive":
        submit_url, url = create_whisper(kind="receive")
        _submit(page, submit_url, files=files)
    else:
        url = create_whisper(files=files)
    _reveal(page, url)
    expect(page.locator("#file-heading")).to_have_text("Decrypted Files")
    expect(page.locator("#download-all-btn")).to_be_visible()
    for index, uploaded in enumerate(files):
        with page.expect_download() as download_info:
            page.locator("#decrypted-file-list li").nth(index).get_by_role(
                "button"
            ).click()
        download = download_info.value
        assert download.suggested_filename == uploaded["name"]
        assert Path(download.path()).read_bytes() == uploaded["buffer"]
    downloads = []
    page.on("download", lambda download: downloads.append(download))
    with page.expect_download(
        predicate=lambda download: download.suggested_filename == "binary.bin"
    ):
        page.locator("#download-all-btn").click()
    assert {download.suggested_filename for download in downloads} == {
        file["name"] for file in files
    }
    for download in downloads:
        uploaded = next(
            file for file in files if file["name"] == download.suggested_filename
        )
        assert Path(download.path()).read_bytes() == uploaded["buffer"]


def test_file_selection_remove_and_size_limit(page, app_url):
    page.goto(app_url)
    page.locator("#tab-file").click()
    page.evaluate("window.PSST_MAX_UPLOAD_SIZE = 8")
    page.locator("#file-input").set_input_files(
        [
            {"name": "small.txt", "mimeType": "text/plain", "buffer": b"small"},
            {"name": "large.txt", "mimeType": "text/plain", "buffer": b"too large"},
        ]
    )
    expect(page.locator("#file-list li")).to_have_count(1)
    expect(page.locator("#file-size-error")).to_contain_text("large.txt")
    page.get_by_role("button", name="Remove", exact=True).click()
    expect(page.locator("#file-list")).to_be_hidden()
    page.locator("#encrypt-btn").click()
    expect(page.locator("#error")).to_contain_text("Please enter some content")


def test_drag_and_drop_single_file(page, app_url):
    page.goto(app_url)
    page.locator("#tab-file").click()
    page.locator("#file-drop-zone").evaluate("""element => {
        const transfer = new DataTransfer();
        transfer.items.add(new File(['dragged bytes'], 'dropped.txt', {type: 'text/plain'}));
        element.dispatchEvent(new DragEvent('drop', {dataTransfer: transfer, bubbles: true}));
    }""")
    expect(page.locator("#file-list")).to_contain_text("dropped.txt")
    page.locator("#encrypt-btn").click()
    expect(page.locator("#result")).to_be_visible()
    _reveal(page, page.locator("#result-url").input_value())
    expect(page.locator("#file-heading")).to_have_text("Decrypted File")
    expect(page.locator("#download-all-row")).to_be_hidden()


@pytest.mark.parametrize("kind", ["send", "receive"])
def test_empty_content_validation(page, app_url, create_whisper, kind):
    if kind == "receive":
        submit_url, _ = create_whisper(kind="receive")
        page.goto(submit_url)
        button = "#submit-btn"
    else:
        page.goto(app_url)
        button = "#encrypt-btn"
    page.locator("#whisper").fill("   ")
    page.locator(button).click()
    expect(page.locator("#error")).to_contain_text("Please enter some content")
    expect(page.locator(button)).to_be_enabled()


def test_password_strength_gate(page, app_url):
    page.goto(app_url)
    page.locator("#advanced-options summary").click()
    page.locator("#password").fill("weak")
    expect(page.locator("#encrypt-btn")).to_be_disabled()
    expect(page.locator("#request-btn")).to_be_disabled()
    page.locator("#password").fill(PASSWORD)
    expect(page.locator("#encrypt-btn")).to_be_enabled()
    page.locator("#password").fill("")
    expect(page.locator("#encrypt-btn")).to_be_enabled()


@pytest.mark.parametrize("bad_fragment", ["", "AAAA"])
def test_missing_or_corrupt_decryption_key(page, create_whisper, bad_fragment):
    url = create_whisper(max_views=0)
    _reveal(page, url.split("#")[0] + ("#" + bad_fragment if bad_fragment else ""))
    expect(page.locator("#error-message")).to_contain_text(
        "Decryption failed" if bad_fragment else "No decryption key"
    )


@pytest.mark.parametrize("bad_fragment", ["", "AAAA"])
def test_submit_fingerprint_required_and_checked(page, create_whisper, bad_fragment):
    submit_url, _ = create_whisper(kind="receive")
    page.goto(submit_url.split("#")[0] + ("#" + bad_fragment if bad_fragment else ""))
    page.locator("#whisper").fill("Must not be submitted")
    page.locator("#submit-btn").click()
    expect(page.locator("#error")).to_be_visible()
    expect(page.locator("#submit-btn")).to_be_enabled()
    stored = redis_store.get_crypto(Whisper.objects.get().id)
    assert stored is not None
    assert not stored["ciphertext"]


@pytest.mark.parametrize("kind", ["send", "receive"])
@pytest.mark.parametrize("password", ["", PASSWORD])
def test_plaintext_and_secret_keys_never_leave_browser(
    page, create_whisper, kind, password
):
    requests = []
    page.on(
        "request",
        lambda request: requests.append((request.url, request.post_data or "")),
    )
    plaintext = "NETWORK-PRIVACY-CANARY-61793"
    result = create_whisper(
        kind=kind, content=plaintext, max_views=0, password=password
    )
    if kind == "receive":
        submit_url, url = result
        _submit(page, submit_url, content=plaintext)
    else:
        url = result
    key = urlsplit(url).fragment or password
    assert key
    whisper = Whisper.objects.get()
    stored = json.dumps(redis_store.get_crypto(whisper.id))
    metadata = json.dumps(Whisper.objects.values().get(), default=str)
    assert plaintext not in stored + metadata
    assert key not in stored + metadata
    _reveal(page, url)
    if password:
        page.locator("#view-password").fill(password)
        page.get_by_role("button", name="Decrypt", exact=True).click()
    expect(page.locator("#decrypted-content")).to_have_text(plaintext)
    for request_url, body in requests:
        assert not urlsplit(request_url).fragment
        assert plaintext not in body + request_url
        assert key not in body + request_url
    assert page.evaluate("[localStorage.length, sessionStorage.length]") == [0, 0]


@pytest.mark.parametrize("reason", ["database_expiry", "redis_eviction"])
@pytest.mark.parametrize("kind", ["send", "receive"])
def test_expired_or_evicted_whisper(page, create_whisper, reason, kind):
    result = create_whisper(kind=kind)
    url = result[0] if kind == "receive" else result
    whisper = Whisper.objects.get()
    if reason == "database_expiry":
        Whisper.objects.filter(pk=whisper.pk).update(
            expires_at=timezone.now() - timedelta(seconds=1)
        )
    else:
        redis_store.delete_crypto(whisper.id)
    response = page.goto(url)
    assert response.status == 410
    expect(page.locator("h1")).to_contain_text("expired")
    assert not Whisper.objects.exists()
    assert redis_store.get_crypto(whisper.id) is None


@pytest.mark.parametrize("kind", ["send", "receive"])
@pytest.mark.parametrize(
    "cidr,allowed", [("127.0.0.0/8", True), ("192.0.2.0/24", False)]
)
def test_ip_restrictions(page, create_whisper, kind, cidr, allowed):
    result = create_whisper(kind=kind, allowed_cidr=cidr)
    url = result[0] if kind == "receive" else result
    response = page.goto(url)
    assert response.status == (200 if allowed else 403)
    if not allowed:
        expect(page.locator("h1")).to_contain_text("denied")
        assert redis_store.get_view_count(Whisper.objects.get().id) == 0


@pytest.mark.parametrize("status", [400, 403, 429, 500])
@pytest.mark.parametrize("kind", ["send", "receive"])
def test_creation_server_errors_allow_retry(page, app_url, status, kind):
    page.goto(app_url)
    if kind == "receive":
        page.locator("#tab-receive").click()
        endpoint, button, result = (
            "**/api/whisper/request",
            "#request-btn",
            "#receive-result",
        )
    else:
        page.locator("#whisper").fill("Retry after failure")
        endpoint, button, result = "**/api/whisper", "#encrypt-btn", "#result"
    page.route(
        endpoint,
        lambda route: route.fulfill(
            status=status,
            content_type="application/json",
            body=json.dumps({"error": "Creation rejected"}),
        ),
    )
    page.locator(button).click()
    expect(page.locator("#error")).to_contain_text("Creation rejected")
    expect(page.locator(button)).to_be_enabled()
    page.unroute(endpoint)
    page.locator(button).click()
    expect(page.locator(result)).to_be_visible()


def test_submit_server_error_allows_retry(page, create_whisper):
    submit_url, _ = create_whisper(kind="receive")
    page.goto(submit_url)
    page.locator("#whisper").fill("Retry submission")
    page.route(
        "**/api/whisper/submit/*",
        lambda route: route.fulfill(status=503, body="Unavailable"),
    )
    page.locator("#submit-btn").click()
    expect(page.locator("#error")).to_contain_text("503")
    expect(page.locator("#submit-btn")).to_be_enabled()
    page.unroute("**/api/whisper/submit/*")
    page.locator("#submit-btn").click()
    expect(page.locator("#submit-success")).to_be_visible()


def test_ciphertext_tampering_is_detected(page, create_whisper):
    url = create_whisper(max_views=0)
    whisper = Whisper.objects.get()
    stored = redis_store.get_crypto(whisper.id)
    assert stored is not None
    ciphertext = bytearray(base64.b64decode(stored["ciphertext"]))
    ciphertext[0] ^= 1
    redis_store.update_crypto(
        whisper.id, ciphertext=base64.b64encode(ciphertext).decode()
    )
    _reveal(page, url)
    expect(page.locator("#error-message")).to_contain_text("Decryption failed")
    expect(page.locator("#decrypted-container")).to_be_hidden()


@pytest.mark.parametrize("kind", ["send", "receive"])
def test_network_failure_restores_creation_controls(page, app_url, kind):
    page.goto(app_url)
    if kind == "receive":
        page.locator("#tab-receive").click()
        endpoint, button = "**/api/whisper/request", "#request-btn"
    else:
        page.locator("#whisper").fill("Network error must not lose content")
        endpoint, button = "**/api/whisper", "#encrypt-btn"
    page.route(endpoint, lambda route: route.abort())
    page.locator(button).click()
    expect(page.locator("#error")).to_be_visible()
    expect(page.locator(button)).to_be_enabled()
    assert not Whisper.objects.exists()


def test_real_rate_limit_is_shown_in_browser(
    page, create_whisper, app_url, monkeypatch
):
    from whispers.views import WhisperCreateThrottle

    monkeypatch.setattr(
        WhisperCreateThrottle,
        "THROTTLE_RATES",
        {"whisper_create": "1/minute"},
    )
    create_whisper()
    page.goto(app_url)
    page.locator("#whisper").fill("Rate limited whisper")
    page.locator("#encrypt-btn").click()
    expect(page.locator("#error")).to_contain_text("429")
    expect(page.locator("#encrypt-btn")).to_be_enabled()
    assert Whisper.objects.count() == 1


def test_duplicate_submit_api_cannot_replace_ciphertext(page, create_whisper):
    submit_url, _ = create_whisper(kind="receive")
    _submit(page, submit_url)
    whisper = Whisper.objects.get()
    stored = redis_store.get_crypto(whisper.id)
    assert stored is not None
    ciphertext = stored["ciphertext"]
    response = page.request.post(
        urlsplit(submit_url)
        ._replace(path="/api/whisper" + urlsplit(submit_url).path, fragment="")
        .geturl(),
        data={
            "ciphertext": "replacement",
            "iv": "nonce",
            "encapsulated_key": "replacement",
        },
    )
    assert response.status == 409
    stored = redis_store.get_crypto(whisper.id)
    assert stored is not None
    assert stored["ciphertext"] == ciphertext


def test_invalid_ip_restriction_is_reported(page, app_url):
    page.goto(app_url)
    page.locator("#whisper").fill("Whisper with an invalid network restriction")
    page.locator("#advanced-options summary").click()
    page.locator("#allowed-cidr").fill("not-a-network")
    page.locator("#encrypt-btn").click()
    expect(page.locator("#error")).to_contain_text("allowed_cidr")
    expect(page.locator("#encrypt-btn")).to_be_enabled()
    assert not Whisper.objects.exists()
