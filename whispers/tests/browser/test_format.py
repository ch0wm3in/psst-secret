import json
from pathlib import Path
from urllib.parse import parse_qs, urlencode

import pytest
from django.conf import settings
from playwright.sync_api import expect

from whispers import redis_store
from whispers.models import Whisper
from whispers.tests.browser.test_flows import _reveal, _submit

pytestmark = pytest.mark.browser

VECTORS = Path(settings.BASE_DIR) / "spec" / "vectors" / "v1"

# Runs the bundled @psst-secret/crypto package against the shared vectors in a real
# browser. Random values are replaced with the vector inputs so encryption must
# reproduce the expected ciphertext exactly. packages/crypto runs them in Node too.
_RUN_VECTORS = """async ({ mode, cases }) => {
    const {
        base64ToBuf, decryptContent, encryptContent, generateRequestKeyPair,
        generateRevealAuthorization, openFromSender, revealFragment, sealForRecipient,
        submitFragment, unwrapPrivateKey, wrapPrivateKey,
    } = PsstCrypto;
    const bytes = b64 => new Uint8Array(base64ToBuf(b64));
    const hexBytes = hex => new Uint8Array(hex.match(/../g).map(h => parseInt(h, 16)));
    async function withRandom(queue, fn) {
        const real = crypto.getRandomValues.bind(crypto);
        crypto.getRandomValues = array => {
            // Other requests, such as noble's scalar blinding, do not affect outputs.
            if (!queue.length || queue[0].length !== array.length) return real(array);
            array.set(queue.shift());
            return array;
        };
        try {
            const result = await fn();
            if (queue.length) throw new Error('unused randomness');
            return result;
        } finally {
            delete crypto.getRandomValues;
        }
    }
    function readFragment(fragment, reader) {
        window.location.hash = fragment;
        return reader();
    }
    const results = [];
    for (const c of cases) {
        const authorization = await withRandom(
            [hexBytes(c.reveal_token)], generateRevealAuthorization
        );
        const result = { authorization };
        if (mode === 'send') {
            result.encrypted = await withRandom(
                [bytes(c.iv)], () => encryptContent(c.plaintext, c.key)
            );
            result.decrypted = await decryptContent(c.ciphertext, c.iv, c.key);
            result.fragment = revealFragment(c.key, c.reveal_token);
            result.parsed = readFragment(c.fragment, readRevealFragment);
        } else if (mode === 'password') {
            result.encrypted = await withRandom(
                [bytes(c.salt), bytes(c.iv)],
                () => encryptContent(c.plaintext, null, c.password)
            );
            result.decrypted = await decryptContent(c.ciphertext, c.iv, null, c.password, c.salt);
            result.fragment = revealFragment('', c.reveal_token);
            result.parsed = readFragment(c.fragment, readRevealFragment);
        } else {
            result.keys = await withRandom([bytes(c.seed)], generateRequestKeyPair);
            result.encrypted = await withRandom(
                [bytes(c.encapsulation_randomness), bytes(c.iv)],
                () => sealForRecipient(c.plaintext, c.public_key, c.fingerprint)
            );
            result.decrypted = await openFromSender(c, c.seed);
            result.submitFragment = submitFragment(c.fingerprint);
            result.parsedSubmit = readFragment(c.submit_fragment, readSubmitFragment);
            result.fragment = revealFragment(c.password ? '' : c.seed, c.reveal_token);
            result.parsed = readFragment(c.view_fragment, readRevealFragment);
            if (c.password) {
                result.wrapped = await withRandom(
                    [bytes(c.salt), bytes(c.wrapped_key_iv)],
                    () => wrapPrivateKey(c.seed, c.password)
                );
                result.unwrapped = await unwrapPrivateKey(
                    c.wrapped_key, c.wrapped_key_iv, c.password, c.salt
                );
            }
        }
        results.push(result);
    }
    return results;
}"""


def _vectors(mode):
    vectors = json.loads((VECTORS / f"{mode}.json").read_text())
    assert vectors["format_version"] == 1
    assert vectors["mode"] == mode
    assert vectors["cases"]
    return vectors["cases"]


@pytest.mark.parametrize("mode", ["send", "password", "receive"])
def test_bundled_crypto_matches_format_vectors(page, app_url, mode):
    cases = _vectors(mode)
    page.goto(app_url)
    results = page.evaluate(_RUN_VECTORS, {"mode": mode, "cases": cases})
    for case, result in zip(cases, results, strict=True):
        assert result["authorization"] == {
            "token": case["reveal_token"],
            "tokenHash": case["reveal_token_hash"],
        }, case["name"]
        assert result["encrypted"]["ciphertext"] == case["ciphertext"], case["name"]
        assert result["encrypted"]["iv"] == case["iv"], case["name"]
        assert result["decrypted"] == case["plaintext"], case["name"]
        if mode == "receive":
            fragment = case["view_fragment"]
            assert result["keys"] == {
                "seedB64": case["seed"],
                "publicKeyB64": case["public_key"],
                "fingerprintB64": case["fingerprint"],
            }
            assert result["encrypted"]["encapsulated_key"] == case["encapsulated_key"]
            assert result["submitFragment"] == "#" + case["submit_fragment"]
            assert result["parsedSubmit"] == {
                "version": 1,
                "fingerprint": case["fingerprint"],
            }
            if "password" in case:
                assert result["wrapped"] == {
                    "wrappedKey": case["wrapped_key"],
                    "wrappedKeyIv": case["wrapped_key_iv"],
                    "salt": case["salt"],
                }
                assert result["unwrapped"] == case["seed"]
        else:
            fragment = case["fragment"]
        if mode == "password":
            assert result["encrypted"]["salt"] == case["salt"]
        assert result["fragment"] == "#" + fragment
        key = case["key"] if mode == "send" else ""
        if mode == "receive" and "password" not in case:
            key = case["seed"]
        assert result["parsed"] == {
            "version": 1,
            "key": key,
            "token": case["reveal_token"],
        }


@pytest.mark.parametrize("kind", ["send", "receive"])
def test_new_links_and_payloads_are_versioned(page, create_whisper, kind):
    bodies = []
    page.on(
        "request",
        lambda request: (
            bodies.append(json.loads(request.post_data))
            if "/api/v1/" in request.url
            else None
        ),
    )
    result = create_whisper(kind=kind)
    if kind == "receive":
        submit_url, url = result
        assert submit_url.split("#", 1)[1].startswith("v=1&fp=")
        _submit(page, submit_url)
    else:
        url = result
    assert url.split("#", 1)[1].startswith("v=1&reveal=")
    assert [body["v"] for body in bodies] == [1] * len(bodies)
    assert len(bodies) == (2 if kind == "receive" else 1)
    assert redis_store.get_crypto(Whisper.objects.get().id)["v"] == 1
    _reveal(page, url)
    expect(page.locator("#decrypted-content")).to_be_visible()


@pytest.mark.parametrize("kind", ["send", "receive"])
def test_unknown_link_version_is_rejected_before_reveal(page, create_whisper, kind):
    result = create_whisper(kind=kind)
    if kind == "receive":
        submit_url, url = result
        _submit(page, submit_url)
    else:
        url = result
    posts = []
    page.on(
        "request",
        lambda request: posts.append(request) if request.method == "POST" else None,
    )
    page.goto(url.replace("#v=1&", "#v=2&"))
    page.locator("#reveal-btn").click()
    expect(page.locator("#reveal-error")).to_contain_text("unsupported format version")
    assert not posts
    assert redis_store.get_view_count(Whisper.objects.get().id) == 0


def test_unknown_payload_version_is_not_decrypted(page, create_whisper):
    url = create_whisper(max_views=0)
    redis_store.update_crypto(Whisper.objects.get().id, v=2)
    _reveal(page, url)
    expect(page.locator("#error-message")).to_contain_text("unsupported format version")
    expect(page.locator("#decrypted-container")).to_be_hidden()


@pytest.mark.parametrize("legacy", [False, True])
def test_submit_link_versions(page, create_whisper, legacy):
    submit_url, url = create_whisper(kind="receive")
    base, current = submit_url.split("#", 1)
    fingerprint = parse_qs(current)["fp"][0]
    # Legacy submit links carry only the bare base64 fingerprint.
    fragment = fingerprint if legacy else urlencode({"v": 2, "fp": fingerprint})
    page.goto(base + "#" + fragment)
    page.locator("#whisper").fill("Submitted through another link version")
    page.locator("#submit-btn").click()
    if legacy:
        expect(page.locator("#submit-success")).to_be_visible()
        _reveal(page, url)
        expect(page.locator("#decrypted-content")).to_have_text(
            "Submitted through another link version"
        )
    else:
        expect(page.locator("#error")).to_contain_text("unsupported format version")
        assert not redis_store.get_crypto(Whisper.objects.get().id)["ciphertext"]


@pytest.mark.parametrize("legacy_link", [False, True])
def test_unknown_request_version_is_not_submitted(page, create_whisper, legacy_link):
    submit_url, _ = create_whisper(kind="receive")
    whisper = Whisper.objects.get()
    redis_store.update_crypto(whisper.id, v=2)
    if legacy_link:
        base, current = submit_url.split("#", 1)
        submit_url = base + "#" + parse_qs(current)["fp"][0]
    page.goto(submit_url)
    page.locator("#whisper").fill("Must not be submitted")
    page.locator("#submit-btn").click()
    expect(page.locator("#error")).to_contain_text("unsupported format version")
    stored = redis_store.get_crypto(whisper.id)
    assert (stored["v"], stored["ciphertext"]) == (2, "")


def test_mismatched_fingerprint_is_not_submitted(page, create_whisper):
    submit_url, _ = create_whisper(kind="receive")
    base = submit_url.split("#", 1)[0]
    # A well-formed fingerprint of a different key, as in a tampered link.
    other = _vectors("receive")[0]["fingerprint"]
    page.goto(base + "#" + urlencode({"v": 1, "fp": other}))
    page.locator("#whisper").fill("Must not be submitted")
    page.locator("#submit-btn").click()
    expect(page.locator("#error")).to_contain_text("does not match the link")
    assert not redis_store.get_crypto(Whisper.objects.get().id)["ciphertext"]
