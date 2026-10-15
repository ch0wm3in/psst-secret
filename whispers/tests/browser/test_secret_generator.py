import re
from urllib.parse import urlsplit

import pytest
from playwright.sync_api import expect

from whispers.tests.browser.test_flows import _reveal, _submit

pytestmark = pytest.mark.browser

AMBIGUOUS = re.compile(r"[O0oIl1|]")
SYMBOLS = "!#$%&()*+,-./:;<=>?@[]^_{|}~"
SYMBOL_CLASS = "[" + re.escape(SYMBOLS) + "]"


def _assert_default_password(value, length=20):
    assert len(value) == length
    assert re.search(r"[A-Z]", value)
    assert re.search(r"[a-z]", value)
    assert re.search(r"[0-9]", value)
    assert re.search(SYMBOL_CLASS, value)
    assert not AMBIGUOUS.search(value)
    assert re.fullmatch(r"[A-Za-z0-9" + re.escape(SYMBOLS) + "]+", value)


def _open_generator(page):
    page.locator("#generate-secret-options-btn").click()
    dialog = page.locator("#secret-generator")
    expect(dialog).to_be_visible()
    expect(page.locator("#sg-preview")).not_to_be_empty()
    return dialog


def test_quick_generate_inserts_secure_password(page, app_url):
    page.goto(app_url)
    whisper = page.locator("#whisper")
    page.locator("#generate-secret-btn").click()
    first = whisper.input_value()
    _assert_default_password(first)

    # The inserted secret stays selected, so generating again replaces it.
    page.locator("#generate-secret-btn").click()
    second = whisper.input_value()
    _assert_default_password(second)
    assert second != first

    # Generated secrets are inserted at the cursor, keeping surrounding text.
    whisper.fill("username: alice\npassword: ")
    whisper.press("End")
    page.locator("#generate-secret-btn").click()
    value = whisper.input_value()
    assert value.startswith("username: alice\npassword: ")
    _assert_default_password(value.removeprefix("username: alice\npassword: "))

    page.locator("#encrypt-btn").click()
    expect(page.locator("#result")).to_be_visible()
    _reveal(page, page.locator("#result-url").input_value())
    expect(page.locator("#decrypted-content")).to_have_text(value)


def test_generator_hidden_in_receive_mode(page, app_url):
    page.goto(app_url)
    expect(page.locator("#generate-secret-btn")).to_be_visible()
    page.locator("#tab-receive").click()
    expect(page.locator("#generate-secret-btn")).to_be_hidden()
    expect(page.locator("#generate-secret-options-btn")).to_be_hidden()


def test_dialog_password_options(page, app_url):
    page.goto(app_url)
    dialog = _open_generator(page)
    preview = page.locator("#sg-preview")
    _assert_default_password(preview.text_content())
    expect(page.locator("#sg-tab-password")).to_have_attribute("aria-selected", "true")
    expect(page.locator("#sg-entropy")).to_contain_text("bits")

    page.locator("#sg-length").fill("32")
    expect(page.locator("#sg-length-range")).to_have_value("32")
    assert len(preview.text_content()) == 32

    page.locator("#sg-length-range").fill("40")
    expect(page.locator("#sg-length")).to_have_value("40")
    assert len(preview.text_content()) == 40

    page.locator("#sg-symbols").uncheck()
    page.locator("#sg-digits").uncheck()
    expect(page.locator("#sg-min-symbols")).to_be_disabled()
    expect(preview).to_have_text(re.compile(r"^[A-Za-z]{40}$"))

    page.locator("#sg-avoid-ambiguous").uncheck()
    page.locator("#sg-uppercase").uncheck()
    page.locator("#sg-lowercase").uncheck()
    expect(page.locator("#sg-error")).to_have_text(
        "Select at least one character type."
    )
    expect(page.locator("#sg-use")).to_be_disabled()
    expect(preview).to_be_empty()

    page.locator("#sg-digits").check()
    page.locator("#sg-min-digits").fill("50")
    expect(page.locator("#sg-error")).to_contain_text("more than the length")
    page.locator("#sg-min-digits").fill("40")
    expect(page.locator("#sg-error")).to_be_hidden()
    expect(preview).to_have_text(re.compile(r"^[0-9]{40}$"))

    page.locator("#sg-min-digits").fill("2")
    page.locator("#sg-lowercase").check()
    page.locator("#sg-min-lowercase").fill("5")
    expect(preview).to_have_text(re.compile(r"^[a-z0-9]{40}$"))
    page.locator("[data-sg-regenerate]").click()
    secret = preview.text_content()
    assert len(re.findall(r"[0-9]", secret)) >= 2
    assert len(re.findall(r"[a-z]", secret)) >= 5

    page.locator("#sg-use").click()
    expect(dialog).to_be_hidden()
    expect(page.locator("#whisper")).to_have_value(secret)

    # The quick button now reuses the saved settings.
    page.locator("#whisper").fill("")
    page.locator("#generate-secret-btn").click()
    expect(page.locator("#whisper")).to_have_value(re.compile(r"^[a-z0-9]{40}$"))

    _open_generator(page)
    expect(page.locator("#sg-length")).to_have_value("40")
    page.locator("[data-sg-reset]").click()
    expect(page.locator("#sg-length")).to_have_value("20")
    _assert_default_password(preview.text_content())


def test_dialog_passphrase_options_and_cancel(page, app_url):
    page.goto(app_url)
    dialog = _open_generator(page)
    preview = page.locator("#sg-preview")
    page.locator("#sg-tab-passphrase").click()
    expect(page.locator("#sg-panel-passphrase")).to_be_visible()
    expect(page.locator("#sg-panel-password")).to_be_hidden()
    expect(preview).to_have_text(re.compile(r"^[A-Z][a-z-]*\d?(-[A-Z][a-z-]*\d?){5}$"))
    assert len(re.findall(r"\d", preview.text_content())) == 1

    page.locator("#sg-words").fill("4")
    page.locator("#sg-separator").select_option(".")
    page.locator("#sg-capitalize").check()
    page.locator("#sg-include-number").check()
    page.locator("#sg-symbol-count").fill("2")
    secret = preview.text_content()
    assert re.fullmatch(
        r"([A-Z][a-z-]*\d?\.){3}[A-Z][a-z-]*\d?" + SYMBOL_CLASS + "{2}", secret
    )
    assert len(re.findall(r"\d", secret)) == 1
    words = [re.sub(r"\d", "", word).lower() for word in secret[:-2].split(".")]
    assert page.evaluate(
        "words => words.every(word => window.PsstWordlistEN.includes(word))", words
    )

    page.locator("#sg-separator").select_option("")
    page.locator("#sg-include-number").uncheck()
    page.locator("#sg-symbol-count").fill("3")
    page.locator("#sg-symbol-position").select_option("random")
    page.locator("[data-sg-regenerate]").click()
    secret = preview.text_content()
    assert re.fullmatch(r"[A-Za-z" + re.escape(SYMBOLS) + "]+", secret)
    assert len(re.findall(r"[A-Z]", secret)) == 4
    assert len(re.sub(r"[A-Za-z]", "", secret)) >= 3

    # Cancelling discards both the secret and the changed settings.
    page.get_by_role("button", name="Cancel", exact=True).click()
    expect(dialog).to_be_hidden()
    expect(page.locator("#whisper")).to_have_value("")
    _open_generator(page)
    expect(page.locator("#sg-tab-password")).to_have_attribute("aria-selected", "true")
    page.keyboard.press("Escape")
    expect(dialog).to_be_hidden()
    expect(page.locator("#whisper")).to_have_value("")

    _open_generator(page)
    page.locator("#sg-tab-passphrase").click()
    secret = preview.text_content()
    page.locator("#sg-use").click()
    expect(page.locator("#whisper")).to_have_value(secret)


@pytest.mark.parametrize("kind", ["send", "receive"])
def test_password_field_generator(page, app_url, kind):
    page.goto(app_url)
    if kind == "receive":
        page.locator("#tab-receive").click()
    page.locator("#advanced-options summary").click()
    password = page.locator("#password")
    expect(password).to_have_attribute("type", "password")
    page.locator("#password-generate-btn").click()
    expect(password).to_have_attribute("type", "text")
    value = password.input_value()
    _assert_default_password(value, length=24)
    expect(page.locator("#password-strength-status")).to_contain_text(
        "all requirements met"
    )
    assert page.evaluate(
        "value => window.PsstPasswordStrength.evaluate(value).allOk", value
    )

    toggle = page.locator("#password-visibility-btn")
    expect(toggle).to_have_attribute("aria-label", "Hide password")
    toggle.click()
    expect(password).to_have_attribute("type", "password")
    expect(toggle).to_have_attribute("aria-label", "Show password")

    if kind == "receive":
        page.locator("#request-btn").click()
        expect(page.locator("#receive-result")).to_be_visible()
        submit_url = page.locator("#submit-url").input_value()
        url = page.locator("#view-url").input_value()
        _submit(page, submit_url, content="Reply protected by a generated password")
        plaintext = "Reply protected by a generated password"
    else:
        plaintext = "Protected by a generated password"
        page.locator("#whisper").fill(plaintext)
        page.locator("#encrypt-btn").click()
        expect(page.locator("#result")).to_be_visible()
        url = page.locator("#result-url").input_value()
    assert not urlsplit(url).fragment
    _reveal(page, url)
    page.locator("#view-password").fill(value)
    page.get_by_role("button", name="Decrypt", exact=True).click()
    expect(page.locator("#decrypted-content")).to_have_text(plaintext)


def test_generator_api_presets(page, app_url):
    page.goto(app_url)
    result = page.evaluate("""() => {
        const G = window.PsstSecretGenerator;
        const strength = window.PsstPasswordStrength;
        const passwords = Array.from({length: 300}, () => G.generate('password'));
        const whisperPasswords = Array.from({length: 300}, () => G.generate('whisperPassword'));
        const counts = new Array(6).fill(0);
        for (let i = 0; i < 6000; i++) counts[G.randomInt(6)]++;
        const errors = {};
        for (const [name, options] of Object.entries({
            none: {type: 'password', uppercase: false, lowercase: false, digits: false, symbols: false},
            tooMany: {type: 'password', length: 8, minDigits: 5, minSymbols: 5},
        })) {
            try { G.generate(options); } catch (e) { errors[name] = e.code; }
        }
        let unknown = null;
        try { G.generate('nope'); } catch (e) { unknown = e.message; }
        return {
            passwords,
            whisperPasswords,
            allStrong: whisperPasswords.every(p => strength.evaluate(p).allOk),
            unique: new Set(passwords).size,
            counts,
            errors,
            unknown,
            passphrase: G.generate('passphrase', {words: 3, separator: ' '}),
            clampedLength: G.resolveOptions({type: 'password', length: 1000}).length,
            clampedWords: G.resolveOptions('passphrase', {words: 1}).words,
            entropy: Math.round(G.estimateEntropy('passphrase')),
            frozen: Object.isFrozen(G.PRESETS.password),
            wordlist: window.PsstWordlistEN.length,
        };
    }""")
    for value in result["passwords"]:
        _assert_default_password(value)
    for value in result["whisperPasswords"]:
        _assert_default_password(value, length=24)
    assert result["allStrong"]
    assert result["unique"] == 300
    assert all(800 < count < 1200 for count in result["counts"])
    assert result["errors"] == {
        "none": "no-character-set",
        "tooMany": "min-exceeds-length",
    }
    assert "Unknown secret generator preset" in result["unknown"]
    assert re.fullmatch(r"[A-Z][a-z-]*\d?( [A-Z][a-z-]*\d?){2}", result["passphrase"])
    assert result["clampedLength"] == 128
    assert result["clampedWords"] == 3
    assert result["entropy"] == 83
    assert result["frozen"]
    assert result["wordlist"] == 7776
