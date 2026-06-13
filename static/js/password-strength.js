/**
 * psst-secret — Interactive password-strength checker.
 *
 * Pure client-side validation (the server never sees the whisper passphrase).
 * Used to enforce strong passphrases on the create flow.
 *
 * Rules (all required when the password is non-empty):
 *   - >= 14 characters
 *   - >= 1 uppercase letter (A-Z)
 *   - >= 1 lowercase letter (a-z)
 *   - >= 1 digit (0-9)
 *   - >= 1 OWASP special character: ! " # $ % & ' ( ) * + , - . / : ; < = > ? @ [ \ ] ^ _ ` { | } ~ and space
 *
 * The module exposes `window.PsstPasswordStrength` with two methods:
 *   - evaluate(password) -> { length, upper, lower, digit, special, allOk, isEmpty }
 *   - attach({ inputEl, listEl, statusEl, criteriaLabels, buttons })
 *
 * All visible strings are passed in via `criteriaLabels` so that translation
 * (Django {% trans %}) lives in templates, not in JS.
 */
(function () {
    'use strict';

    var MIN_LENGTH = 14;

    // OWASP printable special-character set (RFC 2898 / OWASP ASVS).
    // Includes the space character.
    var SPECIAL_RE = /[ !"#$%&'()*+,\-./:;<=>?@[\\\]^_`{|}~]/;

    function evaluate(password) {
        var pwd = password == null ? '' : String(password);
        var checks = {
            length: pwd.length >= MIN_LENGTH,
            upper: /[A-Z]/.test(pwd),
            lower: /[a-z]/.test(pwd),
            digit: /[0-9]/.test(pwd),
            special: SPECIAL_RE.test(pwd),
            isEmpty: pwd.length === 0,
        };
        checks.allOk =
            checks.length &&
            checks.upper &&
            checks.lower &&
            checks.digit &&
            checks.special;
        return checks;
    }

    var BLOCK_ATTR = 'data-psst-strength-block';

    function setButtonBlocked(btn, blocked) {
        if (!btn) return;
        if (blocked) {
            btn.setAttribute(BLOCK_ATTR, '1');
            btn.disabled = true;
        } else if (btn.getAttribute(BLOCK_ATTR) === '1') {
            // Only clear `disabled` when WE are the ones who set it.
            // Other code paths (e.g. handleCreate's in-flight state) toggle
            // `disabled` directly and we must not race with them.
            btn.removeAttribute(BLOCK_ATTR);
            btn.disabled = false;
        }
    }

    /**
     * Wire interactive strength UI to an input field.
     *
     * @param {Object} opts
     * @param {HTMLInputElement} opts.inputEl   Password input.
     * @param {HTMLUListElement}  opts.listEl   <ul> containing one <li> per rule.
     *                                          Each <li> must carry data-rule="length|upper|lower|digit|special".
     *                                          Each <li> must contain a child with class "psst-strength-icon".
     * @param {HTMLElement}       [opts.statusEl] Optional single-line status element.
     * @param {Object}            opts.criteriaLabels  Translated strings:
     *                              { ok, fail, neutral, statusEmpty, statusOk, statusMissing }
     *                              `statusMissing` is a format string containing "{count}".
     * @param {HTMLButtonElement[]} [opts.buttons]  Buttons to disable while invalid.
     */
    function attach(opts) {
        if (!opts || !opts.inputEl || !opts.listEl) return;

        var input = opts.inputEl;
        var list = opts.listEl;
        var statusEl = opts.statusEl || null;
        var labels = opts.criteriaLabels || {};
        var buttons = Array.isArray(opts.buttons) ? opts.buttons : [];

        var ICON_OK = labels.ok || '\u2713';        // ✓
        var ICON_FAIL = labels.fail || '\u2717';    // ✗
        var ICON_NEUTRAL = labels.neutral || '\u00B7'; // ·

        var items = {};
        ['length', 'upper', 'lower', 'digit', 'special'].forEach(function (rule) {
            var li = list.querySelector('[data-rule="' + rule + '"]');
            if (li) items[rule] = li;
        });

        function renderRule(rule, ok, isEmpty) {
            var li = items[rule];
            if (!li) return;
            var icon = li.querySelector('.psst-strength-icon');
            li.classList.remove(
                'text-green-400', 'text-red-400', 'text-gray-500'
            );
            if (isEmpty) {
                li.classList.add('text-gray-500');
                if (icon) icon.textContent = ICON_NEUTRAL;
            } else if (ok) {
                li.classList.add('text-green-400');
                if (icon) icon.textContent = ICON_OK;
            } else {
                li.classList.add('text-red-400');
                if (icon) icon.textContent = ICON_FAIL;
            }
        }

        function render() {
            var result = evaluate(input.value);
            renderRule('length', result.length, result.isEmpty);
            renderRule('upper', result.upper, result.isEmpty);
            renderRule('lower', result.lower, result.isEmpty);
            renderRule('digit', result.digit, result.isEmpty);
            renderRule('special', result.special, result.isEmpty);

            if (statusEl) {
                statusEl.classList.remove(
                    'text-green-400', 'text-red-400', 'text-gray-500'
                );
                if (result.isEmpty) {
                    statusEl.textContent = labels.statusEmpty || '';
                    statusEl.classList.add('text-gray-500');
                } else if (result.allOk) {
                    statusEl.textContent = labels.statusOk || '';
                    statusEl.classList.add('text-green-400');
                } else {
                    var missing = 0;
                    ['length', 'upper', 'lower', 'digit', 'special'].forEach(
                        function (r) { if (!result[r]) missing += 1; }
                    );
                    var tmpl = labels.statusMissing || '';
                    statusEl.textContent = tmpl
                        .replace('{count}', String(missing))
                        .replace('{total}', '5');
                    statusEl.classList.add('text-red-400');
                }
            }

            // Empty passphrase is allowed (the field is optional).
            var blocked = !result.isEmpty && !result.allOk;
            buttons.forEach(function (b) { setButtonBlocked(b, blocked); });
        }

        input.addEventListener('input', render);
        // Initial paint (e.g. when browsers restore the value on back/forward).
        render();
    }

    window.PsstPasswordStrength = {
        evaluate: evaluate,
        attach: attach,
        MIN_LENGTH: MIN_LENGTH,
    };
})();
