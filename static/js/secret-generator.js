/**
 * psst-secret — Client-side secret generator.
 *
 * Generates random passwords and passphrases entirely in the browser. All
 * randomness comes from the Web Crypto CSPRNG (`crypto.getRandomValues`) with
 * rejection sampling, so every character, word, and position is chosen
 * uniformly without modulo bias. Nothing is sent to the server.
 *
 * The module exposes `window.PsstSecretGenerator`:
 *   - PRESETS                          Named, secure option sets (password, passphrase, whisperPassword).
 *   - generate(presetOrOptions, [overrides]) -> string
 *   - resolveOptions(presetOrOptions, [overrides]) -> normalized options
 *   - validate(options) -> null | error code
 *   - estimateEntropy(options) -> bits (number)
 *   - randomInt(max) -> uniform integer in [0, max)
 *   - mountDialog({ dialog, target, openButton, quickButton })
 *   - attachPresetButton({ button, input, preset, toggleButton })
 *   - attachVisibilityToggle({ button, input })
 *
 * Passphrase mode needs `window.PsstWordlistEN` (static/js/wordlist-en.js).
 */
(function () {
    'use strict';

    var UPPERCASE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    var LOWERCASE = 'abcdefghijklmnopqrstuvwxyz';
    var DIGITS = '0123456789';
    // Printable OWASP specials without quotes, backslash, backtick, and space,
    // which are easy to mangle when pasting into shells or config files.
    var SYMBOLS = '!#$%&()*+,-./:;<=>?@[]^_{|}~';
    var AMBIGUOUS = 'O0oIl1|';

    var LIMITS = {
        length: [8, 128],
        minCount: [0, 128],
        words: [3, 20],
        symbolCount: [0, 10],
        separator: 5,
    };

    var PRESETS = {
        password: {
            type: 'password',
            length: 20,
            uppercase: true,
            lowercase: true,
            digits: true,
            symbols: true,
            minUppercase: 1,
            minLowercase: 1,
            minDigits: 1,
            minSymbols: 1,
            avoidAmbiguous: true,
        },
        passphrase: {
            type: 'passphrase',
            words: 6,
            separator: '-',
            capitalize: true,
            includeNumber: true,
            symbolCount: 0,
            symbolPosition: 'end',
        },
        // Satisfies the "Set password" strength rules (see password-strength.js).
        whisperPassword: {
            type: 'password',
            length: 24,
            uppercase: true,
            lowercase: true,
            digits: true,
            symbols: true,
            minUppercase: 2,
            minLowercase: 2,
            minDigits: 2,
            minSymbols: 2,
            avoidAmbiguous: true,
        },
    };

    var CLASSES = [
        { flag: 'uppercase', min: 'minUppercase', chars: UPPERCASE },
        { flag: 'lowercase', min: 'minLowercase', chars: LOWERCASE },
        { flag: 'digits', min: 'minDigits', chars: DIGITS },
        { flag: 'symbols', min: 'minSymbols', chars: SYMBOLS },
    ];

    var gettext = typeof window.gettext === 'function' ? window.gettext : function (message) { return message; };

    // ---- Randomness -------------------------------------------------------

    function getCrypto() {
        var c = window.crypto;
        if (!c || typeof c.getRandomValues !== 'function') {
            throw new Error(gettext('Secure random number generation is not available in this browser.'));
        }
        return c;
    }

    var UINT32_RANGE = 0x100000000;

    /** Uniform random integer in [0, max) using rejection sampling. */
    function randomInt(max) {
        if (!Number.isInteger(max) || max < 1 || max > UINT32_RANGE) {
            throw new RangeError('randomInt: max must be an integer in [1, 2^32]');
        }
        var limit = UINT32_RANGE - (UINT32_RANGE % max);
        var buf = new Uint32Array(1);
        var c = getCrypto();
        do {
            c.getRandomValues(buf);
        } while (buf[0] >= limit);
        return buf[0] % max;
    }

    function pick(chars) {
        return chars.charAt(randomInt(chars.length));
    }

    function shuffle(items) {
        for (var i = items.length - 1; i > 0; i--) {
            var j = randomInt(i + 1);
            var tmp = items[i];
            items[i] = items[j];
            items[j] = tmp;
        }
        return items;
    }

    // ---- Options ----------------------------------------------------------

    function clampInt(value, range, fallback) {
        var n = parseInt(value, 10);
        if (isNaN(n)) n = fallback;
        return Math.min(range[1], Math.max(range[0], n));
    }

    function presetFor(name) {
        if (!Object.prototype.hasOwnProperty.call(PRESETS, name)) {
            throw new Error('Unknown secret generator preset: ' + name);
        }
        return PRESETS[name];
    }

    /**
     * Merge a preset name or options object (plus optional overrides) on top
     * of the secure defaults for its type and clamp every value to safe bounds.
     */
    function resolveOptions(presetOrOptions, overrides) {
        var base = typeof presetOrOptions === 'string' ? presetFor(presetOrOptions) : presetOrOptions || {};
        var merged = Object.assign({}, base, overrides || {});
        var type = merged.type === 'passphrase' ? 'passphrase' : 'password';
        var defaults = PRESETS[type];
        var o = Object.assign({}, defaults, merged, { type: type });

        if (type === 'password') {
            o.length = clampInt(o.length, LIMITS.length, defaults.length);
            CLASSES.forEach(function (cls) {
                o[cls.flag] = !!o[cls.flag];
                o[cls.min] = clampInt(o[cls.min], LIMITS.minCount, defaults[cls.min]);
            });
            o.avoidAmbiguous = !!o.avoidAmbiguous;
        } else {
            o.words = clampInt(o.words, LIMITS.words, defaults.words);
            o.separator = o.separator == null ? '' : String(o.separator).slice(0, LIMITS.separator);
            o.capitalize = !!o.capitalize;
            o.includeNumber = !!o.includeNumber;
            o.symbolCount = clampInt(o.symbolCount, LIMITS.symbolCount, defaults.symbolCount);
            o.symbolPosition = o.symbolPosition === 'random' ? 'random' : 'end';
        }
        return o;
    }

    function charsFor(cls, o) {
        if (!o.avoidAmbiguous) return cls.chars;
        return cls.chars.split('').filter(function (ch) {
            return AMBIGUOUS.indexOf(ch) === -1;
        }).join('');
    }

    function enabledClasses(o) {
        return CLASSES.filter(function (cls) { return o[cls.flag]; }).map(function (cls) {
            return { chars: charsFor(cls, o), min: o[cls.min] };
        });
    }

    function getWordlist() {
        var list = window.PsstWordlistEN;
        return Array.isArray(list) && list.length > 0 ? list : null;
    }

    /** Return null when the options can be generated, otherwise an error code. */
    function validate(options) {
        var o = resolveOptions(options);
        if (o.type === 'passphrase') {
            return getWordlist() ? null : 'wordlist-unavailable';
        }
        var classes = enabledClasses(o);
        if (classes.length === 0) return 'no-character-set';
        var required = classes.reduce(function (sum, cls) { return sum + cls.min; }, 0);
        if (required > o.length) return 'min-exceeds-length';
        return null;
    }

    function errorMessage(code) {
        switch (code) {
        case 'no-character-set': return gettext('Select at least one character type.');
        case 'min-exceeds-length': return gettext('The minimum counts add up to more than the length.');
        case 'wordlist-unavailable': return gettext('The word list could not be loaded.');
        default: return code ? String(code) : '';
        }
    }

    // ---- Generators -------------------------------------------------------

    function generatePassword(o) {
        var classes = enabledClasses(o);
        var pool = classes.map(function (cls) { return cls.chars; }).join('');
        var out = [];
        classes.forEach(function (cls) {
            for (var i = 0; i < cls.min; i++) out.push(pick(cls.chars));
        });
        while (out.length < o.length) out.push(pick(pool));
        return shuffle(out).join('');
    }

    function generatePassphrase(o) {
        var list = getWordlist();
        var words = [];
        for (var i = 0; i < o.words; i++) {
            var word = list[randomInt(list.length)];
            if (o.capitalize) word = word.charAt(0).toUpperCase() + word.slice(1);
            words.push(word);
        }
        if (o.includeNumber) {
            var idx = randomInt(words.length);
            words[idx] += pick(DIGITS);
        }
        var result = words.join(o.separator);
        for (var s = 0; s < o.symbolCount; s++) {
            var symbol = pick(SYMBOLS);
            if (o.symbolPosition === 'random') {
                var pos = randomInt(result.length + 1);
                result = result.slice(0, pos) + symbol + result.slice(pos);
            } else {
                result += symbol;
            }
        }
        return result;
    }

    /**
     * Generate a secret.
     * @param {string|Object} presetOrOptions  Preset name (see PRESETS) or options.
     * @param {Object} [overrides]             Options merged on top of the preset.
     */
    function generate(presetOrOptions, overrides) {
        var o = resolveOptions(presetOrOptions, overrides);
        var error = validate(o);
        if (error) {
            var err = new Error(errorMessage(error));
            err.code = error;
            throw err;
        }
        return o.type === 'passphrase' ? generatePassphrase(o) : generatePassword(o);
    }

    /**
     * Conservative entropy estimate in bits.
     *
     * Password mode counts the draws actually made: each required minimum is
     * drawn from its own class only, and the remaining positions from the full
     * pool. The final shuffle is not credited; for a fixed permutation the
     * output is a bijection of those draws, so the shuffle can only add
     * entropy and the sum is a lower bound.
     *
     * Passphrase mode counts words, the optional digit and its word position,
     * and the symbols, but not random symbol positions. It assumes word
     * boundaries are recoverable (a separator or capitalization); without
     * either, different word sequences can join into the same string.
     */
    function estimateEntropy(options) {
        var o = resolveOptions(options);
        if (validate(o)) return 0;
        if (o.type === 'password') {
            var classes = enabledClasses(o);
            var pool = classes.reduce(function (sum, cls) { return sum + cls.chars.length; }, 0);
            var required = 0;
            var bits = classes.reduce(function (sum, cls) {
                required += cls.min;
                return sum + cls.min * Math.log2(cls.chars.length);
            }, 0);
            return bits + (o.length - required) * Math.log2(pool);
        }
        var phraseBits = o.words * Math.log2(getWordlist().length);
        if (o.includeNumber) phraseBits += Math.log2(DIGITS.length) + Math.log2(o.words);
        phraseBits += o.symbolCount * Math.log2(SYMBOLS.length);
        return phraseBits;
    }

    // ---- UI helpers -------------------------------------------------------

    function fireInput(el) {
        el.dispatchEvent(new Event('input', { bubbles: true }));
    }

    /**
     * Insert `value` at the target's selection (replacing any selected text)
     * and leave the inserted secret selected, so generating again replaces it.
     */
    function insertIntoTarget(target, value) {
        if (typeof target.insertSecret === 'function') {
            target.insertSecret(value);
            return;
        }
        if (typeof target.setRangeText === 'function' && target.selectionStart != null) {
            var start = target.selectionStart;
            var end = target.selectionEnd;
            target.focus();
            target.setRangeText(value, start, end, 'select');
        } else {
            target.value = value;
            target.focus();
        }
        fireInput(target);
    }

    function clone(state) {
        return {
            mode: state.mode,
            password: Object.assign({}, state.password),
            passphrase: Object.assign({}, state.passphrase),
        };
    }

    function defaultState() {
        return {
            mode: 'password',
            password: resolveOptions('password'),
            passphrase: resolveOptions('passphrase'),
        };
    }

    /**
     * Wire the generator dialog.
     *
     * Expected markup inside `dialog` (a <dialog> element):
     *   [data-sg-tab="password|passphrase"]    nav buttons
     *   [data-sg-panel="password|passphrase"]  option panels
     *   [data-sg-option="<name>"]              inputs inside a panel (checkbox, number, range, select)
     *   [data-sg-min-for="<flag>"]             min-count inputs disabled when their class is off
     *   [data-sg-preview] [data-sg-entropy] [data-sg-error]
     *   [data-sg-regenerate] [data-sg-use] [data-sg-cancel] [data-sg-reset]
     *
     * @param {Object} opts
     * @param {HTMLDialogElement} opts.dialog
     * @param {HTMLInputElement|HTMLTextAreaElement} opts.target  Field that receives the secret.
     * @param {HTMLElement} [opts.openButton]   Opens the dialog.
     * @param {HTMLElement} [opts.quickButton]  Generates with the saved settings without opening the dialog.
     */
    function mountDialog(opts) {
        if (!opts || !opts.dialog || !opts.target) return null;
        var dialog = opts.dialog;
        var target = opts.target;
        var saved = defaultState();
        var draft = clone(saved);
        var preview = dialog.querySelector('[data-sg-preview]');
        var entropyEl = dialog.querySelector('[data-sg-entropy]');
        var errorEl = dialog.querySelector('[data-sg-error]');
        var useBtn = dialog.querySelector('[data-sg-use]');
        var regenBtn = dialog.querySelector('[data-sg-regenerate]');
        var tabs = Array.prototype.slice.call(dialog.querySelectorAll('[data-sg-tab]'));
        var panels = Array.prototype.slice.call(dialog.querySelectorAll('[data-sg-panel]'));
        var currentSecret = '';

        function controlsFor(mode) {
            var panel = dialog.querySelector('[data-sg-panel="' + mode + '"]');
            return panel ? Array.prototype.slice.call(panel.querySelectorAll('[data-sg-option]')) : [];
        }

        function writeControls() {
            ['password', 'passphrase'].forEach(function (mode) {
                var values = draft[mode];
                controlsFor(mode).forEach(function (el) {
                    var name = el.getAttribute('data-sg-option');
                    if (el.type === 'checkbox') el.checked = !!values[name];
                    else el.value = String(values[name]);
                });
            });
        }

        function isNumeric(el) {
            return el.type === 'number' || el.type === 'range';
        }

        function readControls(source) {
            var mode = draft.mode;
            var sourceName = source ? source.getAttribute('data-sg-option') : null;
            var values = Object.assign({}, draft[mode]);
            controlsFor(mode).forEach(function (el) {
                var name = el.getAttribute('data-sg-option');
                // A slider and number box can share one option; the edited one wins.
                if (name === sourceName && el !== source) return;
                // Keep the previous value while a number box is being cleared and retyped.
                if (isNumeric(el) && el.value === '') return;
                values[name] = el.type === 'checkbox' ? el.checked : el.value;
            });
            draft[mode] = resolveOptions(Object.assign(values, { type: mode }));
            // Mirror clamped values into the other controls without fighting the user's typing.
            controlsFor(mode).forEach(function (el) {
                if (el !== source && isNumeric(el)) el.value = String(draft[mode][el.getAttribute('data-sg-option')]);
            });
        }

        function renderMode() {
            tabs.forEach(function (tab) {
                var active = tab.getAttribute('data-sg-tab') === draft.mode;
                tab.setAttribute('aria-selected', active ? 'true' : 'false');
                tab.classList.toggle('bg-brand-600', active);
                tab.classList.toggle('text-white', active);
                tab.classList.toggle('bg-gray-800', !active);
                tab.classList.toggle('text-gray-400', !active);
            });
            panels.forEach(function (panel) {
                panel.classList.toggle('hidden', panel.getAttribute('data-sg-panel') !== draft.mode);
            });
            dialog.querySelectorAll('[data-sg-min-for]').forEach(function (el) {
                el.disabled = !draft.password[el.getAttribute('data-sg-min-for')];
            });
        }

        function regenerate() {
            var options = draft[draft.mode];
            var error = validate(options);
            if (errorEl) {
                errorEl.textContent = error ? errorMessage(error) : '';
                errorEl.classList.toggle('hidden', !error);
            }
            currentSecret = error ? '' : generate(options);
            if (preview) preview.textContent = currentSecret;
            if (useBtn) useBtn.disabled = !!error;
            if (entropyEl) {
                var bits = Math.floor(estimateEntropy(options));
                entropyEl.textContent = error ? '' : interpolateBits(bits);
                entropyEl.classList.remove('text-red-400', 'text-amber-400', 'text-green-400');
                entropyEl.classList.add(bits < 60 ? 'text-red-400' : bits < 80 ? 'text-amber-400' : 'text-green-400');
            }
        }

        function interpolateBits(bits) {
            var tmpl = gettext('Estimated strength: ≈ %(bits)s bits');
            if (typeof window.interpolate === 'function') return window.interpolate(tmpl, { bits: bits }, true);
            return tmpl.replace('%(bits)s', String(bits));
        }

        function open() {
            draft = clone(saved);
            writeControls();
            renderMode();
            regenerate();
            if (typeof dialog.showModal === 'function') dialog.showModal();
            else dialog.setAttribute('open', '');
        }

        function close() {
            if (typeof dialog.close === 'function') dialog.close();
            else dialog.removeAttribute('open');
        }

        tabs.forEach(function (tab) {
            tab.addEventListener('click', function (ev) {
                ev.preventDefault();
                draft.mode = tab.getAttribute('data-sg-tab');
                renderMode();
                regenerate();
            });
        });

        ['password', 'passphrase'].forEach(function (mode) {
            controlsFor(mode).forEach(function (el) {
                var handler = function () {
                    readControls(el);
                    renderMode();
                    regenerate();
                };
                el.addEventListener(el.type === 'checkbox' || el.tagName === 'SELECT' ? 'change' : 'input', handler);
                if (el.type === 'number') {
                    el.addEventListener('change', function () {
                        el.value = String(draft[mode][el.getAttribute('data-sg-option')]);
                    });
                }
            });
        });

        if (regenBtn) regenBtn.addEventListener('click', function (ev) { ev.preventDefault(); regenerate(); });

        var resetBtn = dialog.querySelector('[data-sg-reset]');
        if (resetBtn) {
            resetBtn.addEventListener('click', function (ev) {
                ev.preventDefault();
                var mode = draft.mode;
                draft[mode] = resolveOptions(mode);
                writeControls();
                renderMode();
                regenerate();
            });
        }

        dialog.querySelectorAll('[data-sg-cancel]').forEach(function (btn) {
            btn.addEventListener('click', function (ev) { ev.preventDefault(); close(); });
        });

        if (useBtn) {
            useBtn.addEventListener('click', function (ev) {
                ev.preventDefault();
                if (!currentSecret) return;
                saved = clone(draft);
                var secret = currentSecret;
                close();
                insertIntoTarget(target, secret);
            });
        }

        dialog.addEventListener('close', function () {
            currentSecret = '';
            if (preview) preview.textContent = '';
        });

        if (opts.openButton) {
            opts.openButton.addEventListener('click', function (ev) { ev.preventDefault(); open(); });
        }
        if (opts.quickButton) {
            opts.quickButton.addEventListener('click', function (ev) {
                ev.preventDefault();
                insertIntoTarget(target, generate(saved[saved.mode]));
            });
        }

        return { open: open, close: close };
    }

    /**
     * Toggle an <input> between type="password" and type="text". The button
     * label comes from its data-label-show / data-label-hide attributes.
     */
    function attachVisibilityToggle(opts) {
        if (!opts || !opts.button || !opts.input) return null;
        var button = opts.button;
        var input = opts.input;

        function render() {
            var visible = input.type === 'text';
            var label = button.getAttribute(visible ? 'data-label-hide' : 'data-label-show');
            if (label) {
                button.setAttribute('aria-label', label);
                button.setAttribute('title', label);
            }
            button.setAttribute('aria-pressed', visible ? 'true' : 'false');
        }

        function setVisible(visible) {
            input.type = visible ? 'text' : 'password';
            render();
        }

        button.addEventListener('click', function (ev) {
            ev.preventDefault();
            setVisible(input.type !== 'text');
        });
        render();
        return { setVisible: setVisible };
    }

    /**
     * Fill an input with a secret generated from a preset. When a toggle
     * button is provided, the field is revealed so the user can copy it.
     */
    function attachPresetButton(opts) {
        if (!opts || !opts.button || !opts.input) return;
        var toggle = opts.toggleButton ? attachVisibilityToggle({ button: opts.toggleButton, input: opts.input }) : null;
        opts.button.addEventListener('click', function (ev) {
            ev.preventDefault();
            opts.input.value = generate(opts.preset || 'whisperPassword', opts.overrides);
            if (toggle) toggle.setVisible(true);
            fireInput(opts.input);
            opts.input.focus();
            opts.input.select();
        });
    }

    window.PsstSecretGenerator = Object.freeze({
        PRESETS: Object.freeze(Object.keys(PRESETS).reduce(function (acc, key) {
            acc[key] = Object.freeze(Object.assign({}, PRESETS[key]));
            return acc;
        }, {})),
        CHARSETS: Object.freeze({
            uppercase: UPPERCASE,
            lowercase: LOWERCASE,
            digits: DIGITS,
            symbols: SYMBOLS,
            ambiguous: AMBIGUOUS,
        }),
        LIMITS: LIMITS,
        generate: generate,
        resolveOptions: resolveOptions,
        validate: validate,
        errorMessage: errorMessage,
        estimateEntropy: estimateEntropy,
        randomInt: randomInt,
        mountDialog: mountDialog,
        attachPresetButton: attachPresetButton,
        attachVisibilityToggle: attachVisibilityToggle,
    });
})();
