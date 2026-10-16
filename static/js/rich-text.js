/**
 * Markdown WYSIWYG editor for whisper content, built on the Tiptap bundle
 * (theme/static/js/tiptap.min.js). Everything runs in the browser; the
 * markdown is mirrored into the original <textarea> so crypto.js encrypts it
 * exactly like plain text.
 *
 * Public API (window.PsstRichText):
 *   - mount(root)          Enhance a [data-rich-editor="<textarea id>"] wrapper.
 *   - render(el, markdown) Render markdown read-only into `el`.
 */
(function () {
    'use strict';

    // Only these link targets survive parsing, pasting, and rendering.
    var SAFE_URL = /^(https?:\/\/|mailto:)/i;
    var MODE_KEY = 'psst-editor-mode';
    var PLAIN_TEXTAREA_CLASS = 'w-full min-h-48 resize-y bg-transparent px-4 py-3 font-mono text-sm text-gray-100 placeholder-gray-500 focus:outline-none';

    function isSafeUrl(url) {
        return SAFE_URL.test(String(url || '').trim());
    }

    function extensions(T, extra) {
        return [
            T.StarterKit.configure({
                heading: { levels: [1, 2, 3] },
                underline: false,
                trailingNode: false,
                link: {
                    openOnClick: false,
                    autolink: true,
                    defaultProtocol: 'https',
                    isAllowedUri: isSafeUrl,
                    HTMLAttributes: { rel: 'noopener noreferrer nofollow', target: '_blank' },
                },
            }),
            T.Markdown,
        ].concat(extra || []);
    }

    function normalizeUrl(url) {
        url = url.trim();
        if (url && !/^[a-z][a-z0-9+.-]*:/i.test(url)) url = 'https://' + url;
        return url;
    }

    function attachLinkDialog(editor, dialog) {
        var form = dialog.querySelector('form');
        var urlInput = dialog.querySelector('[data-link-url]');
        var textRow = dialog.querySelector('[data-link-text-row]');
        var textInput = dialog.querySelector('[data-link-text]');
        var error = dialog.querySelector('[data-link-error]');
        var removeButton = dialog.querySelector('[data-link-remove]');
        var insertsText = false;

        function close() {
            dialog.close();
        }

        form.addEventListener('submit', function (event) {
            event.preventDefault();
            var url = normalizeUrl(urlInput.value);
            var chain = editor.chain().focus().extendMarkRange('link');
            if (!url) {
                chain.unsetLink().run();
                close();
                return;
            }
            if (!isSafeUrl(url)) {
                error.hidden = false;
                urlInput.setAttribute('aria-invalid', 'true');
                urlInput.focus();
                return;
            }
            if (insertsText) {
                var text = textInput.value.trim() || url;
                chain.insertContent({ type: 'text', text: text, marks: [{ type: 'link', attrs: { href: url } }] }).run();
            } else {
                chain.setLink({ href: url }).run();
            }
            close();
        });
        urlInput.addEventListener('input', function () {
            error.hidden = true;
            urlInput.removeAttribute('aria-invalid');
        });
        removeButton.addEventListener('click', function () {
            editor.chain().focus().extendMarkRange('link').unsetLink().run();
            close();
        });
        dialog.querySelectorAll('[data-link-cancel]').forEach(function (button) {
            button.addEventListener('click', close);
        });
        dialog.addEventListener('close', function () {
            editor.commands.focus();
        });

        return function open() {
            var current = editor.getAttributes('link').href || '';
            insertsText = editor.state.selection.empty && !editor.isActive('link');
            urlInput.value = current;
            textInput.value = '';
            textRow.hidden = !insertsText;
            removeButton.hidden = !current;
            error.hidden = true;
            urlInput.removeAttribute('aria-invalid');
            dialog.showModal();
            urlInput.focus();
        };
    }

    var COMMANDS = {
        bold: { run: function (c) { return c.toggleBold(); }, active: 'bold' },
        italic: { run: function (c) { return c.toggleItalic(); }, active: 'italic' },
        strike: { run: function (c) { return c.toggleStrike(); }, active: 'strike' },
        code: { run: function (c) { return c.toggleCode(); }, active: 'code' },
        paragraph: { run: function (c) { return c.setParagraph(); }, active: 'paragraph' },
        h1: { run: function (c) { return c.toggleHeading({ level: 1 }); }, active: ['heading', { level: 1 }] },
        h2: { run: function (c) { return c.toggleHeading({ level: 2 }); }, active: ['heading', { level: 2 }] },
        h3: { run: function (c) { return c.toggleHeading({ level: 3 }); }, active: ['heading', { level: 3 }] },
        bulletList: { run: function (c) { return c.toggleBulletList(); }, active: 'bulletList' },
        orderedList: { run: function (c) { return c.toggleOrderedList(); }, active: 'orderedList' },
        blockquote: { run: function (c) { return c.toggleBlockquote(); }, active: 'blockquote' },
        codeBlock: { run: function (c) { return c.toggleCodeBlock(); }, active: 'codeBlock' },
    };

    function isActive(editor, active) {
        return Array.isArray(active) ? editor.isActive(active[0], active[1]) : editor.isActive(active);
    }

    function mount(root) {
        var T = window.PsstTiptap;
        var textarea = document.getElementById(root.getAttribute('data-rich-editor'));
        if (!T || !textarea) return null;

        var counter = root.querySelector('[data-rich-editor-count]');
        var content = root.querySelector('[data-rich-editor-content]');
        var formatting = root.querySelector('[data-rich-editor-formatting]');
        var modeToggle = root.querySelector('[data-editor-mode-toggle]');
        var buttons = Array.prototype.slice.call(root.querySelectorAll('[data-command]'));
        var plain = false;
        var editor = new T.Editor({
            element: content,
            extensions: extensions(T, [
                T.Placeholder.configure({ placeholder: textarea.placeholder }),
                T.CharacterCount,
            ]),
            content: textarea.value,
            contentType: 'markdown',
            editorProps: {
                attributes: {
                    class: 'psst-editor psst-prose',
                    role: 'textbox',
                    'aria-multiline': 'true',
                    'aria-label': gettext('Whisper content'),
                },
            },
        });
        var openLinkDialog = attachLinkDialog(
            editor,
            document.querySelector('[data-link-dialog="' + textarea.id + '"]')
        );

        function updateCount(count) {
            if (counter) {
                counter.textContent = interpolate(ngettext('%s character', '%s characters', count), [count]);
            }
        }

        function sync() {
            if (plain) return;
            textarea.value = editor.isEmpty ? '' : editor.getMarkdown().trimEnd();
            updateCount(editor.storage.characterCount.characters());
            buttons.forEach(function (button) {
                var name = button.getAttribute('data-command');
                if (name === 'unlink') {
                    button.disabled = !editor.isActive('link');
                } else if (name === 'link') {
                    button.setAttribute('aria-pressed', String(editor.isActive('link')));
                } else if (COMMANDS[name]) {
                    button.setAttribute('aria-pressed', String(isActive(editor, COMMANDS[name].active)));
                }
            });
        }

        buttons.forEach(function (button) {
            button.addEventListener('click', function () {
                var name = button.getAttribute('data-command');
                if (name === 'link') {
                    openLinkDialog();
                } else if (name === 'unlink') {
                    editor.chain().focus().extendMarkRange('link').unsetLink().run();
                } else if (COMMANDS[name]) {
                    COMMANDS[name].run(editor.chain().focus()).run();
                }
            });
        });

        // Lets the secret generator insert plain text instead of writing the hidden textarea.
        // The secret stays selected so generating again replaces it.
        function insertSecret(value) {
            var start = editor.state.selection.from;
            editor.chain().focus().insertContent({ type: 'text', text: value }).run();
            editor.commands.setTextSelection({ from: start, to: editor.state.selection.to });
        }

        function setPlain(value) {
            plain = value;
            if (!plain) {
                editor.commands.setContent(textarea.value, { contentType: 'markdown' });
            }
            textarea.hidden = !plain;
            content.hidden = plain;
            formatting.hidden = plain;
            modeToggle.setAttribute('aria-pressed', String(plain));
            if (plain) {
                delete textarea.dataset.format;
                delete textarea.insertSecret;
                updateCount(textarea.value.length);
            } else {
                textarea.dataset.format = 'markdown';
                textarea.insertSecret = insertSecret;
                sync();
            }
            try {
                window.localStorage.setItem(MODE_KEY, plain ? 'plain' : 'formatted');
            } catch (e) { /* storage may be unavailable */ }
        }

        // The textarea moves inside the editor frame so both modes share one box.
        textarea.className = PLAIN_TEXTAREA_CLASS;
        content.after(textarea);
        textarea.addEventListener('input', function () {
            if (plain) updateCount(textarea.value.length);
        });
        modeToggle.addEventListener('click', function () {
            setPlain(!plain);
            if (plain) {
                textarea.focus();
            } else {
                editor.commands.focus();
            }
        });
        root.classList.remove('hidden');
        editor.on('transaction', sync);
        var saved = null;
        try {
            saved = window.localStorage.getItem(MODE_KEY);
        } catch (e) { /* storage may be unavailable */ }
        setPlain(saved === 'plain');
        return editor;
    }

    function render(el, markdown) {
        var T = window.PsstTiptap;
        if (!T) return null;
        return new T.Editor({
            element: el,
            extensions: extensions(T),
            content: markdown,
            contentType: 'markdown',
            editable: false,
            editorProps: { attributes: { class: 'psst-prose' } },
        });
    }

    window.PsstRichText = { mount: mount, render: render, isSafeUrl: isSafeUrl };

    document.querySelectorAll('[data-rich-editor]').forEach(mount);
})();
