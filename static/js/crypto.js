/**
 * psst-secret — web UI for creating, submitting, and revealing whispers.
 *
 * The format itself (encryption, key derivation, link fragments, reveal tokens)
 * lives in the @psst-secret/crypto package in packages/crypto, which implements
 * docs/format.md. esbuild bundles both into theme/static/js/crypto.min.js.
 *
 * The encryption key NEVER leaves the browser. It is stored only in the URL
 * fragment (#key=...&reveal=...), which is not sent to the server per the HTTP spec.
 * The independent reveal token is sent only in the reveal POST.
 */
import * as PsstCrypto from '@psst-secret/crypto';
import {
    FORMAT_VERSION,
    filesEnvelope,
    generateKey,
    generateRequestKeyPair,
    generateRevealAuthorization,
    encryptContent,
    isReadableFormat,
    parseFormatVersion,
    parseRevealFragment,
    parseSubmitFragment,
    revealFragment,
    sealForRecipient,
    submitFragment,
    textEnvelope,
    wrapPrivateKey,
} from '@psst-secret/crypto';

// ---- Multi-file selection state (shared between create.html and submit.html) ----

/** Maximum aggregate upload size in bytes (mirrors Django DATA_UPLOAD_MAX_MEMORY_SIZE). */
function getMaxUploadSize() {
    return (typeof window !== 'undefined' && window.PSST_MAX_UPLOAD_SIZE) || 50000000;
}

/** Files queued for the current whisper (File objects). */
let selectedFiles = [];

function formatSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
}

function totalSelectedSize() {
    return selectedFiles.reduce((s, f) => s + f.size, 0);
}

/**
 * Add files to the queue. Rejects any that would push the aggregate size over
 * the cap. Returns the list of rejected filenames (empty if all accepted).
 */
function addFiles(fileList) {
    const cap = getMaxUploadSize();
    let total = totalSelectedSize();
    const rejected = [];
    for (const f of fileList) {
        if (total + f.size > cap) {
            rejected.push(f.name);
            continue;
        }
        selectedFiles.push(f);
        total += f.size;
    }
    renderFileList(rejected);
    return rejected;
}

function removeSelectedFile(index) {
    if (index < 0 || index >= selectedFiles.length) return;
    selectedFiles.splice(index, 1);
    renderFileList();
}

function clearAllFiles() {
    selectedFiles = [];
    const input = document.getElementById('file-input');
    if (input) input.value = '';
    renderFileList();
}

function setButtonLabel(btn, text) {
    btn.querySelector('[data-btn-label]').textContent = text;
}

/**
 * Render the queued-files list and update placeholder/error UI.
 * Expects markup added by create.html / submit.html:
 *   #file-placeholder, #file-list (ul), #file-total, #file-size-error, #file-icon (template)
 */
function renderFileList(rejected) {
    const placeholder = document.getElementById('file-placeholder');
    const list = document.getElementById('file-list');
    const total = document.getElementById('file-total');
    const err = document.getElementById('file-size-error');
    if (!list) return;

    list.innerHTML = '';
    const hasFiles = selectedFiles.length > 0;
    if (placeholder) placeholder.classList.toggle('hidden', hasFiles);
    list.classList.toggle('hidden', !hasFiles);
    if (total) total.classList.toggle('hidden', !hasFiles);

    selectedFiles.forEach((file, i) => {
        const li = document.createElement('li');
        li.className = 'flex items-center justify-between gap-3 rounded-lg bg-gray-900 border border-gray-700 px-3 py-2';
        const meta = document.createElement('div');
        meta.className = 'flex items-center gap-2 min-w-0';
        const icon = document.getElementById('file-icon').content.firstElementChild.cloneNode(true);
        const text = document.createElement('div');
        text.className = 'min-w-0';
        const name = document.createElement('p');
        name.className = 'truncate text-sm text-brand-300';
        name.textContent = file.name;
        const size = document.createElement('p');
        size.className = 'text-xs text-gray-500';
        size.textContent = formatSize(file.size);
        text.appendChild(name);
        text.appendChild(size);
        meta.appendChild(icon);
        meta.appendChild(text);
        const remove = document.createElement('button');
        remove.type = 'button';
        remove.className = 'shrink-0 text-xs text-red-400 hover:text-red-300 underline';
        remove.textContent = gettext('Remove');
        remove.onclick = (e) => { e.stopPropagation(); removeSelectedFile(i); };
        li.appendChild(meta);
        li.appendChild(remove);
        list.appendChild(li);
    });

    if (total) {
        const cap = getMaxUploadSize();
        total.textContent = interpolate(gettext('Total: %s / %s'), [formatSize(totalSelectedSize()), formatSize(cap)]);
    }

    if (err) {
        if (rejected && rejected.length > 0) {
            err.textContent = interpolate(gettext('Skipped (would exceed %s total): %s'), [formatSize(getMaxUploadSize()), rejected.join(', ')]);
            err.classList.remove('hidden');
        } else {
            err.classList.add('hidden');
        }
    }

    // Reset the input so re-selecting the same file fires onchange again.
    const input = document.getElementById('file-input');
    if (input) input.value = '';
}

/** Called by <input type="file" multiple onchange="onFileSelected()">. */
function onFileSelected() {
    const input = document.getElementById('file-input');
    if (!input || !input.files || input.files.length === 0) return;
    addFiles(input.files);
}

/** Build the multi-file payload envelope from the current selection. */
async function buildFilesEnvelope() {
    const files = [];
    for (const file of selectedFiles) {
        files.push({ filename: file.name, mimetype: file.type, data: await readFileAsArrayBuffer(file) });
    }
    return filesEnvelope(files);
}

/**
 * Read a File object as an ArrayBuffer.
 */
function readFileAsArrayBuffer(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve(reader.result);
        reader.onerror = () => reject(reader.error);
        reader.readAsArrayBuffer(file);
    });
}

function readRevealFragment(allowLegacy = false) {
    return parseRevealFragment(window.location.hash, allowLegacy);
}

function readSubmitFragment() {
    return parseSubmitFragment(window.location.hash);
}

/**
 * Read the max-views policy selected on the create page.
 * Returns an int: 0 = unlimited, 1 = burn, N = destroy after N reveals.
 */
function readMaxViews() {
    const sel = document.getElementById('max-views');
    if (!sel) return 1;
    if (sel.value === 'custom') {
        const custom = document.getElementById('max-views-custom');
        const n = custom ? parseInt(custom.value, 10) : NaN;
        if (!Number.isFinite(n) || n < 1) return 1;
        return Math.min(n, 100);
    }
    const n = parseInt(sel.value, 10);
    return Number.isFinite(n) && n >= 0 ? n : 1;
}

/**
 * Main handler for the Create page. Called by the "Encrypt & Share" button.
 */
async function handleCreate() {
    const whisperEl = document.getElementById('whisper');
    const fileEl = document.getElementById('file-input');
    const expiryEl = document.getElementById('expiry');
    const errorEl = document.getElementById('error');
    const resultEl = document.getElementById('result');
    const formEl = document.getElementById('create-form');
    const btn = document.getElementById('encrypt-btn');

    errorEl.classList.add('hidden');
    const maxViews = readMaxViews();

    const isFileMode = selectedFiles.length > 0;
    const plaintext = whisperEl.value;

    if (!isFileMode && !plaintext.trim()) {
        errorEl.textContent = gettext('Please enter some content or select a file to encrypt.');
        errorEl.classList.remove('hidden');
        return;
    }

    if (isFileMode && totalSelectedSize() > getMaxUploadSize()) {
        errorEl.textContent = interpolate(gettext('Selected files exceed the maximum total size of %s.'), [formatSize(getMaxUploadSize())]);
        errorEl.classList.remove('hidden');
        return;
    }

    btn.disabled = true;
    setButtonLabel(btn, gettext('Encrypting…'));

    try {
        const passwordEl = document.getElementById('password');
        const password = passwordEl ? passwordEl.value : '';

        // Defense-in-depth: re-check passphrase strength even if the UI gate
        // was bypassed (e.g. via devtools). Empty passphrase is allowed because
        // the field is optional.
        if (password && window.PsstPasswordStrength) {
            const check = window.PsstPasswordStrength.evaluate(password);
            if (!check.allOk) {
                throw new Error(
                    gettext('Passphrase does not meet the strength requirements shown below the field.')
                );
            }
        }

        // Build the payload envelope
        let payload;
        if (isFileMode) {
            payload = await buildFilesEnvelope();
        } else {
            payload = textEnvelope(plaintext, whisperEl.dataset.format);
        }

        // 1. Generate a random key (never sent to server)
        const keyB64 = await generateKey();

        // 2. Encrypt in-browser (with optional password-derived key)
        const { ciphertext, iv, salt } = await encryptContent(payload, keyB64, password || undefined);
        const authorization = await generateRevealAuthorization();

        // 3. Send only ciphertext to server
        const csrfToken = document.querySelector('[name=csrfmiddlewaretoken]').value;
        const response = await fetch('/api/v1/whisper', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrfToken,
            },
            body: JSON.stringify({
                v: FORMAT_VERSION,
                ciphertext,
                iv,
                salt,
                reveal_token_hash: authorization.tokenHash,
                max_views: maxViews,
                expiry: expiryEl.value,
                allowed_cidr: (document.getElementById('allowed-cidr') || {}).value || '',
                require_auth_view: !!(document.getElementById('require-auth-view') || {}).checked,
                notify_email: (document.getElementById('notify-email') || {}).value || '',
            }),
        });

        if (!response.ok) {
            let msg = interpolate(gettext('Server error (%s)'), [response.status]);
            try { const err = await response.json(); msg = err.error || msg; } catch(e) {}
            throw new Error(msg);
        }

        const data = await response.json();

        // Password-protected links carry authorization but no decryption key.
        const shareUrl = data.url + revealFragment(password ? '' : keyB64, authorization.token);

        document.getElementById('result-url').value = shareUrl;
        if (password) {
            document.getElementById('password-notice').classList.remove('hidden');
        }
        const burnWarn = document.getElementById('burn-warning');
        const burnWarnText = document.getElementById('burn-warning-text');
        if (burnWarn && maxViews > 0) {
            if (maxViews === 1) {
                burnWarnText.textContent = gettext('This whisper will be destroyed after being viewed once.');
            } else {
                burnWarnText.textContent = interpolate(gettext('This whisper will be destroyed after %s views.'), [maxViews]);
            }
            burnWarn.classList.remove('hidden');
        }

        formEl.classList.add('hidden');
        document.getElementById('direction-toggle').classList.add('hidden');
        resultEl.classList.remove('hidden');
    } catch (e) {
        errorEl.textContent = interpolate(gettext('Error: %s'), [e.message]);
        errorEl.classList.remove('hidden');
    } finally {
        btn.disabled = false;
        setButtonLabel(btn, gettext('Encrypt & Share'));
    }
}

/**
 * Copy the share URL to clipboard.
 */
function copyUrl() {
    const urlInput = document.getElementById('result-url');
    navigator.clipboard.writeText(urlInput.value).then(() => {
        const btn = document.getElementById('copy-btn');
        btn.textContent = gettext('Copied!');
        setTimeout(() => btn.textContent = gettext('Copy'), 2000);
    });
}

/**
 * Handler for Receive mode on the Create page.
 * Creates a receive request — operator sets options and gets submit + view links.
 */
async function handleCreateRequest() {
    const expiryEl = document.getElementById('expiry');
    const errorEl = document.getElementById('error');
    const formEl = document.getElementById('create-form');
    const btn = document.getElementById('request-btn');

    errorEl.classList.add('hidden');
    const maxViews = readMaxViews();

    btn.disabled = true;
    setButtonLabel(btn, gettext('Creating…'));

    try {
        const passwordEl = document.getElementById('password');
        const password = passwordEl ? passwordEl.value : '';

        // Defense-in-depth: re-check passphrase strength even if the UI gate
        // was bypassed (e.g. via devtools). Empty passphrase is allowed because
        // the field is optional.
        if (password && window.PsstPasswordStrength) {
            const check = window.PsstPasswordStrength.evaluate(password);
            if (!check.allOk) {
                throw new Error(
                    gettext('Passphrase does not meet the strength requirements shown below the field.')
                );
            }
        }

        const { seedB64, publicKeyB64, fingerprintB64 } = await generateRequestKeyPair();
        const authorization = await generateRevealAuthorization();
        let salt = '';
        let wrappedKey = '';
        let wrappedKeyIv = '';

        if (password) {
            ({ wrappedKey, wrappedKeyIv, salt } = await wrapPrivateKey(seedB64, password));
        }

        const creatorOnly = document.getElementById('creator-only');
        const readerEmails = document.getElementById('allowed-reader-emails');
        const receiveAccess = creatorOnly ? {
            creator_only: creatorOnly.checked,
            allowed_reader_emails: creatorOnly.checked && readerEmails
                ? readerEmails.value.split(/[\s,;]+/).filter(Boolean)
                : [],
        } : {};
        const csrfToken = document.querySelector('[name=csrfmiddlewaretoken]').value;
        const response = await fetch('/api/v1/whisper/request', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrfToken,
            },
            body: JSON.stringify({
                v: FORMAT_VERSION,
                public_key: publicKeyB64,
                reveal_token_hash: authorization.tokenHash,
                salt,
                wrapped_key: wrappedKey,
                wrapped_key_iv: wrappedKeyIv,
                ...receiveAccess,
                max_views: maxViews,
                expiry: expiryEl.value,
                allowed_cidr: (document.getElementById('allowed-cidr') || {}).value || '',
                require_auth_view: !!(document.getElementById('require-auth-view') || {}).checked,
                require_auth_submit: !!(document.getElementById('require-auth-submit') || {}).checked,
                notify_email: (document.getElementById('notify-email') || {}).value || '',
            }),
        });

        if (!response.ok) {
            let msg = interpolate(gettext('Server error (%s)'), [response.status]);
            try { const err = await response.json(); msg = err.error || msg; } catch(e) {}
            throw new Error(msg);
        }

        const data = await response.json();

        // Submit link gets the public-key fingerprint; view link gets the key seed unless password-wrapped.
        const submitUrl = data.submit_url + submitFragment(fingerprintB64);
        const viewUrl = data.view_url + revealFragment(password ? '' : seedB64, authorization.token);

        document.getElementById('submit-url').value = submitUrl;
        document.getElementById('view-url').value = viewUrl;

        // Opt-in local history; the label stays in this browser and is never sent.
        const history = window.PsstReceiveHistory;
        const savedNotice = document.getElementById('receive-history-saved');
        if (history && history.isEnabled() && savedNotice) {
            const saved = await history.add({
                id: data.id,
                viewUrl,
                submitUrl,
                label: (document.getElementById('receive-label') || {}).value || '',
                expiresAt: data.expires_at,
                maxViews,
                passwordProtected: !!password,
            });
            savedNotice.classList.toggle('hidden', !saved);
        }

        if (password) {
            document.getElementById('receive-password-notice').classList.remove('hidden');
        }
        const rBurnWarn = document.getElementById('receive-burn-warning');
        const rBurnWarnText = document.getElementById('receive-burn-warning-text');
        if (rBurnWarn && maxViews > 0) {
            if (maxViews === 1) {
                rBurnWarnText.textContent = gettext('The whisper will be destroyed after you view it once.');
            } else {
                rBurnWarnText.textContent = interpolate(gettext('The whisper will be destroyed after %s views.'), [maxViews]);
            }
            rBurnWarn.classList.remove('hidden');
        }

        formEl.classList.add('hidden');
        document.getElementById('direction-toggle').classList.add('hidden');
        document.getElementById('receive-result').classList.remove('hidden');
    } catch (e) {
        errorEl.textContent = interpolate(gettext('Error: %s'), [e.message]);
        errorEl.classList.remove('hidden');
    } finally {
        btn.disabled = false;
        setButtonLabel(btn, gettext('Create Request'));
    }
}

/**
 * Handler for the Submit page. Called by a third party to submit a whisper
 * for a receive-mode request.
 */
async function handleSubmit() {
    const whisperEl = document.getElementById('whisper');
    const fileEl = document.getElementById('file-input');
    const errorEl = document.getElementById('error');
    const formEl = document.getElementById('submit-form');
    const btn = document.getElementById('submit-btn');

    errorEl.classList.add('hidden');

    const isFileMode = selectedFiles.length > 0;
    const plaintext = whisperEl.value;

    if (!isFileMode && !plaintext.trim()) {
        errorEl.textContent = gettext('Please enter some content or select a file to encrypt.');
        errorEl.classList.remove('hidden');
        return;
    }

    if (isFileMode && totalSelectedSize() > getMaxUploadSize()) {
        errorEl.textContent = interpolate(gettext('Selected files exceed the maximum total size of %s.'), [formatSize(getMaxUploadSize())]);
        errorEl.classList.remove('hidden');
        return;
    }

    btn.disabled = true;
    setButtonLabel(btn, gettext('Encrypting…'));

    try {
        const fragment = readSubmitFragment();
        if (!isReadableFormat(fragment.version) || !isReadableFormat(parseFormatVersion(requestData.v))) {
            throw new Error(gettext('This link uses an unsupported format version. Ask for a new link.'));
        }
        if (!fragment.fingerprint) {
            throw new Error(gettext('No encryption key found in URL. The link may be incomplete.'));
        }

        // Build the payload envelope (same format as send mode)
        let payload;
        if (isFileMode) {
            payload = await buildFilesEnvelope();
        } else {
            payload = textEnvelope(plaintext, whisperEl.dataset.format);
        }

        let sealed;
        try {
            sealed = await sealForRecipient(payload, requestData.public_key, fragment.fingerprint);
        } catch (e) {
            if (e.code === 'fingerprint_mismatch') {
                throw new Error(gettext('The request key does not match the link. The link may be incomplete or tampered with.'));
            }
            throw e;
        }

        // Submit to server
        const csrfToken = document.querySelector('[name=csrfmiddlewaretoken]').value;
        const response = await fetch('/api/v1/whisper/submit/' + requestData.submit_token, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrfToken,
            },
            body: JSON.stringify({ v: FORMAT_VERSION, ...sealed }),
        });

        if (!response.ok) {
            let msg = interpolate(gettext('Server error (%s)'), [response.status]);
            try { const err = await response.json(); msg = err.error || msg; } catch(e) {}
            throw new Error(msg);
        }

        formEl.classList.add('hidden');
        document.getElementById('submit-success').classList.remove('hidden');
    } catch (e) {
        errorEl.textContent = interpolate(gettext('Error: %s'), [e.message]);
        errorEl.classList.remove('hidden');
    } finally {
        btn.disabled = false;
        setButtonLabel(btn, gettext('Encrypt & Submit'));
    }
}

// Templates call these from inline handlers and scripts.
Object.assign(window, {
    PsstCrypto,
    addFiles,
    copyUrl,
    formatSize,
    handleCreate,
    handleCreateRequest,
    handleSubmit,
    onFileSelected,
    readRevealFragment,
    readSubmitFragment,
});
