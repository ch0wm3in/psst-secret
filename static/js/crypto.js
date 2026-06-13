/**
 * psst-secret — Client-side encryption/decryption using Web Crypto API (AES-256-GCM).
 *
 * The encryption key NEVER leaves the browser. It is stored only in the URL
 * fragment (#key), which is not sent to the server per the HTTP spec.
 *
 * Encrypted payload format (JSON before encryption):
 *   Text:  { type: "text", content: "..." }
 *   Files: { type: "files", files: [{ filename, mimetype, data: "<base64>" }, ...] }
 *   Legacy (single file, still decoded for backward compatibility):
 *          { type: "file", filename: "...", mimetype: "...", data: "<base64>" }
 */

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

/**
 * Render the queued-files list and update placeholder/error UI.
 * Expects markup added by create.html / submit.html:
 *   #file-placeholder, #file-list (ul), #file-total, #file-size-error
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
        const icon = document.createElement('span');
        icon.className = 'text-lg';
        icon.textContent = '📄';
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
        remove.textContent = 'Remove';
        remove.onclick = (e) => { e.stopPropagation(); removeSelectedFile(i); };
        li.appendChild(meta);
        li.appendChild(remove);
        list.appendChild(li);
    });

    if (total) {
        const cap = getMaxUploadSize();
        total.textContent = 'Total: ' + formatSize(totalSelectedSize()) + ' / ' + formatSize(cap);
    }

    if (err) {
        if (rejected && rejected.length > 0) {
            err.textContent = 'Skipped (would exceed ' + formatSize(getMaxUploadSize()) + ' total): ' + rejected.join(', ');
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
        const arrayBuf = await readFileAsArrayBuffer(file);
        files.push({
            filename: file.name,
            mimetype: file.type || 'application/octet-stream',
            data: bufToBase64(arrayBuf),
        });
    }
    return JSON.stringify({ type: 'files', files });
}

/**
 * Sanitize a filename from an untrusted source.
 * Strips path separators and null bytes, limits length, applies a fallback.
 */
function sanitizeFilename(name) {
    if (typeof name !== 'string' || !name) return 'download';
    // Strip path components and null bytes
    let clean = name.replace(/[/\\]/g, '_').replace(/\0/g, '');
    // Collapse leading dots to prevent hidden files
    clean = clean.replace(/^\.+/, '');
    // Limit length (255 is common filesystem max)
    if (clean.length > 200) clean = clean.substring(0, 200);
    return clean || 'download';
}

/**
 * Convert an ArrayBuffer to a Base64 string.
 */
function bufToBase64(buf) {
    const bytes = new Uint8Array(buf);
    let binary = '';
    for (const b of bytes) binary += String.fromCharCode(b);
    return btoa(binary);
}

/**
 * Convert a Base64 string to an ArrayBuffer.
 */
function base64ToBuf(b64) {
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
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

/**
 * Generate a random AES-256-GCM key and return it as a Base64 string.
 */
async function generateKey() {
    const key = await crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt']
    );
    const raw = await crypto.subtle.exportKey('raw', key);
    return bufToBase64(raw);
}

/**
 * Import a Base64-encoded raw key into a CryptoKey object.
 */
async function importKey(keyB64) {
    const raw = base64ToBuf(keyB64);
    return crypto.subtle.importKey(
        'raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']
    );
}

/**
 * Derive an AES-256-GCM key from a password + salt using PBKDF2.
 * Returns { key (CryptoKey), saltB64 }.
 */
async function deriveKey(password, saltB64) {
    const enc = new TextEncoder();
    const salt = saltB64 ? base64ToBuf(saltB64) : crypto.getRandomValues(new Uint8Array(16));
    const keyMaterial = await crypto.subtle.importKey(
        'raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']
    );
    const key = await crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt, iterations: 600000, hash: 'SHA-256' },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );
    return { key, saltB64: saltB64 || bufToBase64(salt) };
}

/**
 * Encrypt plaintext string. Returns { ciphertext, iv } as Base64 strings.
 * If password is provided, derives key via PBKDF2 and also returns salt.
 */
async function encryptContent(plaintext, keyB64, password) {
    let key, saltB64 = '';
    if (password) {
        const derived = await deriveKey(password);
        key = derived.key;
        saltB64 = derived.saltB64;
    } else {
        key = await importKey(keyB64);
    }
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encoded = new TextEncoder().encode(plaintext);

    const encrypted = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        key,
        encoded
    );

    return {
        ciphertext: bufToBase64(encrypted),
        iv: bufToBase64(iv),
        salt: saltB64,
    };
}

/**
 * Decrypt Base64-encoded ciphertext with Base64-encoded IV and key.
 * If saltB64 is provided, derives key from password via PBKDF2.
 * Returns the plaintext string.
 */
async function decryptContent(ciphertextB64, ivB64, keyB64, password, saltB64) {
    let key;
    if (password && saltB64) {
        const derived = await deriveKey(password, saltB64);
        key = derived.key;
    } else {
        key = await importKey(keyB64);
    }
    const iv = base64ToBuf(ivB64);
    const ciphertext = base64ToBuf(ciphertextB64);

    const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv },
        key,
        ciphertext
    );

    return new TextDecoder().decode(decrypted);
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
    const plaintext = whisperEl.value.trim();

    if (!isFileMode && !plaintext) {
        errorEl.textContent = 'Please enter some content or select a file to encrypt.';
        errorEl.classList.remove('hidden');
        return;
    }

    if (isFileMode && totalSelectedSize() > getMaxUploadSize()) {
        errorEl.textContent = 'Selected files exceed the maximum total size of ' + formatSize(getMaxUploadSize()) + '.';
        errorEl.classList.remove('hidden');
        return;
    }

    btn.disabled = true;
    btn.textContent = 'Encrypting…';

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
                    'Passphrase does not meet the strength requirements shown below the field.'
                );
            }
        }

        // Build the payload envelope
        let payload;
        if (isFileMode) {
            payload = await buildFilesEnvelope();
        } else {
            payload = JSON.stringify({
                type: 'text',
                content: plaintext,
            });
        }

        // 1. Generate a random key (never sent to server)
        const keyB64 = await generateKey();

        // 2. Encrypt in-browser (with optional password-derived key)
        const { ciphertext, iv, salt } = await encryptContent(payload, keyB64, password || undefined);

        // 3. Send only ciphertext to server
        const csrfToken = document.querySelector('[name=csrfmiddlewaretoken]').value;
        const response = await fetch('/api/whisper', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrfToken,
            },
            body: JSON.stringify({
                ciphertext,
                iv,
                salt,
                max_views: maxViews,
                expiry: expiryEl.value,
                allowed_cidr: (document.getElementById('allowed-cidr') || {}).value || '',
                require_auth_view: !!(document.getElementById('require-auth-view') || {}).checked,
                notify_email: (document.getElementById('notify-email') || {}).value || '',
            }),
        });

        if (!response.ok) {
            let msg = 'Server error (' + response.status + ')';
            try { const err = await response.json(); msg = err.error || msg; } catch(e) {}
            throw new Error(msg);
        }

        const data = await response.json();

        // 4. Build the share URL with key in fragment (never sent to server)
        //    If password-protected, key is not needed in URL
        const shareUrl = password
            ? data.url
            : data.url + '#' + keyB64;

        document.getElementById('result-url').value = shareUrl;
        if (password) {
            document.getElementById('password-notice').classList.remove('hidden');
        }
        const burnWarn = document.getElementById('burn-warning');
        const burnWarnText = document.getElementById('burn-warning-text');
        if (burnWarn && maxViews > 0) {
            if (maxViews === 1) {
                burnWarnText.textContent = 'This whisper will be destroyed after being viewed once.';
            } else {
                burnWarnText.textContent = 'This whisper will be destroyed after ' + maxViews + ' views.';
            }
            burnWarn.classList.remove('hidden');
        }

        formEl.classList.add('hidden');
        resultEl.classList.remove('hidden');
    } catch (e) {
        errorEl.textContent = 'Error: ' + e.message;
        errorEl.classList.remove('hidden');
    } finally {
        btn.disabled = false;
        btn.textContent = '🔒 Encrypt & Share';
    }
}

/**
 * Copy the share URL to clipboard.
 */
function copyUrl() {
    const urlInput = document.getElementById('result-url');
    navigator.clipboard.writeText(urlInput.value).then(() => {
        const btn = document.getElementById('copy-btn');
        btn.textContent = 'Copied!';
        setTimeout(() => btn.textContent = 'Copy', 2000);
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
    btn.textContent = 'Creating…';

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
                    'Passphrase does not meet the strength requirements shown below the field.'
                );
            }
        }

        let salt = '';
        let keyB64 = '';
        let passwordVerifyToken = '';
        let passwordVerifyIv = '';

        if (password) {
            // Password mode: generate salt, store on server
            const derived = await deriveKey(password);
            salt = derived.saltB64;

            // Generate a verification token: encrypt a known string with the derived key
            const verifyIv = crypto.getRandomValues(new Uint8Array(12));
            const verifyPlaintext = new TextEncoder().encode('whisper-verify');
            const verifyEncrypted = await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv: verifyIv }, derived.key, verifyPlaintext
            );
            passwordVerifyToken = bufToBase64(verifyEncrypted);
            passwordVerifyIv = bufToBase64(verifyIv);
        } else {
            // Key mode: generate random key for URL fragment
            keyB64 = await generateKey();
        }

        const csrfToken = document.querySelector('[name=csrfmiddlewaretoken]').value;
        const response = await fetch('/api/whisper/request', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrfToken,
            },
            body: JSON.stringify({
                salt,
                password_verify_token: passwordVerifyToken,
                password_verify_iv: passwordVerifyIv,
                max_views: maxViews,
                expiry: expiryEl.value,
                allowed_cidr: (document.getElementById('allowed-cidr') || {}).value || '',
                require_auth_view: !!(document.getElementById('require-auth-view') || {}).checked,
                require_auth_submit: !!(document.getElementById('require-auth-submit') || {}).checked,
                notify_email: (document.getElementById('notify-email') || {}).value || '',
            }),
        });

        if (!response.ok) {
            let msg = 'Server error (' + response.status + ')';
            try { const err = await response.json(); msg = err.error || msg; } catch(e) {}
            throw new Error(msg);
        }

        const data = await response.json();

        // Build URLs with key fragment if not password-protected
        const submitUrl = password ? data.submit_url : data.submit_url + '#' + keyB64;
        const viewUrl = password ? data.view_url : data.view_url + '#' + keyB64;

        document.getElementById('submit-url').value = submitUrl;
        document.getElementById('view-url').value = viewUrl;

        if (password) {
            document.getElementById('receive-password-notice').classList.remove('hidden');
        }
        const rBurnWarn = document.getElementById('receive-burn-warning');
        const rBurnWarnText = document.getElementById('receive-burn-warning-text');
        if (rBurnWarn && maxViews > 0) {
            if (maxViews === 1) {
                rBurnWarnText.textContent = 'The whisper will be destroyed after you view it once.';
            } else {
                rBurnWarnText.textContent = 'The whisper will be destroyed after ' + maxViews + ' views.';
            }
            rBurnWarn.classList.remove('hidden');
        }

        formEl.classList.add('hidden');
        document.getElementById('receive-result').classList.remove('hidden');
    } catch (e) {
        errorEl.textContent = 'Error: ' + e.message;
        errorEl.classList.remove('hidden');
    } finally {
        btn.disabled = false;
        btn.textContent = '🔗 Create Request';
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
    const plaintext = whisperEl.value.trim();

    if (!isFileMode && !plaintext) {
        errorEl.textContent = 'Please enter some content or select a file to encrypt.';
        errorEl.classList.remove('hidden');
        return;
    }

    if (isFileMode && totalSelectedSize() > getMaxUploadSize()) {
        errorEl.textContent = 'Selected files exceed the maximum total size of ' + formatSize(getMaxUploadSize()) + '.';
        errorEl.classList.remove('hidden');
        return;
    }

    btn.disabled = true;
    btn.textContent = 'Encrypting…';

    try {
        const isPasswordProtected = !!requestData.salt;
        const password = isPasswordProtected
            ? (document.getElementById('password') ? document.getElementById('password').value : '')
            : '';

        if (isPasswordProtected && !password) {
            errorEl.textContent = 'Password is required for this request.';
            errorEl.classList.remove('hidden');
            btn.disabled = false;
            btn.textContent = '🔒 Encrypt & Submit';
            return;
        }

        // Validate password using the verification token before encrypting
        if (isPasswordProtected && requestData.password_verify_token) {
            try {
                const derived = await deriveKey(password, requestData.salt);
                await crypto.subtle.decrypt(
                    { name: 'AES-GCM', iv: base64ToBuf(requestData.password_verify_iv) },
                    derived.key,
                    base64ToBuf(requestData.password_verify_token)
                );
            } catch (e) {
                errorEl.textContent = 'Wrong password. Please check with the requester and try again.';
                errorEl.classList.remove('hidden');
                btn.disabled = false;
                btn.textContent = '🔒 Encrypt & Submit';
                return;
            }
        }

        // Build the payload envelope (same format as send mode)
        let payload;
        if (isFileMode) {
            payload = await buildFilesEnvelope();
        } else {
            payload = JSON.stringify({
                type: 'text',
                content: plaintext,
            });
        }

        // Encrypt: use password+salt or key from URL fragment
        let ciphertext, iv;
        if (isPasswordProtected) {
            const derived = await deriveKey(password, requestData.salt);
            const key = derived.key;
            const ivBuf = crypto.getRandomValues(new Uint8Array(12));
            const encoded = new TextEncoder().encode(payload);
            const encrypted = await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv: ivBuf }, key, encoded
            );
            ciphertext = bufToBase64(encrypted);
            iv = bufToBase64(ivBuf);
        } else {
            if (!keyB64) {
                throw new Error('No encryption key found in URL. The link may be incomplete.');
            }
            const result = await encryptContent(payload, keyB64);
            ciphertext = result.ciphertext;
            iv = result.iv;
        }

        // Submit to server
        const csrfToken = document.querySelector('[name=csrfmiddlewaretoken]').value;
        const response = await fetch('/api/whisper/submit/' + requestData.request_id, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrfToken,
            },
            body: JSON.stringify({ ciphertext, iv }),
        });

        if (!response.ok) {
            let msg = 'Server error (' + response.status + ')';
            try { const err = await response.json(); msg = err.error || msg; } catch(e) {}
            throw new Error(msg);
        }

        formEl.classList.add('hidden');
        document.getElementById('submit-success').classList.remove('hidden');
    } catch (e) {
        errorEl.textContent = 'Error: ' + e.message;
        errorEl.classList.remove('hidden');
    } finally {
        btn.disabled = false;
        btn.textContent = '🔒 Encrypt & Submit';
    }
}
