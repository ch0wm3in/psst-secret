/**
 * psst-secret — Client-side encryption/decryption using Web Crypto API (AES-256-GCM).
 *
 * The encryption key NEVER leaves the browser. It is stored only in the URL
 * fragment (#key), which is not sent to the server per the HTTP spec.
 *
 * Encrypted payload format (JSON before encryption):
 *   Text:  { type: "text", content: "..." }
 *   File:  { type: "file", filename: "...", mimetype: "...", data: "<base64>" }
 */

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
 * Main handler for the Create page. Called by the "Encrypt & Share" button.
 */
async function handleCreate() {
    const whisperEl = document.getElementById('whisper');
    const fileEl = document.getElementById('file-input');
    const expiryEl = document.getElementById('expiry');
    const burnEl = document.getElementById('burn');
    const errorEl = document.getElementById('error');
    const resultEl = document.getElementById('result');
    const formEl = document.getElementById('create-form');
    const btn = document.getElementById('encrypt-btn');

    errorEl.classList.add('hidden');

    const isFileMode = fileEl && fileEl.files.length > 0;
    const plaintext = whisperEl.value.trim();

    if (!isFileMode && !plaintext) {
        errorEl.textContent = 'Please enter some content or select a file to encrypt.';
        errorEl.classList.remove('hidden');
        return;
    }

    btn.disabled = true;
    btn.textContent = 'Encrypting…';

    try {
        const passwordEl = document.getElementById('password');
        const password = passwordEl ? passwordEl.value : '';

        // Build the payload envelope
        let payload;
        if (isFileMode) {
            const file = fileEl.files[0];
            const arrayBuf = await readFileAsArrayBuffer(file);
            const fileDataB64 = bufToBase64(arrayBuf);
            payload = JSON.stringify({
                type: 'file',
                filename: file.name,
                mimetype: file.type || 'application/octet-stream',
                data: fileDataB64,
            });
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
                burn_after_read: burnEl.checked,
                expiry: expiryEl.value,
                allowed_cidr: (document.getElementById('allowed-cidr') || {}).value || '',
                require_auth_view: !!(document.getElementById('require-auth-view') || {}).checked,
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
        if (burnEl.checked) {
            document.getElementById('burn-warning').classList.remove('hidden');
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
    const burnEl = document.getElementById('burn');
    const errorEl = document.getElementById('error');
    const formEl = document.getElementById('create-form');
    const btn = document.getElementById('request-btn');

    errorEl.classList.add('hidden');

    btn.disabled = true;
    btn.textContent = 'Creating…';

    try {
        const passwordEl = document.getElementById('password');
        const password = passwordEl ? passwordEl.value : '';

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
        const response = await fetch('/api/request', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrfToken,
            },
            body: JSON.stringify({
                salt,
                password_verify_token: passwordVerifyToken,
                password_verify_iv: passwordVerifyIv,
                burn_after_read: burnEl.checked,
                expiry: expiryEl.value,
                allowed_cidr: (document.getElementById('allowed-cidr') || {}).value || '',
                require_auth_view: !!(document.getElementById('require-auth-view') || {}).checked,
                require_auth_submit: !!(document.getElementById('require-auth-submit') || {}).checked,
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
        if (burnEl.checked) {
            document.getElementById('receive-burn-warning').classList.remove('hidden');
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

    const isFileMode = fileEl && fileEl.files.length > 0;
    const plaintext = whisperEl.value.trim();

    if (!isFileMode && !plaintext) {
        errorEl.textContent = 'Please enter some content or select a file to encrypt.';
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
            const file = fileEl.files[0];
            const arrayBuf = await readFileAsArrayBuffer(file);
            const fileDataB64 = bufToBase64(arrayBuf);
            payload = JSON.stringify({
                type: 'file',
                filename: file.name,
                mimetype: file.type || 'application/octet-stream',
                data: fileDataB64,
            });
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
        const response = await fetch('/api/submit/' + requestData.request_id, {
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
