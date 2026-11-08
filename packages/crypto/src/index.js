/**
 * @psst-secret/crypto: the psst-secret encryption format, link fragments, and
 * reveal tokens.
 *
 * docs/format.md in the psst-secret repository is the normative specification.
 * This module has no DOM dependencies; it needs only the Web Crypto API
 * (`globalThis.crypto`), `TextEncoder`, `btoa`, and `atob`, which browsers and
 * Node.js 20+ provide.
 */
import { ml_kem768_x25519 as kem } from '@noble/post-quantum/hybrid.js';

/** Format version written by this package. The package major version matches it. */
export const FORMAT_VERSION = 1;
/** Version 0 is the unmarked legacy format, which is still read but never written. */
export const READABLE_FORMAT_VERSIONS = Object.freeze([0, 1]);
export const PBKDF2_ITERATIONS = 600000;
const RECEIVE_HKDF_INFO = 'psst-receive-v2';
/** Fragment of legacy links that carry only a bare base64 key or fingerprint. */
const LEGACY_FRAGMENT = /^[A-Za-z0-9+/]+={0,2}$/;

/** Error with a stable `code`, so callers can show their own (translated) message. */
export class FormatError extends Error {
    constructor(code, message) {
        super(message);
        this.name = 'FormatError';
        this.code = code;
    }
}

/** Parse a `v` value from a fragment or payload. Missing means legacy version 0. */
export function parseFormatVersion(value) {
    if (value === null || value === undefined) return 0;
    return /^[0-9]+$/.test(String(value)) ? Number(value) : NaN;
}

export function isReadableFormat(version) {
    return READABLE_FORMAT_VERSIONS.includes(version);
}

// ---- Encoding ----

/** Encode an ArrayBuffer or Uint8Array as standard padded base64. */
export function bufToBase64(buf) {
    const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
    let binary = '';
    for (const b of bytes) binary += String.fromCharCode(b);
    return btoa(binary);
}

/** Decode standard base64 into an ArrayBuffer. */
export function base64ToBuf(b64) {
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
}

function base64ToBytes(b64) {
    return new Uint8Array(base64ToBuf(b64));
}

function toHex(bytes) {
    return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

function randomBytes(length) {
    return globalThis.crypto.getRandomValues(new Uint8Array(length));
}

function subtle() {
    return globalThis.crypto.subtle;
}

// ---- Plaintext envelope ----

/** Serialize a text whisper. `format` is optional, e.g. "markdown". */
export function textEnvelope(content, format) {
    return JSON.stringify({ type: 'text', content, ...(format ? { format } : {}) });
}

/** Serialize a files whisper from `[{ filename, mimetype, data }]`, where data is bytes. */
export function filesEnvelope(files) {
    return JSON.stringify({
        type: 'files',
        files: files.map(f => ({
            filename: f.filename,
            mimetype: f.mimetype || 'application/octet-stream',
            data: bufToBase64(f.data),
        })),
    });
}

/**
 * Sanitize a filename from an untrusted source.
 * Strips path separators and null bytes, limits length, applies a fallback.
 */
export function sanitizeFilename(name) {
    if (typeof name !== 'string' || !name) return 'download';
    let clean = name.replace(/[/\\]/g, '_').replace(/\0/g, '');
    // Collapse leading dots to prevent hidden files.
    clean = clean.replace(/^\.+/, '');
    if (clean.length > 200) clean = clean.substring(0, 200);
    return clean || 'download';
}

// ---- Reveal tokens and link fragments ----

/** SHA-256 hex digest of the ASCII reveal token, as stored by the server. */
export async function revealTokenHash(token) {
    return toHex(new Uint8Array(await subtle().digest('SHA-256', new TextEncoder().encode(token))));
}

/** Generate a reveal token. Returns { token, tokenHash }. */
export async function generateRevealAuthorization() {
    const token = toHex(randomBytes(32));
    return { token, tokenHash: await revealTokenHash(token) };
}

/** View link fragment, including the leading `#`. Pass an empty key for password-protected links. */
export function revealFragment(key, token) {
    const params = new URLSearchParams({ v: FORMAT_VERSION, reveal: token });
    if (key) params.set('key', key);
    return '#' + params.toString();
}

/** Parse a view link fragment, with or without the leading `#`. Returns { version, key, token }. */
export function parseRevealFragment(fragment, allowLegacy = false) {
    const raw = String(fragment || '').replace(/^#/, '');
    if (allowLegacy && LEGACY_FRAGMENT.test(raw)) {
        return { version: 0, key: raw, token: '' };
    }
    const params = new URLSearchParams(raw);
    return {
        version: parseFormatVersion(params.get('v')),
        key: params.get('key') || '',
        token: params.get('reveal') || '',
    };
}

/** Submit link fragment, including the leading `#`. */
export function submitFragment(fingerprint) {
    return '#' + new URLSearchParams({ v: FORMAT_VERSION, fp: fingerprint }).toString();
}

/** Parse a submit link fragment. Legacy links carry only the bare fingerprint. */
export function parseSubmitFragment(fragment) {
    const raw = String(fragment || '').replace(/^#/, '');
    if (LEGACY_FRAGMENT.test(raw)) {
        return { version: 0, fingerprint: raw };
    }
    const params = new URLSearchParams(raw);
    return { version: parseFormatVersion(params.get('v')), fingerprint: params.get('fp') || '' };
}

// ---- Send mode: AES-256-GCM, optionally with a PBKDF2 password key ----

/** Generate a random AES-256-GCM key and return it as base64. */
export async function generateKey() {
    const key = await subtle().generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
    return bufToBase64(await subtle().exportKey('raw', key));
}

function importKey(keyB64) {
    return subtle().importKey('raw', base64ToBuf(keyB64), { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

/**
 * Derive an AES-256-GCM key from a password and salt with PBKDF2.
 * Generates a salt when none is given. Returns { key (CryptoKey), saltB64 }.
 */
async function deriveKey(password, saltB64) {
    const salt = saltB64 ? base64ToBuf(saltB64) : randomBytes(16);
    const keyMaterial = await subtle().importKey(
        'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']
    );
    const key = await subtle().deriveKey(
        { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );
    return { key, saltB64: saltB64 || bufToBase64(salt) };
}

/**
 * Encrypt a plaintext string. Returns { ciphertext, iv, salt } as base64.
 * With a password, the key is derived with PBKDF2 and `salt` is set; otherwise
 * `keyB64` is used and `salt` is empty.
 */
export async function encryptContent(plaintext, keyB64, password) {
    let key;
    let saltB64 = '';
    if (password) {
        ({ key, saltB64 } = await deriveKey(password));
    } else {
        key = await importKey(keyB64);
    }
    const iv = randomBytes(12);
    const encrypted = await subtle().encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(plaintext));
    return { ciphertext: bufToBase64(encrypted), iv: bufToBase64(iv), salt: saltB64 };
}

/**
 * Decrypt base64 ciphertext and IV. With a password and salt, the key is derived
 * with PBKDF2; otherwise `keyB64` is used. Returns the plaintext string.
 */
export async function decryptContent(ciphertextB64, ivB64, keyB64, password, saltB64) {
    const key = password && saltB64 ? (await deriveKey(password, saltB64)).key : await importKey(keyB64);
    const decrypted = await subtle().decrypt(
        { name: 'AES-GCM', iv: base64ToBuf(ivB64) }, key, base64ToBuf(ciphertextB64)
    );
    return new TextDecoder().decode(decrypted);
}

// ---- Receive mode: X-Wing (ML-KEM-768 + X25519) + HKDF-SHA256 + AES-256-GCM ----
// The public key is stored server-side; the submit link carries only its SHA-256
// fingerprint, so the server cannot swap it. The view link carries the key seed.

async function sha256B64(bytes) {
    return bufToBase64(await subtle().digest('SHA-256', bytes));
}

async function hkdfAesKey(sharedSecret, usage) {
    const ikm = await subtle().importKey('raw', sharedSecret, 'HKDF', false, ['deriveKey']);
    return subtle().deriveKey(
        {
            name: 'HKDF',
            hash: 'SHA-256',
            salt: new Uint8Array(32),
            info: new TextEncoder().encode(RECEIVE_HKDF_INFO),
        },
        ikm,
        { name: 'AES-GCM', length: 256 },
        false,
        [usage]
    );
}

/** Generate the request key pair. Returns { seedB64, publicKeyB64, fingerprintB64 }. */
export async function generateRequestKeyPair() {
    const seed = randomBytes(kem.lengths.seed);
    const { publicKey } = kem.keygen(seed);
    return {
        seedB64: bufToBase64(seed),
        publicKeyB64: bufToBase64(publicKey),
        fingerprintB64: await sha256B64(publicKey),
    };
}

/**
 * Encrypt plaintext to the request's public key after checking it against the
 * link fingerprint. Throws a FormatError with code `fingerprint_mismatch` if
 * they differ. Returns { ciphertext, iv, encapsulated_key } as base64.
 */
export async function sealForRecipient(plaintext, publicKeyB64, fingerprintB64) {
    const publicKey = base64ToBytes(publicKeyB64);
    if (await sha256B64(publicKey) !== fingerprintB64) {
        throw new FormatError('fingerprint_mismatch', 'The request public key does not match the link fingerprint.');
    }
    const { cipherText, sharedSecret } = kem.encapsulate(publicKey);
    const key = await hkdfAesKey(sharedSecret, 'encrypt');
    const iv = randomBytes(12);
    const ct = await subtle().encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(plaintext));
    return {
        ciphertext: bufToBase64(ct),
        iv: bufToBase64(iv),
        encapsulated_key: bufToBase64(cipherText),
    };
}

/** Decrypt a receive-mode payload `{ ciphertext, iv, encapsulated_key }` with the request's key seed. */
export async function openFromSender(data, seedB64) {
    const { secretKey } = kem.keygen(base64ToBytes(seedB64));
    const sharedSecret = kem.decapsulate(base64ToBytes(data.encapsulated_key), secretKey);
    const key = await hkdfAesKey(sharedSecret, 'decrypt');
    const pt = await subtle().decrypt(
        { name: 'AES-GCM', iv: base64ToBuf(data.iv) }, key, base64ToBuf(data.ciphertext)
    );
    return new TextDecoder().decode(pt);
}

/** Encrypt the request key seed with a password. Returns { wrappedKey, wrappedKeyIv, salt }. */
export async function wrapPrivateKey(seedB64, password) {
    const { key, saltB64 } = await deriveKey(password);
    const iv = randomBytes(12);
    const wrapped = await subtle().encrypt({ name: 'AES-GCM', iv }, key, base64ToBuf(seedB64));
    return { wrappedKey: bufToBase64(wrapped), wrappedKeyIv: bufToBase64(iv), salt: saltB64 };
}

/** Decrypt a password-wrapped request key seed. Throws on a wrong password. */
export async function unwrapPrivateKey(wrappedKeyB64, wrappedKeyIvB64, password, saltB64) {
    const { key } = await deriveKey(password, saltB64);
    const raw = await subtle().decrypt(
        { name: 'AES-GCM', iv: base64ToBuf(wrappedKeyIvB64) }, key, base64ToBuf(wrappedKeyB64)
    );
    return bufToBase64(raw);
}
