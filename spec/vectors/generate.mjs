// Regenerates spec/vectors/v1/*.json from fixed inputs, independently of static/js/crypto.js.
// Run from the repository root after `npm ci --prefix theme/static_src`:
//   node spec/vectors/generate.mjs
import { createHash, webcrypto } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';

const { ml_kem768_x25519: kem } = await import(
    new URL('../../theme/static_src/node_modules/@noble/post-quantum/hybrid.js', import.meta.url)
);

const VERSION = 1;
const PBKDF2_ITERATIONS = 600000;
const { subtle } = webcrypto;
const utf8 = new TextEncoder();
const b64 = bytes => Buffer.from(bytes).toString('base64');
const hex = bytes => Buffer.from(bytes).toString('hex');
const sha256 = data => createHash('sha256').update(data).digest();

// Deterministic stand-ins for random values, so the vectors are reproducible.
const fixed = (label, length) => new Uint8Array(
    createHash('shake256', { outputLength: length })
        .update(`psst-secret format v${VERSION} test vector: ${label}`)
        .digest()
);

async function aesGcmEncrypt(key, iv, data) {
    if (key instanceof Uint8Array) {
        key = await subtle.importKey('raw', key, 'AES-GCM', false, ['encrypt']);
    }
    return new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv }, key, data));
}

async function passwordKey(password, salt) {
    const material = await subtle.importKey('raw', utf8.encode(password), 'PBKDF2', false, ['deriveKey']);
    return subtle.deriveKey(
        { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: PBKDF2_ITERATIONS },
        material,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt']
    );
}

async function receiveKey(sharedSecret) {
    const material = await subtle.importKey('raw', sharedSecret, 'HKDF', false, ['deriveKey']);
    return subtle.deriveKey(
        { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: utf8.encode('psst-receive-v2') },
        material,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt']
    );
}

function revealAuthorization(label) {
    const token = hex(fixed(`${label} reveal token`, 32));
    return { reveal_token: token, reveal_token_hash: hex(sha256(token)) };
}

function fragment(entries) {
    return new URLSearchParams(entries).toString();
}

const PLAINTEXTS = {
    text: JSON.stringify({ type: 'text', content: 'Hello, whisper!' }),
    unicode: JSON.stringify({ type: 'text', content: 'Æble, čaj, 🔐\nsecond line', format: 'markdown' }),
    files: JSON.stringify({
        type: 'files',
        files: [{ filename: 'note.txt', mimetype: 'text/plain', data: b64(utf8.encode('file body\n')) }],
    }),
};

async function sendCases() {
    const cases = [];
    for (const [name, plaintext] of Object.entries(PLAINTEXTS)) {
        const key = fixed(`send ${name} key`, 32);
        const iv = fixed(`send ${name} iv`, 12);
        const authorization = revealAuthorization(`send ${name}`);
        cases.push({
            name,
            key: b64(key),
            iv: b64(iv),
            plaintext,
            ciphertext: b64(await aesGcmEncrypt(key, iv, utf8.encode(plaintext))),
            ...authorization,
            fragment: fragment({ v: VERSION, reveal: authorization.reveal_token, key: b64(key) }),
        });
    }
    return cases;
}

async function passwordCases() {
    const cases = [];
    for (const [name, password] of [['ascii', 'correct horse battery staple 42!'], ['unicode', 'pässwörd-🔑-2026']]) {
        const salt = fixed(`password ${name} salt`, 16);
        const iv = fixed(`password ${name} iv`, 12);
        const authorization = revealAuthorization(`password ${name}`);
        cases.push({
            name,
            password,
            salt: b64(salt),
            iterations: PBKDF2_ITERATIONS,
            iv: b64(iv),
            plaintext: PLAINTEXTS.text,
            ciphertext: b64(await aesGcmEncrypt(await passwordKey(password, salt), iv, utf8.encode(PLAINTEXTS.text))),
            ...authorization,
            fragment: fragment({ v: VERSION, reveal: authorization.reveal_token }),
        });
    }
    return cases;
}

async function receiveCases() {
    const cases = [];
    for (const [name, password] of [['plain', ''], ['password', 'correct horse battery staple 42!']]) {
        const seed = fixed(`receive ${name} seed`, kem.lengths.seed);
        const { publicKey } = kem.keygen(seed);
        const fingerprint = b64(sha256(publicKey));
        const randomness = fixed(`receive ${name} encapsulation`, 64);
        const { cipherText, sharedSecret } = kem.encapsulate(publicKey, randomness);
        const iv = fixed(`receive ${name} iv`, 12);
        const authorization = revealAuthorization(`receive ${name}`);
        const ciphertext = await aesGcmEncrypt(await receiveKey(sharedSecret), iv, utf8.encode(PLAINTEXTS.unicode));
        const item = {
            name,
            seed: b64(seed),
            public_key: b64(publicKey),
            fingerprint,
            submit_fragment: fragment({ v: VERSION, fp: fingerprint }),
            encapsulation_randomness: b64(randomness),
            encapsulated_key: b64(cipherText),
            iv: b64(iv),
            plaintext: PLAINTEXTS.unicode,
            ciphertext: b64(ciphertext),
            ...authorization,
        };
        if (password) {
            const salt = fixed(`receive ${name} salt`, 16);
            const wrapIv = fixed(`receive ${name} wrapped key iv`, 12);
            Object.assign(item, {
                password,
                salt: b64(salt),
                iterations: PBKDF2_ITERATIONS,
                wrapped_key_iv: b64(wrapIv),
                wrapped_key: b64(await aesGcmEncrypt(await passwordKey(password, salt), wrapIv, seed)),
                view_fragment: fragment({ v: VERSION, reveal: authorization.reveal_token }),
            });
        } else {
            item.view_fragment = fragment({ v: VERSION, reveal: authorization.reveal_token, key: b64(seed) });
        }
        cases.push(item);
    }
    return cases;
}

const outDir = new URL(`./v${VERSION}/`, import.meta.url);
mkdirSync(outDir, { recursive: true });
for (const [mode, build] of [['send', sendCases], ['password', passwordCases], ['receive', receiveCases]]) {
    const vectors = { format_version: VERSION, mode, cases: await build() };
    writeFileSync(new URL(`${mode}.json`, outDir), JSON.stringify(vectors, null, 2) + '\n');
}
