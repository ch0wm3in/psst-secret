// Checks the package against the shared format vectors in spec/vectors/.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { afterEach, describe, test } from 'node:test';

import * as psst from '../src/index.js';

const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url)));
const vectorsDir = new URL(`../../../spec/vectors/v${psst.FORMAT_VERSION}/`, import.meta.url);

function vectors(mode) {
    const data = JSON.parse(readFileSync(new URL(`${mode}.json`, vectorsDir)));
    assert.equal(data.format_version, psst.FORMAT_VERSION);
    assert.equal(data.mode, mode);
    assert.ok(data.cases.length);
    return data.cases;
}

const bytes = b64 => new Uint8Array(psst.base64ToBuf(b64));
const hexBytes = hex => new Uint8Array(hex.match(/../g).map(h => parseInt(h, 16)));

const realRandom = globalThis.crypto.getRandomValues;
afterEach(() => {
    globalThis.crypto.getRandomValues = realRandom;
});

// Replace random values with the vector inputs, so encryption must reproduce the
// expected output exactly.
async function withRandom(queue, fn) {
    globalThis.crypto.getRandomValues = array => {
        // Other requests, such as noble's scalar blinding, do not affect outputs.
        if (!queue.length || queue[0].length !== array.length) return realRandom.call(globalThis.crypto, array);
        array.set(queue.shift());
        return array;
    };
    try {
        const result = await fn();
        assert.equal(queue.length, 0, 'unused randomness');
        return result;
    } finally {
        globalThis.crypto.getRandomValues = realRandom;
    }
}

async function checkAuthorization(c) {
    const authorization = await withRandom([hexBytes(c.reveal_token)], psst.generateRevealAuthorization);
    assert.deepEqual(authorization, { token: c.reveal_token, tokenHash: c.reveal_token_hash });
    assert.equal(await psst.revealTokenHash(c.reveal_token), c.reveal_token_hash);
}

test('package major version matches the format version', () => {
    assert.equal(Number(pkg.version.split('.')[0]), psst.FORMAT_VERSION);
});

describe('send vectors', () => {
    for (const c of vectors('send')) {
        test(c.name, async () => {
            await checkAuthorization(c);
            const encrypted = await withRandom([bytes(c.iv)], () => psst.encryptContent(c.plaintext, c.key));
            assert.deepEqual(encrypted, { ciphertext: c.ciphertext, iv: c.iv, salt: '' });
            assert.equal(await psst.decryptContent(c.ciphertext, c.iv, c.key), c.plaintext);
            assert.equal(psst.revealFragment(c.key, c.reveal_token), '#' + c.fragment);
            assert.deepEqual(psst.parseRevealFragment('#' + c.fragment), {
                version: 1, key: c.key, token: c.reveal_token,
            });
        });
    }
});

describe('password vectors', () => {
    for (const c of vectors('password')) {
        test(c.name, async () => {
            assert.equal(c.iterations, psst.PBKDF2_ITERATIONS);
            await checkAuthorization(c);
            const encrypted = await withRandom(
                [bytes(c.salt), bytes(c.iv)], () => psst.encryptContent(c.plaintext, null, c.password)
            );
            assert.deepEqual(encrypted, { ciphertext: c.ciphertext, iv: c.iv, salt: c.salt });
            assert.equal(await psst.decryptContent(c.ciphertext, c.iv, null, c.password, c.salt), c.plaintext);
            await assert.rejects(psst.decryptContent(c.ciphertext, c.iv, null, c.password + 'x', c.salt));
            assert.equal(psst.revealFragment('', c.reveal_token), '#' + c.fragment);
            assert.deepEqual(psst.parseRevealFragment(c.fragment), {
                version: 1, key: '', token: c.reveal_token,
            });
        });
    }
});

describe('receive vectors', () => {
    for (const c of vectors('receive')) {
        test(c.name, async () => {
            await checkAuthorization(c);
            const keys = await withRandom([bytes(c.seed)], psst.generateRequestKeyPair);
            assert.deepEqual(keys, {
                seedB64: c.seed, publicKeyB64: c.public_key, fingerprintB64: c.fingerprint,
            });
            const sealed = await withRandom(
                [bytes(c.encapsulation_randomness), bytes(c.iv)],
                () => psst.sealForRecipient(c.plaintext, c.public_key, c.fingerprint)
            );
            assert.deepEqual(sealed, {
                ciphertext: c.ciphertext, iv: c.iv, encapsulated_key: c.encapsulated_key,
            });
            assert.equal(await psst.openFromSender(c, c.seed), c.plaintext);
            assert.equal(psst.submitFragment(c.fingerprint), '#' + c.submit_fragment);
            assert.deepEqual(psst.parseSubmitFragment(c.submit_fragment), {
                version: 1, fingerprint: c.fingerprint,
            });
            const key = c.password ? '' : c.seed;
            assert.equal(psst.revealFragment(key, c.reveal_token), '#' + c.view_fragment);
            assert.deepEqual(psst.parseRevealFragment(c.view_fragment), {
                version: 1, key, token: c.reveal_token,
            });
            if (c.password) {
                const wrapped = await withRandom(
                    [bytes(c.salt), bytes(c.wrapped_key_iv)], () => psst.wrapPrivateKey(c.seed, c.password)
                );
                assert.deepEqual(wrapped, {
                    wrappedKey: c.wrapped_key, wrappedKeyIv: c.wrapped_key_iv, salt: c.salt,
                });
                assert.equal(
                    await psst.unwrapPrivateKey(c.wrapped_key, c.wrapped_key_iv, c.password, c.salt), c.seed
                );
            }
        });
    }

    test('rejects a public key that does not match the fingerprint', async () => {
        const [c, other] = vectors('receive');
        await assert.rejects(
            psst.sealForRecipient(c.plaintext, c.public_key, other.fingerprint),
            err => err instanceof psst.FormatError && err.code === 'fingerprint_mismatch'
        );
    });
});
