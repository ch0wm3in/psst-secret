// Behavior from docs/format.md that the vectors do not cover.
import assert from 'node:assert/strict';
import { test } from 'node:test';

import * as psst from '../src/index.js';

test('a missing version is legacy 0, and only known versions are readable', () => {
    assert.equal(psst.parseFormatVersion(null), 0);
    assert.equal(psst.parseFormatVersion(undefined), 0);
    assert.equal(psst.parseFormatVersion('1'), 1);
    assert.equal(psst.parseFormatVersion(1), 1);
    assert.ok(Number.isNaN(psst.parseFormatVersion('1.0')));
    assert.ok(Number.isNaN(psst.parseFormatVersion('x')));
    assert.ok(psst.isReadableFormat(0));
    assert.ok(psst.isReadableFormat(1));
    assert.ok(!psst.isReadableFormat(2));
    assert.ok(!psst.isReadableFormat(NaN));
});

test('legacy fragments carry a bare key or fingerprint', () => {
    const key = 'wDBqzMt8+lAOxVIeB5bL6FLBKEl+Tj4KFY01ZOeZVb4=';
    assert.deepEqual(psst.parseRevealFragment('#' + key, true), { version: 0, key, token: '' });
    assert.deepEqual(psst.parseRevealFragment('#' + key), { version: 0, key: '', token: '' });
    assert.deepEqual(psst.parseSubmitFragment(key), { version: 0, fingerprint: key });
    assert.deepEqual(psst.parseRevealFragment(''), { version: 0, key: '', token: '' });
});

test('unknown fragment versions and parameters are reported, not dropped', () => {
    assert.deepEqual(psst.parseRevealFragment('#v=2&reveal=ab&key=cd&extra=1'), {
        version: 2, key: 'cd', token: 'ab',
    });
    assert.deepEqual(psst.parseSubmitFragment('v=2&fp=abc'), { version: 2, fingerprint: 'abc' });
});

test('random keys and tokens round-trip', async () => {
    const key = await psst.generateKey();
    assert.equal(psst.base64ToBuf(key).byteLength, 32);
    const encrypted = await psst.encryptContent('hello', key);
    assert.equal(psst.base64ToBuf(encrypted.iv).byteLength, 12);
    assert.equal(await psst.decryptContent(encrypted.ciphertext, encrypted.iv, key), 'hello');
    const { token, tokenHash } = await psst.generateRevealAuthorization();
    assert.match(token, /^[0-9a-f]{64}$/);
    assert.match(tokenHash, /^[0-9a-f]{64}$/);
    const pair = await psst.generateRequestKeyPair();
    const sealed = await psst.sealForRecipient('hi', pair.publicKeyB64, pair.fingerprintB64);
    assert.equal(await psst.openFromSender(sealed, pair.seedB64), 'hi');
});

test('envelopes', () => {
    assert.equal(psst.textEnvelope('hi'), '{"type":"text","content":"hi"}');
    assert.equal(
        psst.textEnvelope('hi', 'markdown'), '{"type":"text","content":"hi","format":"markdown"}'
    );
    assert.deepEqual(
        JSON.parse(psst.filesEnvelope([
            { filename: 'a.txt', mimetype: 'text/plain', data: new TextEncoder().encode('file body\n') },
            { filename: 'b', mimetype: '', data: new Uint8Array([0, 255]).buffer },
        ])),
        {
            type: 'files',
            files: [
                { filename: 'a.txt', mimetype: 'text/plain', data: 'ZmlsZSBib2R5Cg==' },
                { filename: 'b', mimetype: 'application/octet-stream', data: 'AP8=' },
            ],
        }
    );
});

test('filenames from whispers are sanitized', () => {
    assert.equal(psst.sanitizeFilename('../../etc/passwd'), '_.._etc_passwd');
    assert.equal(psst.sanitizeFilename('..\\a\0b'), '_ab');
    assert.equal(psst.sanitizeFilename('.hidden'), 'hidden');
    assert.equal(psst.sanitizeFilename(''), 'download');
    assert.equal(psst.sanitizeFilename(null), 'download');
    assert.equal(psst.sanitizeFilename('...'), 'download');
    assert.equal(psst.sanitizeFilename('x'.repeat(300)).length, 200);
});
