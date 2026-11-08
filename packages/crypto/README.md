# @psst-secret/crypto

The encryption format of [psst-secret](https://github.com/ch0wm3in/psst-secret):
AES-256-GCM, PBKDF2 password keys, X-Wing (ML-KEM-768 + X25519) receive mode, link
fragments, and reveal tokens. The psst-secret web UI uses this package, and other
clients can use it to read and write the same whispers.

The [format specification](https://github.com/ch0wm3in/psst-secret/blob/main/docs/format.md)
is normative. The package is tested against the shared
[test vectors](https://github.com/ch0wm3in/psst-secret/tree/main/spec/vectors).

## Versions

The major version is the format version: `1.x.y` writes format version 1 and reads
versions 0 and 1. Minor and patch releases never change the bytes the package produces.

## Requirements

An ES module environment with the Web Crypto API on `globalThis.crypto`: current
browsers, browser extensions, or Node.js 20 or later. The package does not use the DOM.

## Usage

```js
import {
    generateKey, encryptContent, generateRevealAuthorization, revealFragment,
    parseRevealFragment, isReadableFormat, decryptContent, textEnvelope, FORMAT_VERSION,
} from '@psst-secret/crypto';

// Send a whisper.
const key = await generateKey();
const { ciphertext, iv, salt } = await encryptContent(textEnvelope('Hello, whisper!'), key);
const { token, tokenHash } = await generateRevealAuthorization();
// POST { v: FORMAT_VERSION, ciphertext, iv, salt, reveal_token_hash: tokenHash, ... }
// to /api/v1/whisper, then share:
const link = url + revealFragment(key, token);

// Read it.
const fragment = parseRevealFragment(new URL(link).hash);
if (!isReadableFormat(fragment.version)) throw new Error('Unsupported format version');
// POST { reveal_token: fragment.token } to the reveal endpoint, then:
const envelope = JSON.parse(await decryptContent(data.ciphertext, data.iv, fragment.key));
```

Every function is documented in [`src/index.js`](src/index.js), with types in
[`src/index.d.ts`](src/index.d.ts). See the
[API documentation](https://github.com/ch0wm3in/psst-secret/blob/main/docs/api.md) for the
HTTP endpoints.

## Errors

`sealForRecipient` throws a `FormatError` with `code === 'fingerprint_mismatch'` when the
request public key does not match the fingerprint in the submit link. Web Crypto errors,
such as a wrong key or password, are passed through.
