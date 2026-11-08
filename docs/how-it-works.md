# How it works

psst-secret is zero-knowledge: whispers are encrypted and decrypted in the browser, and
the server only ever handles ciphertext, public keys, and metadata.

## Storage model

| Store | What it holds | Persistence |
|---|---|---|
| **Redis** | Ciphertext, IV, PBKDF2 salt, receive-mode public key, key encapsulation, password-encrypted private key seed and its IV, reveal-token hash, view counter, receive-mode submitted flag (lets [status checks](api.md#receive-request-status) skip reading the ciphertext) | In memory only by default (`--save "" --appendonly no`) |
| **PostgreSQL / SQLite** | Metadata: view identifier, separate submit token, timestamps, mode, view limit, IP restriction, auth flags, optional notification email, receive creator and approved readers. With [API tokens](api.md#api-tokens) enabled, also SHA-256 hashes of API tokens and sign-in codes with their user, client name, scopes, and times | On disk |

With the default configuration, encrypted data never touches disk, and a Redis restart
deletes every whisper by design. The server never stores plaintext, unencrypted private
keys, or passwords. Email addresses are stored only if you opt in to notifications.

A [persistence-enabled Compose example](../docker-compose-with-persistence-example.yml)
is available for deployments that need whispers to survive restarts. It writes encrypted
data to disk but never gives the server decryption keys. Set
`ABOUT_PAGE_PERSISTENCE_ENABLED=True` so the About page describes the deployment
accurately.

## Send mode

1. You write a whisper (text or file). The browser generates a random AES-256-GCM key
   and encrypts it locally.
2. Only the ciphertext and encryption parameters are uploaded, together with the
   SHA-256 hash of an independent random [reveal token](#reveal-tokens).
3. The link fragment contains the token and key: `#v=1&reveal=TOKEN&key=KEY`.
4. The recipient's browser sends only the token to reveal the ciphertext, then decrypts
   it with the key from the fragment.

With a password, the key is derived from it with PBKDF2 (600,000 iterations,
SHA-256) and the fragment contains only the format version and `reveal=TOKEN`. Share
the password separately. The server stores only the random salt.

Send mode is purely symmetric. Grover's algorithm at most reduces AES-256 to 128-bit
security, and Shor's algorithm does not apply.

## Receive mode

1. You create a request. The browser generates an **X-Wing** key pair, a hybrid of
   ML-KEM-768 (post-quantum, FIPS 203) and X25519.
2. The server stores the public key and the reveal-token hash. You get two links:
   - a **submit link** with a separate random identifier and the public-key fingerprint;
   - a **view link** with the reveal token and private key seed in its fragment. With a
     password, the seed is encrypted by it instead and the sender never needs it.
3. The sender's browser checks the public key against the fingerprint, so the server
   cannot substitute its own key. The whisper is then encrypted with X-Wing,
   HKDF-SHA256, and AES-256-GCM.
4. You open the view link to reveal and decrypt the whisper locally.

The submit link cannot find, read, or burn the submitted whisper. Hybrid key exchange
stays secure as long as either ML-KEM-768 or X25519 holds, including against attackers
who record traffic today to decrypt later.

### Saved receive requests

When an operator enables [saved receive requests](configuration.md#saved-receive-requests),
users can opt in to keeping their requests in the browser's `localStorage` instead of
saving each view link themselves. This changes the threat model for that browser:

- **Stored:** the complete view link, including the reveal token and, unless the request
  has a password, the private key seed; the submit link; an optional label; and the
  expiry, view limit, and status. With a password, the seed stays encrypted on the
  server and the password is never stored.
- **Not stored:** decrypted whispers, files, or passwords. Labels never leave the
  browser.
- **Risk:** anyone who can read the browser profile, such as another person using the
  device, malware, or a script injected into this site, can open saved whispers that have
  no password. Do not turn it on for shared or untrusted devices, and use a password for
  sensitive requests.
- **Cleanup:** entries are removed when they pass their expiry (checked locally), when
  the [status endpoint](api.md#receive-request-status) reports them gone, and right after
  the final allowed reveal. The browser checks the status on page loads, when it becomes
  visible, and every 30 seconds while the list or drawer is open. Status checks never
  consume a view.

With the option off, which is the default, nothing is written to browser storage.

## Links and reveal tokens

Key material lives in the URL fragment (the part after `#`), which browsers never
send to the server ([RFC 3986 §3.5](https://www.rfc-editor.org/rfc/rfc3986#section-3.5),
[RFC 9110 §7.1](https://www.rfc-editor.org/rfc/rfc9110#section-7.1)), so it never
appears in server or proxy request logs. The [encryption format](format.md) specifies
every algorithm, parameter, and fragment exactly.

### Reveal tokens

Every new whisper has a random reveal token, generated independently of the
encryption keys. Redis stores only its SHA-256 hash. The browser sends the token in the
reveal POST body, never in the URL. The server compares the hash in constant time, and
the check, view-counter increment, and final-view deletion happen in one Redis
transaction.

- Missing or invalid tokens return HTTP 403 without returning ciphertext, consuming a
  view, or deleting the whisper.
- Tokens stay valid until expiry or the final allowed reveal, so multi-view links work.
- Notification emails omit the entire fragment, so they cannot be used to reveal a
  whisper.
- The token proves possession of the link, not successful decryption. A wrong key or
  password still consumes a view; the server cannot check keys without seeing them.

**Legacy whispers.** Whispers created before reveal tokens existed remain readable
until they expire. They are still counted atomically, but anyone who knows the UUID can
reveal or burn them through the API. New whispers always require a token, and an
old-style link cannot downgrade one.

## Expiry and view limits

Whispers expire after 5 minutes to 1 month. Each whisper allows a configured number of
successful reveals: `1` burns it after the first read (the default), `0` means unlimited,
and any other value is a strict limit.

Cleanup happens in four layers:

1. **Redis TTL** evicts each key at its expiry.
2. **Atomic reveal counter**: the final permitted reveal deletes the whisper in the
   same `WATCH`/`MULTI`/`EXEC` transaction, so concurrent reveals cannot exceed the
   limit.
3. **Background thread** deletes expired database rows and Redis keys every 60
   seconds, along with expired API tokens and old sign-in codes (also available as
   `python manage.py cleanup_expired`).
4. **On-access cleanup** deletes a database row whose Redis key has already gone.

## Further security notes

- AES-256-GCM is authenticated; tampered ciphertext fails to decrypt.
- IP/CIDR restrictions limit who can view (send mode) or submit (receive mode).
- Optional per-whisper or global authentication and
  [receive reader access](configuration.md#receive-reader-access) are enforced before
  any Redis lookup or view counting. They add to client-side encryption, not replace it.
- Whisper pages are served with no-cache headers so browsers and proxies do not store them.
- [API tokens](api.md#api-tokens) are issued only after the user approves the client in a
  signed-in browser session, are redirected only to loopback addresses or to
  [browser extension addresses](api.md#browser-extensions) the server lists, and require
  PKCE. Tokens carry only the scopes the user approved and never give access to
  decryption keys, which stay in link fragments.
- The app refuses to start with `DEBUG=False` and the default `SECRET_KEY`.
- Validation errors return fixed messages, never internal exception details.

To report a vulnerability, see [SECURITY.md](../SECURITY.md).
