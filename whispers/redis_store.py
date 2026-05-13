import json
import logging

import redis
from django.conf import settings

logger = logging.getLogger(__name__)

_client = None


def get_client():
    global _client
    if _client is None:
        _client = redis.from_url(settings.REDIS_URL, decode_responses=True)
    return _client


def _key(whisper_id):
    return f"whisper:{whisper_id}"


def _views_key(whisper_id):
    return f"whisper:views:{whisper_id}"


def store_crypto(
    whisper_id,
    ttl_seconds,
    *,
    ciphertext="",
    iv="",
    salt="",
    password_verify_token="",
    password_verify_iv="",
):
    """Store crypto fields in Redis with a TTL (seconds)."""
    payload = json.dumps(
        {
            "ciphertext": ciphertext,
            "iv": iv,
            "salt": salt,
            "password_verify_token": password_verify_token,
            "password_verify_iv": password_verify_iv,
        }
    )
    get_client().setex(_key(whisper_id), int(ttl_seconds), payload)


def get_crypto(whisper_id):
    """Return dict of crypto fields, or None if the key is gone."""
    raw = get_client().get(_key(whisper_id))
    if raw is None:
        return None
    return json.loads(raw)


def update_crypto(whisper_id, **fields):
    """Atomically merge *fields* into the existing Redis blob, keeping the
    current TTL.  Uses WATCH/MULTI/EXEC for optimistic locking to avoid
    read-modify-write races."""
    client = get_client()
    key = _key(whisper_id)
    with client.pipeline() as pipe:
        while True:
            try:
                pipe.watch(key)
                raw = pipe.get(key)
                if raw is None:
                    return False
                data = json.loads(raw)
                data.update(fields)
                ttl = pipe.ttl(key)
                pipe.multi()
                if ttl and ttl > 0:
                    pipe.setex(key, ttl, json.dumps(data))
                else:
                    pipe.set(key, json.dumps(data))
                pipe.execute()
                return True
            except redis.WatchError:
                continue


def get_and_delete_crypto(whisper_id):
    """Atomically get and delete the crypto blob (for burn-after-read).
    Returns the dict, or None if the key was already gone."""
    client = get_client()
    key = _key(whisper_id)
    with client.pipeline() as pipe:
        while True:
            try:
                pipe.watch(key)
                raw = pipe.get(key)
                if raw is None:
                    return None
                pipe.multi()
                pipe.delete(key)
                pipe.execute()
                return json.loads(raw)
            except redis.WatchError:
                continue


def delete_crypto(whisper_id):
    """Remove the crypto blob from Redis (burn-after-read / manual cleanup)."""
    client = get_client()
    client.delete(_key(whisper_id))
    client.delete(_views_key(whisper_id))


def get_view_count(whisper_id):
    """Return the current view count for a whisper (0 if never viewed)."""
    raw = get_client().get(_views_key(whisper_id))
    try:
        return int(raw) if raw is not None else 0
    except TypeError, ValueError:
        return 0


def increment_and_reveal(whisper_id, max_views):
    """Atomically increment the view counter and fetch the ciphertext.

    Returns a tuple ``(crypto_dict_or_None, count, exhausted)``:
      * ``crypto_dict_or_None`` — the crypto payload, or ``None`` if the blob
        has already been destroyed/expired.
      * ``count`` — the new view count after this reveal.
      * ``exhausted`` — True when ``max_views > 0`` and the data was destroyed
        as part of this reveal (i.e. this was the final allowed view).

    ``max_views == 0`` means "unlimited" — the counter still increments for
    visibility, but the data is never destroyed by this function.
    """
    client = get_client()
    key = _key(whisper_id)
    counter_key = _views_key(whisper_id)

    # Atomic INCR; redis creates the key at 0 if absent.
    count = client.incr(counter_key)

    # On first view, align the counter TTL with the data TTL so it doesn't
    # outlive the whisper.
    if count == 1:
        ttl = client.ttl(key)
        if ttl and ttl > 0:
            client.expire(counter_key, ttl)

    exhausted = max_views > 0 and count >= max_views
    if exhausted:
        # Atomically read and delete the data + counter.
        with client.pipeline() as pipe:
            pipe.get(key)
            pipe.delete(key)
            pipe.delete(counter_key)
            raw = pipe.execute()[0]
        if raw is None:
            return None, count, True
        return json.loads(raw), count, True

    raw = client.get(key)
    if raw is None:
        return None, count, False
    return json.loads(raw), count, False
