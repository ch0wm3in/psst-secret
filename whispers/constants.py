from datetime import timedelta

# See docs/format.md. Version 0 is the unmarked legacy format, accepted only when reading.
FORMAT_VERSION = 1
SUPPORTED_FORMAT_VERSIONS = (1,)
API_VERSION = 1

EXPIRY_DELTAS = {
    "5m": timedelta(minutes=5),
    "1h": timedelta(hours=1),
    "1d": timedelta(days=1),
    "1w": timedelta(weeks=1),
    "1M": timedelta(days=30),
}
