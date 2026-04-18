from datetime import timedelta

EXPIRY_DELTAS = {
    "5m": timedelta(minutes=5),
    "1h": timedelta(hours=1),
    "1d": timedelta(days=1),
    "1w": timedelta(weeks=1),
    "1M": timedelta(days=30),
}
