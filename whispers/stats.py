import logging
from datetime import timedelta
from datetime import timezone as datetime_timezone

from django.conf import settings
from django.db import transaction
from django.db.models import F
from django.utils import timezone
from django.utils.translation import gettext as _

from .constants import EXPIRY_DELTAS
from .models import HourlyWhisperStats

logger = logging.getLogger(__name__)
RETENTION = timedelta(days=365)
RANGES = (("1d", 1), ("1w", 7), ("1m", 30), ("3m", 90), ("6m", 180), ("1y", 365))


def prune_stats(now=None):
    return HourlyWhisperStats.objects.filter(
        bucket_start__lt=(now or timezone.now()) - RETENTION
    ).delete()[0]


def record_stats(event, *, mode=None, max_views=None, expiry=None):
    if not settings.PSST_ENABLE_STATS:
        return
    increments = {}
    if (
        event == "submission"
        and mode in ("send", "receive")
        and expiry in EXPIRY_DELTAS
    ):
        increments["sends" if mode == "send" else "receives"] = 1
        increments["burn_after_read"] = int(max_views == 1)
        increments[f"expiry_{expiry}"] = 1
    elif event == "reveal":
        increments["reveals"] = 1
    else:
        raise ValueError("Unknown statistics event")
    bucket = (
        timezone.now()
        .astimezone(datetime_timezone.utc)
        .replace(minute=0, second=0, microsecond=0)
    )
    try:
        with transaction.atomic():
            HourlyWhisperStats.objects.get_or_create(bucket_start=bucket)
            HourlyWhisperStats.objects.filter(bucket_start=bucket).update(
                **{field: F(field) + count for field, count in increments.items()}
            )
    except Exception:
        logger.warning("Anonymous statistics update failed")


def stats_report(preset="1w", now=None):
    now = (now or timezone.now()).astimezone(datetime_timezone.utc)
    days = dict(RANGES).get(preset)
    if days is None:
        preset, days = "1w", 7
    start = max(
        (now - timedelta(days=days)).replace(minute=0, second=0, microsecond=0),
        now - RETENTION,
    )
    prune_stats(now)
    rows = list(
        HourlyWhisperStats.objects.filter(
            bucket_start__gte=start, bucket_start__lte=now
        )
        .order_by("bucket_start")
        .values()
    )
    fields = [
        field.name
        for field in HourlyWhisperStats._meta.fields
        if field.name != "bucket_start"
    ]
    totals = {field: sum(row[field] for row in rows) for field in fields}
    total = totals["sends"] + totals["receives"]
    daily = {}
    current = start.date()
    while current <= now.date():
        daily[current] = 0
        current += timedelta(days=1)
    weekdays = [0] * 7
    for row in rows:
        count = row["sends"] + row["receives"]
        day = row["bucket_start"].date()
        daily[day] += count
        weekdays[day.weekday()] += count
    weekday_names = [
        _("Monday"),
        _("Tuesday"),
        _("Wednesday"),
        _("Thursday"),
        _("Friday"),
        _("Saturday"),
        _("Sunday"),
    ]
    peak = max(daily.values(), default=0)
    weekday_peak = max(weekdays, default=0)
    trend = []
    group_size = 7 if len(daily) > 60 else 1
    daily_items = list(daily.items())
    for offset in range(0, len(daily_items), group_size):
        group = daily_items[offset : offset + group_size]
        trend.append(
            {
                "start": group[0][0],
                "end": group[-1][0],
                "count": sum(count for _, count in group),
            }
        )
    trend_peak = max((item["count"] for item in trend), default=0)
    for item in trend:
        item["height"] = round(item["count"] / trend_peak * 100, 2) if trend_peak else 0
    expiry_names = {
        "5m": _("5 minutes"),
        "1h": _("1 hour"),
        "1d": _("1 day"),
        "1w": _("1 week"),
        "1M": _("1 month"),
    }
    return {
        "preset": preset,
        "start": start,
        "end": now,
        "total": total,
        **totals,
        "average": total / ((now - start).total_seconds() / 86400),
        "burn_share": totals["burn_after_read"] / total * 100 if total else 0,
        "busiest_days": [day for day, count in daily.items() if peak and count == peak],
        "busiest_weekdays": [
            weekday_names[index]
            for index, count in enumerate(weekdays)
            if weekday_peak and count == weekday_peak
        ],
        "trend": trend,
        "weekly_trend": group_size == 7,
        "daily": [{"day": day, "count": count} for day, count in daily.items()],
        "weekdays": [
            {
                "name": weekday_names[index],
                "count": count,
                "width": count / weekday_peak * 100 if weekday_peak else 0,
            }
            for index, count in enumerate(weekdays)
        ],
        "expiry_choices": [
            {
                "name": expiry_names[choice],
                "count": totals[f"expiry_{choice}"],
                "width": totals[f"expiry_{choice}"] / total * 100 if total else 0,
            }
            for choice in EXPIRY_DELTAS
        ],
    }
