from django.core.management.base import BaseCommand
from django.utils import timezone

from whispers import redis_store
from whispers.models import Whisper
from whispers.stats import prune_stats


class Command(BaseCommand):
    help = "Delete all expired whispers from the database and Redis."

    def handle(self, *args, **options):
        expired = Whisper.objects.filter(expires_at__lte=timezone.now())
        ids = list(expired.values_list("id", flat=True))

        for whisper_id in ids:
            redis_store.delete_crypto(whisper_id)

        count, _ = expired.delete()
        stats_count = prune_stats()
        self.stdout.write(
            self.style.SUCCESS(f"Deleted {stats_count} expired statistics bucket(s).")
        )
        self.stdout.write(
            self.style.SUCCESS(f"Deleted {count} expired whisper(s).")
        )  # noqa: E501
