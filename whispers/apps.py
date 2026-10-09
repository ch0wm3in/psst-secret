import logging
import threading
import time

from django.apps import AppConfig

logger = logging.getLogger(__name__)


def _cleanup_loop():
    """Background loop that purges expired whispers and prunes stats(if enabled) every 60s."""
    from django.utils import timezone

    # Wait for DB to be ready
    logger.info("Starting cleanup loop every 60 seconds")
    time.sleep(5)
    while True:
        try:
            from whispers import redis_store
            from whispers.models import Whisper

            expired = Whisper.objects.filter(expires_at__lte=timezone.now())
            for whisper_id in expired.values_list("id", flat=True):
                redis_store.delete_crypto(whisper_id)
            expired.delete()
        except Exception as e:
            logger.exception("Error cleaning up expired whispers: %s", e)
        try:
            from whispers.stats import prune_stats

            prune_stats()
        except Exception as e:
            logger.exception("Error pruning stats: %s", e)
        time.sleep(60)


class WhispersConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "whispers"

    def ready(self):
        t = threading.Thread(target=_cleanup_loop, daemon=True)
        t.start()
