import uuid

from django.db import models
from django.utils import timezone


class Whisper(models.Model):
    """
    Stores an encrypted whisper. The server NEVER sees plaintext.
    The encryption key lives only in the URL fragment (#key) which
    is never sent to the server.
    """

    class ExpiryChoices(models.TextChoices):
        FIVE_MINUTES = "5m", "5 Minutes"
        ONE_HOUR = "1h", "1 Hour"
        ONE_DAY = "1d", "1 Day"
        ONE_WEEK = "1w", "1 Week"
        ONE_MONTH = "1M", "1 Month"

    class ModeChoices(models.TextChoices):
        SEND = "send", "Send"
        RECEIVE = "receive", "Receive"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    mode = models.CharField(
        max_length=7,
        choices=ModeChoices.choices,
        default=ModeChoices.SEND,
    )
    burn_after_read = models.BooleanField(default=False)
    allowed_cidr = models.CharField(
        max_length=43,
        blank=True,
        default="",
        help_text="IP or CIDR restricting who can view (send) or submit (receive)",  # noqa: E501
    )
    require_auth_view = models.BooleanField(
        default=False,
        help_text="Require authentication to view/retrieve this whisper",
    )
    require_auth_submit = models.BooleanField(
        default=False,
        help_text="Require authentication to submit to this receive-mode request",
    )
    notify_email = models.EmailField(
        max_length=254,
        blank=True,
        default="",
        help_text="Email address to notify (receiver in send mode, creator in receive mode)",
    )
    expiry_option = models.CharField(
        max_length=5,
        choices=ExpiryChoices.choices,
        default=ExpiryChoices.ONE_DAY,
    )
    expires_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"Whisper {self.id} (created {self.created_at})"

    @property
    def is_expired(self):
        if self.expires_at is None:
            return False
        return timezone.now() >= self.expires_at
