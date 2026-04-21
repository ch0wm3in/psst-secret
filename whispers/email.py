import logging

from django.conf import settings
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string

logger = logging.getLogger(__name__)


def _email_enabled():
    """Check if email notifications are enabled."""
    return getattr(settings, "PSST_ENABLE_EMAIL", False)


def send_whisper_created_email(notify_email, whisper_url):
    """Send notification to the receiver that a whisper has been created.

    The URL sent is intentionally incomplete — it does NOT contain the
    decryption key (URL fragment).  The sender must share the key or full
    URL through a separate channel.
    """
    if not _email_enabled() or not notify_email:
        return

    subject = "You have received a whisper!"
    context = {"whisper_url": whisper_url, "brand": settings.BRAND_COLORS}
    text_body = render_to_string("whispers/email/whisper_created.txt", context)
    html_body = render_to_string("whispers/email/whisper_created.html", context)

    try:
        msg = EmailMultiAlternatives(
            subject=subject,
            body=text_body,
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=[notify_email],
        )
        msg.attach_alternative(html_body, "text/html")
        msg.send(fail_silently=False)
    except Exception:
        logger.exception(
            "Failed to send whisper-created notification to %s", notify_email
        )


def send_whisper_submitted_email(notify_email, view_url):
    """Send notification to the request creator that a whisper has been submitted.

    The URL sent is intentionally incomplete — it does NOT contain the
    decryption key (URL fragment).  The creator must already have the key
    from when they created the request.
    """
    if not _email_enabled() or not notify_email:
        return

    subject = "A whisper has been submitted to your request!"
    context = {"view_url": view_url, "brand": settings.BRAND_COLORS}
    text_body = render_to_string("whispers/email/whisper_submitted.txt", context)
    html_body = render_to_string("whispers/email/whisper_submitted.html", context)

    try:
        msg = EmailMultiAlternatives(
            subject=subject,
            body=text_body,
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=[notify_email],
        )
        msg.attach_alternative(html_body, "text/html")
        msg.send(fail_silently=False)
    except Exception:
        logger.exception(
            "Failed to send whisper-submitted notification to %s", notify_email
        )
