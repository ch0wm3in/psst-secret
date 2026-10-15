import base64
import binascii
import logging
import mimetypes
from email.mime.base import MIMEBase
from urllib.parse import unquote_to_bytes

from django.conf import settings
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.module_loading import import_string

from whispers.branding import get_branding

logger = logging.getLogger(__name__)

_LOGO_CID = "brand-logo@psst-secret"


def _email_enabled():
    """Check if email notifications are enabled."""
    return getattr(settings, "PSST_ENABLE_EMAIL", False)


def _decode_data_image(url):
    """Return ``(subtype, bytes)`` for a ``data:image/`` URI, or ``None``."""
    header, separator, data = url.partition(",")
    if not separator or not header.lower().startswith("data:image/"):
        return None
    mimetype, *params = header[len("data:") :].split(";")
    subtype = mimetype.lower().partition("/")[2].strip()
    if not subtype:
        return None
    try:
        if "base64" in (param.strip().lower() for param in params):
            content = base64.b64decode("".join(data.split()), validate=True)
        else:
            content = unquote_to_bytes(data)
    except binascii.Error, ValueError:
        return None
    return (subtype, content) if content else None


def _uses_azure_backend():
    try:
        from django_better_azure_communication_email.backend import ACEmailBackend

        backend = import_string(settings.MAILERS["default"]["BACKEND"])
    except ImportError, KeyError, TypeError:
        return False
    return isinstance(backend, type) and issubclass(backend, ACEmailBackend)


class _BrandedEmail(EmailMultiAlternatives):
    """Nests an inline logo with the HTML part in multipart/related."""

    inline_logo = None

    def message(self, **kwargs):
        msg = super().message(**kwargs)
        if self.inline_logo:
            subtype, content, filename = self.inline_logo
            html = next(
                part for part in msg.walk() if part.get_content_type() == "text/html"
            )
            html.add_related(
                content,
                maintype="image",
                subtype=subtype,
                disposition="inline",
                filename=filename,
                cid=f"<{_LOGO_CID}>",
            )
        return msg


def _attach_inline_logo(msg, subtype, content):
    filename = "logo" + (mimetypes.guess_extension(f"image/{subtype}") or "")
    if not _uses_azure_backend():
        msg.inline_logo = (subtype, content, filename)
        return
    # The Azure backend ignores message() and only converts legacy MIMEBase
    # attachments, passing Content-ID through verbatim as the API's bare
    # contentId. Append directly to skip Django's MIMEBase deprecation warning.
    part = MIMEBase("image", subtype)
    part.set_payload(base64.b64encode(content).decode())
    part["Content-Transfer-Encoding"] = "base64"
    part["Content-ID"] = _LOGO_CID
    part.add_header("Content-Disposition", "inline", filename=filename)
    msg.attachments.append(part)


def _build_message(notify_email, subject, template, context):
    branding = get_branding()
    logo = _decode_data_image(branding["brand_logo_url"])
    if logo:
        # Email clients commonly block data URIs, so embed the image inline.
        branding["brand_email_logo_url"] = f"cid:{_LOGO_CID}"
    context = {"brand": settings.BRAND_COLORS, **branding, **context}
    text_body = render_to_string(f"whispers/email/{template}.txt", context)
    html_body = render_to_string(f"whispers/email/{template}.html", context)

    msg = _BrandedEmail(
        subject=subject,
        body=text_body,
        from_email=settings.DEFAULT_FROM_EMAIL,
        to=[notify_email],
    )
    msg.attach_alternative(html_body, "text/html")
    if logo:
        _attach_inline_logo(msg, *logo)
    return msg


def _send(notify_email, subject, template, context):
    _build_message(notify_email, subject, template, context).send(fail_silently=False)


def send_whisper_created_email(notify_email, whisper_url):
    """Send notification to the receiver that a whisper has been created.

    The URL sent is intentionally incomplete — it does NOT contain the
    decryption key (URL fragment).  The sender must share the key or full
    URL through a separate channel.
    """
    if not _email_enabled() or not notify_email:
        return

    try:
        _send(
            notify_email,
            "You have received a whisper!",
            "whisper_created",
            {"whisper_url": whisper_url},
        )
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

    try:
        _send(
            notify_email,
            "A whisper has been submitted to your request!",
            "whisper_submitted",
            {"view_url": view_url},
        )
    except Exception:
        logger.exception(
            "Failed to send whisper-submitted notification to %s", notify_email
        )
