# isort: off
import json

from django import template
from django.conf import settings
from django.templatetags.static import static
from django.utils.html import format_html
from django.utils.safestring import mark_safe

register = template.Library()


# Try to import the provider_login_url tag from allauth, if available.
# Allauth is condtionally enabled in settings.py,
# so we need to handle the case where it's not installed.
try:
    from allauth.socialaccount.templatetags.socialaccount import (
        register as allauth_register,
    )

    register.tags["provider_login_url"] = allauth_register.tags["provider_login_url"]
except ImportError, Exception:
    # allauth not installed or socialaccount not in INSTALLED_APPS —
    # register a no-op tag so the template still compiles.
    @register.simple_tag(name="provider_login_url", takes_context=True)
    def provider_login_url_noop(context, *args, **kwargs):
        return ""


# settings value
@register.simple_tag
def settings_value(name):
    return getattr(settings, name, "")


@register.simple_tag
def icon(name, **attrs):
    """Render a heroicon from the sprite built by theme/static_src/build-icons.mjs."""
    style, _, icon_name = name.rpartition("/")
    href = f"{static('icons/heroicons.svg')}#{style or 'outline'}-{icon_name}"
    css_class = f"icon {attrs['class']}" if attrs.get("class") else "icon"
    return format_html(
        '<svg class="{}" aria-hidden="true" focusable="false"><use href="{}"></use></svg>',
        css_class,
        href,
    )


@register.filter
def to_json(
    value,
):
    # Not using user input in this filter, so no risk of XSS or code injection.
    """Serialize a Python object to a JSON string,
    safe for embedding in <script>."""
    return mark_safe(json.dumps(value))  # nosec: B703, B308


@register.filter
def filesizeformat(bytes):
    """Format bytes as human-readable file size."""
    if bytes < 1024:
        return f"{bytes} B"
    elif bytes < 1024**2:
        return f"{bytes / 1024:.1f} KB"
    elif bytes < 1024**3:
        return f"{bytes / 1024**2:.1f} MB"
    else:
        return f"{bytes / 1024**3:.1f} GB"
