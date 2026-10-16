import re
from urllib.parse import quote, urlsplit

from django.conf import settings

DEFAULT_BRAND_NAME = "psst-secret"
_DEFAULT_FAVICON_COLOR = "#2dd4bf"
_HEX_COLOR = re.compile(r"#(?:[0-9a-fA-F]{3}){1,2}")
# Heroicons lock-closed (solid), MIT License, Tailwind Labs
_LOCK_PATH = (
    "M12 1.5a5.25 5.25 0 0 0-5.25 5.25v3a3 3 0 0 0-3 3v6.75a3 3 0 0 0 3 3h10.5a3 3 0 0 0 "
    "3-3v-6.75a3 3 0 0 0-3-3v-3c0-2.9-2.35-5.25-5.25-5.25Zm3.75 8.25v-3a3.75 3.75 0 1 0-7.5 "
    "0v3h7.5Z"
)


def _default_favicon_url():
    color = getattr(settings, "BRAND_COLORS", {}).get("400", "")
    if not isinstance(color, str) or not _HEX_COLOR.fullmatch(color):
        color = _DEFAULT_FAVICON_COLOR
    svg = (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="{color}">'
        f'<path fill-rule="evenodd" clip-rule="evenodd" d="{_LOCK_PATH}"/></svg>'
    )
    return "data:image/svg+xml," + quote(svg)


def _is_absolute_http_url(url):
    try:
        parts = urlsplit(url)
        return parts.scheme.lower() in ("http", "https") and bool(parts.hostname)
    except ValueError:
        return False


def is_valid_asset_url(url):
    """Accept absolute http(s) URLs, root-relative paths and data:image/ URIs."""
    if not url:
        return True
    if url.startswith("/"):
        return not url.startswith("//")
    return url.lower().startswith("data:image/") or _is_absolute_http_url(url)


def get_branding():
    logo_url = getattr(settings, "PSST_BRAND_LOGO_URL", "")
    brand_name = getattr(settings, "PSST_BRAND_NAME", "") or DEFAULT_BRAND_NAME
    return {
        "brand_name": brand_name,
        "brand_is_default": brand_name == DEFAULT_BRAND_NAME,
        "brand_logo_url": logo_url,
        # Email clients cannot resolve relative paths and commonly block data URIs;
        # whispers.email attaches data: logos inline instead.
        "brand_email_logo_url": logo_url if _is_absolute_http_url(logo_url) else "",
        "brand_favicon_url": getattr(settings, "PSST_BRAND_FAVICON_URL", ""),
        "default_favicon_url": _default_favicon_url(),
        "hide_social_links": getattr(settings, "PSST_HIDE_SOCIAL_LINKS", False),
        "hide_footer_text": getattr(settings, "PSST_HIDE_FOOTER_TEXT", False),
        "hide_nav_brand_name": getattr(settings, "PSST_HIDE_NAV_BRAND_NAME", False),
    }
