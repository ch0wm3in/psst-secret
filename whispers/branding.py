from django.conf import settings

DEFAULT_BRAND_NAME = "psst-secret"

_ALLOWED_URL_PREFIXES = ("https://", "http://", "data:image/")


def is_valid_asset_url(url):
    """Accept absolute http(s) URLs, root-relative paths and data:image/ URIs."""
    if not url:
        return True
    if url.startswith("/"):
        return not url.startswith("//")
    return url.lower().startswith(_ALLOWED_URL_PREFIXES)


def get_branding():
    logo_url = getattr(settings, "PSST_BRAND_LOGO_URL", "")
    brand_name = getattr(settings, "PSST_BRAND_NAME", "") or DEFAULT_BRAND_NAME
    return {
        "brand_name": brand_name,
        "brand_is_default": brand_name == DEFAULT_BRAND_NAME,
        "brand_logo_url": logo_url,
        # Email clients cannot resolve relative paths and commonly block data URIs.
        "brand_email_logo_url": (
            logo_url if logo_url.lower().startswith(("https://", "http://")) else ""
        ),
        "brand_favicon_url": getattr(settings, "PSST_BRAND_FAVICON_URL", ""),
        "hide_social_links": getattr(settings, "PSST_HIDE_SOCIAL_LINKS", False),
        "hide_footer_text": getattr(settings, "PSST_HIDE_FOOTER_TEXT", False),
        "hide_nav_brand_name": getattr(settings, "PSST_HIDE_NAV_BRAND_NAME", False),
    }
