from django.conf import settings
from django.core.checks import Error, register

from whispers.branding import is_valid_asset_url


@register()
def check_branding_urls(app_configs, **kwargs):
    errors = []
    for name in ("PSST_BRAND_LOGO_URL", "PSST_BRAND_FAVICON_URL"):
        if not is_valid_asset_url(getattr(settings, name, "")):
            errors.append(
                Error(
                    f"{name} must be an absolute http(s) URL, a path starting with '/', "
                    "or a data:image/ URI.",
                    id="whispers.E001",
                )
            )
    return errors
