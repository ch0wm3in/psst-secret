import re

from django.conf import settings
from django.shortcuts import redirect


class LoginRequiredMiddleware:
    """Require authentication for all URLs except those matching
    LOGIN_REQUIRED_EXEMPT_URLS patterns defined in settings.

    Add regex patterns (strings) to settings.LOGIN_REQUIRED_EXEMPT_URLS
    to exempt specific paths.  The login and static-file URLs are always
    exempt.
    """

    def __init__(self, get_response):
        self.get_response = get_response
        raw = getattr(settings, "LOGIN_REQUIRED_EXEMPT_URLS", [])
        self.exempt_patterns = [re.compile(p) for p in raw]

    def __call__(self, request):
        if not request.user.is_authenticated:
            path = request.path_info.lstrip("/")
            if not any(p.match(path) for p in self.exempt_patterns):
                login_url = getattr(settings, "LOGIN_URL", "/accounts/login/")
                return redirect(f"{login_url}?next={request.path}")
        return self.get_response(request)


class NoCacheMiddleware:
    """Add no-cache headers to all responses."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        response["Cache-Control"] = (
            "no-cache, no-store, must-revalidate, private"  # noqa: E501
        )
        response["Pragma"] = "no-cache"
        response["Expires"] = "0"
        return response
