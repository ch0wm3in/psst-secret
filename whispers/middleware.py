import re

from django.conf import settings
from django.shortcuts import redirect

# Versioned endpoints are exempt whenever the unversioned path serving the same view is.
_V1_ALIASES = (
    (re.compile(r"api/v1/whisper/([0-9a-f-]+)/reveal$"), r"whisper/\1"),
    (re.compile(r"api/v1/(whisper(?:/.*)?)$"), r"api/\1"),
)


def is_login_exempt(path, patterns):
    """Return whether ``path`` (without leading slash) matches an exempt pattern."""
    paths = [path]
    for alias, legacy in _V1_ALIASES:
        match = alias.match(path)
        if match:
            paths.append(match.expand(legacy))
            break
    return any(re.match(pattern, p) for pattern in patterns for p in paths)


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
            if not is_login_exempt(path, self.exempt_patterns):
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
