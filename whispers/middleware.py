import re

from django.conf import settings
from django.http import JsonResponse
from django.shortcuts import redirect
from django.utils.translation import gettext as _

# Versioned endpoints are exempt whenever the unversioned path serving the same view is.
_V1_ALIASES = (
    (re.compile(r"api/v1/whisper/([0-9a-f-]+)/reveal$"), r"whisper/\1"),
    (re.compile(r"api/v1/(whisper(?:/.*)?)$"), r"api/\1"),
)


# Sign-in and discovery endpoints for API clients; the authorize page redirects to the
# login page itself so its query string is kept.
_ALWAYS_EXEMPT = re.compile(r"(api/v1/info|api/v1/cli/token|cli/authorize)$")


def _is_api_path(path):
    """Return whether ``path`` (without leading slash) is a versioned API endpoint."""
    return path.startswith("api/v1/")


def _unauthorized(message, error=None):
    from whispers.api_tokens import AUTH_SCHEME

    response = JsonResponse({"error": message}, status=401)
    challenge = AUTH_SCHEME
    if error:
        challenge += f' error="{error}"'
    response["WWW-Authenticate"] = challenge
    return response


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
            if _ALWAYS_EXEMPT.match(path):
                return self.get_response(request)
            if not is_login_exempt(path, self.exempt_patterns):
                if _is_api_path(path):
                    return _unauthorized(_("Authentication required"))
                login_url = getattr(settings, "LOGIN_URL", "/accounts/login/")
                return redirect(f"{login_url}?next={request.path}")
        return self.get_response(request)


class ApiTokenMiddleware:
    """Authenticate API token requests to ``/api/v1/`` before LoginRequiredMiddleware.

    A valid token replaces ``request.user`` so the login requirement, forced-auth
    settings and view checks all see the token's user. An invalid, expired or revoked
    token, or one belonging to an inactive user, gets a JSON 401.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        from whispers.api_tokens import (
            AUTH_SCHEME,
            api_tokens_enabled,
            authenticate_token,
        )

        header = request.META.get("HTTP_AUTHORIZATION", "")
        scheme, _sep, credentials = header.partition(" ")
        if (
            scheme.lower() == AUTH_SCHEME.lower()
            and _is_api_path(request.path_info.lstrip("/"))
            and api_tokens_enabled()
        ):
            token = authenticate_token(credentials.strip())
            if token is None:
                return _unauthorized(
                    _("The API token is invalid, expired or revoked."), "invalid_token"
                )
            request.user = token.user
            request.api_token = token
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
