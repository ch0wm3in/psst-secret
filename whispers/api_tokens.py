"""API tokens for non-browser clients, issued through a loopback redirect + PKCE sign-in.

See docs/api.md#api-tokens. Tokens and authorization codes are random, prefixed so secret
scanners can find them, and stored only as SHA-256 hashes.
"""

import base64
import hashlib
import hmac
import re
import secrets
import string
from datetime import timedelta

from django.conf import settings
from django.db import transaction
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from rest_framework.authentication import BaseAuthentication
from rest_framework.permissions import BasePermission
from rest_framework.throttling import SimpleRateThrottle, UserRateThrottle

from .models import ApiAuthorizationCode, ApiToken

AUTH_SCHEME = "Bearer"
TOKEN_PREFIX = "psst_"
CODE_PREFIX = "psstc_"
_ALPHABET = string.ascii_letters + string.digits
_RANDOM_LENGTH = 40  # about 238 bits

CODE_TTL = timedelta(seconds=60)
MANUAL_CODE_TTL = timedelta(minutes=5)
# Used codes are kept this long after expiry so a replay can still revoke its token.
USED_CODE_RETENTION = timedelta(hours=1)
LAST_USED_RESOLUTION = timedelta(minutes=1)

MANUAL_REDIRECT_URI = "urn:ietf:wg:oauth:2.0:oob"
SCOPES = {
    "whisper:create": _("Create whispers and submit to receive requests"),
    "whisper:read": _("Reveal whispers"),
    "request:manage": _("Create receive requests and manage their reader access"),
}

# Only IP literals: "localhost" can be resolved or bound by another process.
_LOOPBACK_REDIRECT_RE = re.compile(
    r"\Ahttp://(?P<host>127\.0\.0\.1|\[::1\]):(?P<port>[1-9][0-9]{0,4})"
    r"(?P<path>/[A-Za-z0-9._~/-]*)?\Z"
)
_CODE_CHALLENGE_RE = re.compile(r"\A[A-Za-z0-9_-]{43}\Z")
_CODE_VERIFIER_RE = re.compile(r"\A[A-Za-z0-9._~-]{43,128}\Z")
_STATE_RE = re.compile(r"\A[\x21-\x7e]{1,256}\Z")
_CLIENT_NAME_MAX = 64


def api_tokens_enabled():
    return getattr(settings, "ENABLE_AUTH", False) and getattr(
        settings, "PSST_ENABLE_API_TOKENS", False
    )


def manual_code_enabled():
    return api_tokens_enabled() and getattr(
        settings, "PSST_ENABLE_API_TOKEN_MANUAL_CODE", False
    )


def hash_secret(value):
    return hashlib.sha256(value.encode()).hexdigest()


def _random_secret(prefix):
    return prefix + "".join(secrets.choice(_ALPHABET) for _ in range(_RANDOM_LENGTH))


def s256_challenge(code_verifier):
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


class AuthorizationRequestError(ValueError):
    pass


def validate_redirect_uri(redirect_uri, allow_manual=False):
    if allow_manual and redirect_uri == MANUAL_REDIRECT_URI:
        return redirect_uri
    match = _LOOPBACK_REDIRECT_RE.match(redirect_uri or "")
    if not match or int(match["port"]) > 65535:
        raise AuthorizationRequestError(
            _(
                "The redirect address must be a loopback address such as "
                "http://127.0.0.1:<port>/callback or http://[::1]:<port>/callback."
            )
        )
    return redirect_uri


def validate_authorization_request(params):
    """Validate authorize parameters and return them normalized.

    Raises AuthorizationRequestError with a user-facing message. Callers must never
    redirect when validation fails.
    """
    response_type = params.get("response_type", "code")
    if response_type != "code":
        raise AuthorizationRequestError(_("Unsupported response type."))
    redirect_uri = validate_redirect_uri(
        params.get("redirect_uri", ""), allow_manual=manual_code_enabled()
    )
    if params.get("code_challenge_method") != "S256":
        raise AuthorizationRequestError(
            _("The client must use the S256 code challenge method.")
        )
    code_challenge = params.get("code_challenge", "")
    if not _CODE_CHALLENGE_RE.match(code_challenge):
        raise AuthorizationRequestError(_("The code challenge is missing or invalid."))
    state = params.get("state", "")
    if not _STATE_RE.match(state):
        raise AuthorizationRequestError(_("The state parameter is missing or invalid."))
    client_name = " ".join(params.get("client_name", "").split())
    if len(client_name) > _CLIENT_NAME_MAX or not client_name.isprintable():
        raise AuthorizationRequestError(_("The client name is invalid."))
    requested = params.get("scope", "").split() or list(SCOPES)
    if any(scope not in SCOPES for scope in requested):
        raise AuthorizationRequestError(_("The client requested an unknown scope."))
    scopes = [scope for scope in SCOPES if scope in requested]
    return {
        "redirect_uri": redirect_uri,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "state": state,
        "client_name": client_name,
        "scope": " ".join(scopes),
        "scopes": scopes,
        "manual": redirect_uri == MANUAL_REDIRECT_URI,
    }


def create_authorization_code(user, request_data):
    code = _random_secret(CODE_PREFIX)
    ttl = MANUAL_CODE_TTL if request_data["manual"] else CODE_TTL
    ApiAuthorizationCode.objects.create(
        user=user,
        code_hash=hash_secret(code),
        client_name=request_data["client_name"],
        scopes=request_data["scope"],
        code_challenge=request_data["code_challenge"],
        redirect_uri=request_data["redirect_uri"],
        expires_at=timezone.now() + ttl,
    )
    return code


class TokenExchangeError(ValueError):
    pass


def exchange_code(code, code_verifier, redirect_uri):
    """Exchange an authorization code for a new token. Returns ``(token, raw_token)``.

    A code works once. Presenting a used code again revokes the token it issued.
    """
    invalid = TokenExchangeError(_("The authorization code is invalid or expired."))
    if not isinstance(code, str) or not code.startswith(CODE_PREFIX):
        raise invalid
    if not isinstance(code_verifier, str) or not _CODE_VERIFIER_RE.match(
        code_verifier
    ):
        raise TokenExchangeError(_("The code verifier is missing or invalid."))
    if not isinstance(redirect_uri, str):
        raise invalid

    now = timezone.now()
    token = raw_token = None
    # Decide inside the transaction, raise after it, so that marking a code as used
    # and revoking on replay are committed even when the exchange fails.
    with transaction.atomic():
        auth_code = (
            ApiAuthorizationCode.objects.select_for_update()
            .select_related("user")
            .filter(code_hash=hash_secret(code))
            .first()
        )
        if auth_code is None:
            pass
        elif not ApiAuthorizationCode.objects.filter(
            pk=auth_code.pk, used_at__isnull=True
        ).update(used_at=now):
            if auth_code.token_id is not None:
                ApiToken.objects.filter(pk=auth_code.token_id).delete()
        elif (
            auth_code.expires_at > now
            and auth_code.user.is_active
            and hmac.compare_digest(auth_code.redirect_uri.encode(), redirect_uri.encode())
            and hmac.compare_digest(
                s256_challenge(code_verifier).encode(), auth_code.code_challenge.encode()
            )
        ):
            raw_token = _random_secret(TOKEN_PREFIX)
            token = ApiToken.objects.create(
                user=auth_code.user,
                token_hash=hash_secret(raw_token),
                client_name=auth_code.client_name,
                scopes=auth_code.scopes,
                expires_at=now + timedelta(seconds=settings.PSST_API_TOKEN_TTL),
            )
            auth_code.token = token
            auth_code.save(update_fields=["token"])
    if token is None:
        raise invalid
    return token, raw_token


def authenticate_token(raw_token):
    """Return the active, unexpired token for ``raw_token``, or None."""
    if not raw_token.startswith(TOKEN_PREFIX) or len(raw_token) > 100:
        return None
    token = (
        ApiToken.objects.select_related("user")
        .filter(token_hash=hash_secret(raw_token))
        .first()
    )
    if token is None or token.is_expired or not token.user.is_active:
        return None
    now = timezone.now()
    if token.last_used_at is None or now - token.last_used_at >= LAST_USED_RESOLUTION:
        ApiToken.objects.filter(pk=token.pk).update(last_used_at=now)
        token.last_used_at = now
    return token


def delete_expired():
    """Delete expired tokens and stale authorization codes. Returns the token count."""
    now = timezone.now()
    ApiAuthorizationCode.objects.filter(
        expires_at__lte=now - USED_CODE_RETENTION
    ).delete()
    count, _deleted = ApiToken.objects.filter(expires_at__lte=now).delete()
    return count


class BearerTokenAuthentication(BaseAuthentication):
    """DRF side of ApiTokenMiddleware, which has already validated the token.

    Returning the user here means SessionAuthentication, and its CSRF check, never runs
    for token requests.
    """

    def authenticate(self, request):
        token = getattr(request._request, "api_token", None)
        if token is None:
            return None
        return (token.user, token)

    def authenticate_header(self, request):
        return AUTH_SCHEME


class TokenScopePermission(BasePermission):
    """Limit token requests to the view's ``required_scope``. Other requests pass."""

    message = _("This token does not have the required scope.")

    def has_permission(self, request, view):
        if not isinstance(request.auth, ApiToken):
            return True
        scope = getattr(view, "required_scope", None)
        return scope is None or scope in request.auth.scope_list


def _configured_rate(scope):
    return settings.REST_FRAMEWORK["DEFAULT_THROTTLE_RATES"].get(scope)


class ApiTokenUserThrottle(UserRateThrottle):
    """Per-user rate limit for token-authenticated requests."""

    scope = "api_token_user"

    def get_rate(self):
        return _configured_rate(self.scope)

    def get_cache_key(self, request, view):
        if not isinstance(request.auth, ApiToken):
            return None
        return self.cache_format % {"scope": self.scope, "ident": request.user.pk}


class TokenExchangeThrottle(SimpleRateThrottle):
    """Per-IP rate limit for the token endpoint."""

    scope = "api_token_exchange"

    def get_rate(self):
        return _configured_rate(self.scope)

    def get_cache_key(self, request, view):
        return self.cache_format % {
            "scope": self.scope,
            "ident": self.get_ident(request),
        }


# Registers the OpenAPI security scheme for BearerTokenAuthentication.
from whispers import schema  # noqa: E402,F401
