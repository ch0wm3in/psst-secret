import ipaddress
import logging
import uuid
from urllib.parse import urlencode

import redis
from django.conf import settings
from django.db import transaction
from django.http import Http404
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.utils.http import url_has_allowed_host_and_scheme
from django.utils.translation import gettext as _
from django.views.decorators.http import require_GET
from drf_spectacular.utils import extend_schema
from rest_framework import status
from rest_framework.exceptions import ValidationError
from rest_framework.parsers import FormParser, JSONParser
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.throttling import AnonRateThrottle, UserRateThrottle
from rest_framework.views import APIView
from rest_framework.views import exception_handler as drf_exception_handler

from whispers.constants import API_VERSION, EXPIRY_DELTAS, SUPPORTED_FORMAT_VERSIONS

from . import api_tokens, redis_store
from .deployment import _login_required_for, deployment_features
from .email import send_whisper_created_email, send_whisper_submitted_email
from .models import Whisper
from .serializers import (
    ApiInfoSerializer,
    CreateRequestResponseSerializer,
    CreateRequestSerializer,
    CreateWhisperResponseSerializer,
    CreateWhisperSerializer,
    ReceiveAccessSerializer,
    RevealWhisperResponseSerializer,
    RevealWhisperSerializer,
    SubmitRequestKeySerializer,
    SubmitWhisperResponseSerializer,
    SubmitWhisperSerializer,
    WhisperGoneSerializer,
    WhisperStatusSerializer,
)
from .stats import record_stats, stats_report

logger = logging.getLogger(__name__)


def _storage_unavailable(exc, whisper_id=None):
    """Log a Redis failure without whisper details and return a 503 response.

    When *whisper_id* is given, the Redis entry may have been written before the
    error surfaced, so it is removed on a best-effort basis.
    """
    logger.warning("Redis is unavailable: %s", type(exc).__name__)
    if whisper_id is not None:
        try:
            redis_store.delete_crypto(whisper_id)
        except redis.RedisError:
            pass
    return Response(
        {
            "error": _(
                "Whisper storage is temporarily unavailable. Please try again later."
            )
        },
        status=status.HTTP_503_SERVICE_UNAVAILABLE,
    )


def api_exception_handler(exc, context):
    """DRF exception handler that turns Redis failures into a 503.

    Throttling also uses Redis (via the cache), so this covers errors raised
    before a view method runs, not just storage writes.
    """
    if isinstance(exc, redis.RedisError):
        return _storage_unavailable(exc)
    return drf_exception_handler(exc, context)


class WhisperCreateThrottle(AnonRateThrottle):
    scope = "whisper_create"


class WhisperViewThrottle(AnonRateThrottle):
    scope = "whisper_view"


class WhisperStatusThrottle(AnonRateThrottle):
    """Per-IP limit for every caller; AnonRateThrottle alone skips signed-in users."""

    scope = "whisper_status"

    def get_cache_key(self, request, view):
        return self.cache_format % {
            "scope": self.scope,
            "ident": self.get_ident(request),
        }


class ReceiveAccessThrottle(UserRateThrottle):
    scope = "receive_access"

    def get_rate(self):
        return settings.REST_FRAMEWORK["DEFAULT_THROTTLE_RATES"][self.scope]

    def get_cache_key(self, request, view):
        if not request.user.is_authenticated:
            return None
        return super().get_cache_key(request, view)


def get_client_ip(request):
    """Return the real client IP, respecting NUM_PROXIES.

    NUM_PROXIES=0 (default): ignore X-Forwarded-For entirely, use REMOTE_ADDR.
    NUM_PROXIES=N: take the Nth-from-right entry in X-Forwarded-For,
    which is the value appended by the outermost trusted proxy.
    """
    num_proxies = getattr(settings, "NUM_PROXIES", 0)
    if num_proxies and request.META.get("HTTP_X_FORWARDED_FOR"):
        addrs = [a.strip() for a in request.META["HTTP_X_FORWARDED_FOR"].split(",")]
        # The trusted proxy at position N appended the real client IP
        # at index -(num_proxies) from the right.
        try:
            return addrs[-num_proxies]
        except IndexError:
            return addrs[0]
    return request.META.get("REMOTE_ADDR")


def check_ip_allowed(request, whisper):
    if not whisper.allowed_cidr:
        return True
    try:
        client_ip = ipaddress.ip_address(get_client_ip(request))
        network = ipaddress.ip_network(whisper.allowed_cidr, strict=False)
        return client_ip in network
    except ValueError:
        return False


def _requires_auth_view(whisper):
    """Check whether viewing this whisper requires authentication."""
    if whisper.mode == "receive" and whisper.creator_only:
        return True
    if getattr(settings, "PSST_FORCE_AUTH_VIEW", False):
        return True
    return whisper.require_auth_view


def _requires_auth_submit(whisper):
    """Check whether submitting to this whisper requires authentication."""
    if getattr(settings, "PSST_FORCE_AUTH_SUBMIT", False):
        return True
    return whisper.require_auth_submit


def _receive_access_enabled():
    return getattr(settings, "ENABLE_AUTH", False) and getattr(
        settings, "PSST_ENABLE_RECEIVE_ACCESS", False
    )


def _receive_reader_allowed(user, whisper):
    if whisper.mode != "receive" or not whisper.creator_only:
        return True
    if not user.is_authenticated or not user.is_active:
        return False
    return (
        whisper.creator_id == user.pk
        or whisper.allowed_readers.filter(pk=user.pk).exists()
    )


def _resolve_receive_readers(emails):
    from allauth.account.models import EmailAddress

    readers = set()
    for email in emails:
        accounts = list(
            EmailAddress.objects.filter(
                email__iexact=email,
                verified=True,
                primary=True,
                user__is_active=True,
                user__email__iexact=email,
            )
            .values_list("user_id", flat=True)
            .distinct()[:2]
        )
        if len(accounts) != 1:
            raise ValueError(
                _("Enter the verified primary email of each additional reader.")
            )
        readers.add(accounts[0])
    return readers


def _receive_access_data(whisper):
    return {
        "creator_only": whisper.creator_only,
        "allowed_reader_emails": list(
            whisper.allowed_readers.order_by("email").values_list("email", flat=True)
        ),
    }


def _receive_access_context(request, whisper):
    if (
        _receive_access_enabled()
        and request.user.is_authenticated
        and whisper.mode == "receive"
        and whisper.creator_id == request.user.pk
    ):
        return {
            "manage_receive_access": True,
            "force_receive_access": getattr(
                settings, "PSST_FORCE_RECEIVE_ACCESS", False
            ),
            "receive_access": _receive_access_data(whisper),
            "whisper": whisper,
        }
    return {}


def _redirect_to_login(request):
    """Redirect to the login page, preserving the current URL as next."""
    login_url = getattr(settings, "LOGIN_URL", "/accounts/login/")
    next_url = request.get_full_path()
    allowed_hosts = {request.get_host()}
    if url_has_allowed_host_and_scheme(next_url, allowed_hosts=allowed_hosts):
        return redirect(f"{login_url}?{urlencode({'next': next_url})}")
    return redirect(login_url)


def _first_error(errors):
    """Extract the first human-readable error string from DRF validation errors."""
    for field, msgs in errors.items():
        if isinstance(msgs, list) and msgs:
            return (
                f"{msgs[0]}" if field == "non_field_errors" else f"{field}: {msgs[0]}"
            )
        if isinstance(msgs, str):
            return msgs
    return "Validation error"


def _reveal_error_response(
    request,
    should_render,
    *,
    template,
    error,
    api_status,
    render_status,
    context=None,
):
    if should_render:
        return render(request, template, context, status=render_status)
    return Response({"error": error}, status=api_status)


def _reveal_auth_response(request, should_render):
    if should_render:
        return _redirect_to_login(request)
    return Response(
        {"error": "Authentication required"},
        status=status.HTTP_403_FORBIDDEN,
    )


def _receive_history_enabled():
    return getattr(settings, "PSST_ENABLE_RECEIVE_HISTORY", False)


@require_GET
def create(request):
    """Render the creation page."""
    return render(
        request,
        "whispers/create.html",
        {
            "enable_auth": getattr(settings, "ENABLE_AUTH", False),
            "enable_receive_history": _receive_history_enabled(),
            "force_auth_view": getattr(settings, "PSST_FORCE_AUTH_VIEW", False),
            "force_auth_submit": getattr(settings, "PSST_FORCE_AUTH_SUBMIT", False),
            "enable_email": getattr(settings, "PSST_ENABLE_EMAIL", False),
            "enable_receive_access": _receive_access_enabled()
            and request.user.is_authenticated,
            "default_receive_access": getattr(
                settings, "PSST_RECEIVE_ACCESS_DEFAULT", False
            )
            or getattr(settings, "PSST_FORCE_RECEIVE_ACCESS", False),
            "force_receive_access": getattr(
                settings, "PSST_FORCE_RECEIVE_ACCESS", False
            ),
        },
    )


@require_GET
def about(request):
    """Render the about page."""
    return render(
        request,
        "whispers/about.html",
        {
            "persistence_enabled": settings.ABOUT_PAGE_PERSISTENCE_ENABLED,
            "enable_receive_access": _receive_access_enabled(),
            "deployment_features": deployment_features(),
        },
    )


@require_GET
def stats(request):
    if not settings.PSST_ENABLE_STATS:
        raise Http404
    return render(
        request, "whispers/stats.html", stats_report(request.GET.get("range", "1w"))
    )


@require_GET
def receive_history(request):
    """Render the saved receive requests page; entries live only in the browser."""
    if not _receive_history_enabled():
        raise Http404
    return render(request, "whispers/receives.html")


class ApiInfoView(APIView):
    """Report the server version and the API and format versions it supports."""

    permission_classes = [AllowAny]

    @extend_schema(responses={200: ApiInfoSerializer})
    def get(self, request):
        return Response(
            {
                "server_version": settings.APP_VERSION,
                "api_version": API_VERSION,
                "format_versions": list(SUPPORTED_FORMAT_VERSIONS),
                "auth": {
                    "login_required": _login_required_for("api/v1/whisper"),
                    "loopback_pkce": api_tokens.api_tokens_enabled(),
                    "manual_code": api_tokens.manual_code_enabled(),
                    "scopes": (
                        list(api_tokens.SCOPES)
                        if api_tokens.api_tokens_enabled()
                        else []
                    ),
                },
            }
        )


class CreateWhisperView(APIView):
    """
    Create a new encrypted whisper.

    Accepts client-side encrypted data and stores it. The server never
    sees the plaintext or the encryption key.
    """

    permission_classes = [AllowAny, api_tokens.TokenScopePermission]
    required_scope = "whisper:create"
    throttle_classes = [WhisperCreateThrottle, api_tokens.ApiTokenUserThrottle]
    serializer_class = CreateWhisperSerializer

    @extend_schema(
        request=CreateWhisperSerializer,
        responses={200: CreateWhisperResponseSerializer},
    )
    def post(self, request):
        from .serializers import CreateWhisperSerializer

        serializer = CreateWhisperSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                {"error": _first_error(serializer.errors)},
                status=status.HTTP_400_BAD_REQUEST,
            )

        d = serializer.validated_data
        delta = EXPIRY_DELTAS[d["expiry"]]
        expires_at = timezone.now() + delta

        require_auth_view = (
            getattr(settings, "PSST_FORCE_AUTH_VIEW", False) or d["require_auth_view"]
        )

        whisper_id = uuid.uuid4()
        try:
            with transaction.atomic():
                whisper = Whisper.objects.create(
                    id=whisper_id,
                    max_views=d["max_views"],
                    allowed_cidr=d["allowed_cidr"],
                    require_auth_view=require_auth_view,
                    expiry_option=d["expiry"],
                    expires_at=expires_at,
                    notify_email=d["notify_email"],
                )
                redis_store.store_crypto(
                    whisper.id,
                    delta.total_seconds(),
                    ciphertext=d["ciphertext"],
                    iv=d["iv"],
                    salt=d["salt"],
                    reveal_token_hash=d["reveal_token_hash"],
                    v=d.get("v", 0),
                )
        except redis.RedisError as exc:
            return _storage_unavailable(exc, whisper_id)

        whisper_url = request.build_absolute_uri(f"/whisper/{whisper.id}")

        record_stats(
            "submission",
            mode="send",
            max_views=whisper.max_views,
            expiry=whisper.expiry_option,
        )

        if d["notify_email"]:
            send_whisper_created_email(d["notify_email"], whisper_url)

        return Response(
            {
                "id": str(whisper.id),
                "url": whisper_url,
            }
        )


class RevealWhisperView(APIView):
    """
    View and reveal a whisper.

    GET: Show a confirmation page.
    POST: Return the crypto payload as JSON. For burn-after-read whispers,
    the whisper is permanently deleted. Browser form posts with ?render=1
    render the payload directly without copying it through Web Storage.
    """

    permission_classes = [AllowAny, api_tokens.TokenScopePermission]
    required_scope = "whisper:read"
    parser_classes = [JSONParser, FormParser]
    throttle_classes = [WhisperViewThrottle, api_tokens.ApiTokenUserThrottle]
    allow_render = True

    @extend_schema(exclude=True)
    def get(self, request, whisper_id):
        whisper = Whisper.objects.filter(id=whisper_id).first()
        if whisper is None:
            return render(request, "whispers/burned.html", status=404)

        if not _receive_reader_allowed(request.user, whisper):
            if not request.user.is_authenticated:
                return _redirect_to_login(request)
            return render(
                request,
                "whispers/forbidden.html",
                {"reader_access_denied": True},
                status=403,
            )

        # Check expiry — delete from DB and Redis
        if whisper.is_expired:
            redis_store.delete_crypto(whisper_id)
            whisper.delete()
            return render(request, "whispers/expired.html", status=410)

        # Authentication check for viewing
        if _requires_auth_view(whisper) and not request.user.is_authenticated:
            return _redirect_to_login(request)

        # IP restriction: in send mode, restrict the viewer
        if whisper.mode == "send" and not check_ip_allowed(request, whisper):
            return render(request, "whispers/forbidden.html", status=403)

        crypto = redis_store.get_crypto(whisper_id)
        if crypto is None:
            whisper.delete()
            return render(request, "whispers/expired.html", status=410)

        # Receive mode: if no ciphertext yet, show pending page
        if whisper.mode == "receive" and not crypto.get("ciphertext"):
            return render(
                request,
                "whispers/pending.html",
                {"whisper": whisper, **_receive_access_context(request, whisper)},
            )

        return render(
            request,
            "whispers/confirm.html",
            {
                "whisper": whisper,
                "reveal_url": request.path,
                "password_protected": bool(crypto.get("salt")),
                "legacy_reveal": not crypto.get("reveal_token_hash"),
                **_receive_access_context(request, whisper),
            },
        )

    @extend_schema(
        request=RevealWhisperSerializer,
        responses={200: RevealWhisperResponseSerializer},
    )
    def post(self, request, whisper_id):
        whisper = get_object_or_404(Whisper, id=whisper_id)
        should_render = self.allow_render and bool(request.GET.get("render"))

        if not _receive_reader_allowed(request.user, whisper):
            if not request.user.is_authenticated:
                return _reveal_auth_response(request, should_render)
            return _reveal_error_response(
                request,
                should_render,
                template="whispers/forbidden.html",
                error=_("You do not have access to this whisper."),
                api_status=status.HTTP_403_FORBIDDEN,
                render_status=403,
                context={"reader_access_denied": True},
            )

        if whisper.is_expired:
            redis_store.delete_crypto(whisper_id)
            whisper.delete()
            return _reveal_error_response(
                request,
                should_render,
                template="whispers/expired.html",
                error="This whisper has expired",
                api_status=status.HTTP_410_GONE,
                render_status=410,
            )

        if _requires_auth_view(whisper) and not request.user.is_authenticated:
            return _reveal_auth_response(request, should_render)

        if whisper.mode == "send" and not check_ip_allowed(request, whisper):
            return _reveal_error_response(
                request,
                should_render,
                template="whispers/forbidden.html",
                error="Access denied from your IP address",
                api_status=status.HTTP_403_FORBIDDEN,
                render_status=403,
            )

        serializer = RevealWhisperSerializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
            crypto, count, exhausted = redis_store.increment_and_reveal(
                whisper_id, whisper.max_views, serializer.validated_data["reveal_token"]
            )
        except ValidationError, redis_store.RevealAuthorizationError:
            return _reveal_error_response(
                request,
                should_render,
                template="whispers/forbidden.html",
                error=_(
                    "The reveal authorization is missing or invalid. Use the complete view link."
                ),
                api_status=status.HTTP_403_FORBIDDEN,
                render_status=403,
                context={"reveal_authorization_denied": True},
            )
        except redis_store.RevealPendingError:
            return _reveal_error_response(
                request,
                should_render,
                template="whispers/pending.html",
                error="No content has been submitted yet",
                api_status=status.HTTP_404_NOT_FOUND,
                render_status=200,
                context={
                    "whisper": whisper,
                    **_receive_access_context(request, whisper),
                },
            )
        if crypto is None:
            whisper.delete()
            return _reveal_error_response(
                request,
                should_render,
                template="whispers/expired.html",
                error="This whisper has expired",
                api_status=status.HTTP_410_GONE,
                render_status=410,
            )

        record_stats("reveal")

        if exhausted:
            whisper.delete()

        remaining = max(whisper.max_views - count, 0) if whisper.max_views > 0 else 0

        paste_data = {
            "v": crypto.get("v", 0),
            "ciphertext": crypto["ciphertext"],
            "iv": crypto["iv"],
            "salt": crypto["salt"],
            "encapsulated_key": crypto.get("encapsulated_key", ""),
            "wrapped_key": crypto.get("wrapped_key", ""),
            "wrapped_key_iv": crypto.get("wrapped_key_iv", ""),
            "view_count": count,
            "max_views": whisper.max_views,
            "remaining_views": remaining,
        }

        if should_render:
            return render(
                request,
                "whispers/view.html",
                {
                    "burn_after_read": whisper.burn_after_read,
                    "paste_data": paste_data,
                    "legacy_reveal": not crypto.get("reveal_token_hash"),
                    **(
                        _receive_access_context(request, whisper)
                        if not exhausted
                        else {}
                    ),
                },
            )

        return Response(paste_data)


class RevealWhisperAPIView(RevealWhisperView):
    """JSON-only reveal endpoint of the versioned API."""

    http_method_names = ["post", "options"]
    allow_render = False


def _gone(api_status):
    return Response({"status": "gone"}, status=api_status)


class WhisperStatusView(APIView):
    """
    Report whether a receive request is still waiting or has been submitted.

    Never returns ciphertext and never counts as a view, so saved receive requests can
    be checked as often as the rate limit allows.
    """

    permission_classes = [AllowAny, api_tokens.TokenScopePermission]
    required_scope = "whisper:read"
    throttle_classes = [WhisperStatusThrottle, api_tokens.ApiTokenUserThrottle]

    @extend_schema(
        responses={
            200: WhisperStatusSerializer,
            404: WhisperGoneSerializer,
            410: WhisperGoneSerializer,
        },
    )
    def get(self, request, whisper_id):
        if not _receive_history_enabled():
            raise Http404
        whisper = Whisper.objects.filter(id=whisper_id, mode="receive").first()
        if whisper is None:
            return _gone(status.HTTP_404_NOT_FOUND)

        if not _receive_reader_allowed(request.user, whisper):
            if not request.user.is_authenticated:
                return _reveal_auth_response(request, False)
            return Response(
                {"error": _("You do not have access to this whisper.")},
                status=status.HTTP_403_FORBIDDEN,
            )

        if whisper.is_expired:
            redis_store.delete_crypto(whisper_id)
            whisper.delete()
            return _gone(status.HTTP_410_GONE)

        if _requires_auth_view(whisper) and not request.user.is_authenticated:
            return _reveal_auth_response(request, False)

        crypto_status = redis_store.get_submission_status(whisper_id)
        if crypto_status is None:
            whisper.delete()
            return _gone(status.HTTP_410_GONE)

        count = redis_store.get_view_count(whisper_id)
        remaining = max(whisper.max_views - count, 0) if whisper.max_views > 0 else 0
        return Response(
            {
                "status": crypto_status,
                "expires_at": whisper.expires_at,
                "view_count": count,
                "max_views": whisper.max_views,
                "remaining_views": remaining,
            }
        )


@require_GET
def submit_whisper(request, submit_token):
    """
    Render the submit page for a receive-mode request.
    A third party visits this to enter a whisper for the operator.
    """
    whisper = get_object_or_404(Whisper, submit_token=submit_token, mode="receive")

    if whisper.is_expired:
        redis_store.delete_crypto(whisper.id)
        whisper.delete()
        return render(request, "whispers/expired.html", status=410)

    # Authentication check for submitting
    if _requires_auth_submit(whisper) and not request.user.is_authenticated:
        return _redirect_to_login(request)

    # IP restriction: in receive mode, restrict the submitter
    if not check_ip_allowed(request, whisper):
        return render(request, "whispers/forbidden.html", status=403)

    crypto = redis_store.get_crypto(whisper.id)
    if crypto is None:
        whisper.delete()
        return render(request, "whispers/expired.html", status=410)

    if crypto.get("ciphertext"):
        return render(request, "whispers/submitted.html")

    return render(
        request,
        "whispers/submit.html",
        {
            "burn_after_read": whisper.burn_after_read,
            "request_data": {
                "submit_token": str(whisper.submit_token),
                "public_key": crypto.get("public_key", ""),
                "v": crypto.get("v", 0),
            },
        },
    )


class CreateRequestView(APIView):
    """
    Create a receive-mode request.

    The operator sets options (expiry, password, burn) and gets back
    a submit URL (to share) and a view URL (to check later).
    """

    permission_classes = [AllowAny, api_tokens.TokenScopePermission]
    required_scope = "request:manage"
    throttle_classes = [
        WhisperCreateThrottle,
        ReceiveAccessThrottle,
        api_tokens.ApiTokenUserThrottle,
    ]
    serializer_class = CreateRequestSerializer

    @extend_schema(
        request=CreateRequestSerializer,
        responses={200: CreateRequestResponseSerializer},
    )
    def post(self, request):
        from .serializers import CreateRequestSerializer

        serializer = CreateRequestSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                {"error": _first_error(serializer.errors)},
                status=status.HTTP_400_BAD_REQUEST,
            )

        d = serializer.validated_data
        delta = EXPIRY_DELTAS[d["expiry"]]
        expires_at = timezone.now() + delta

        require_auth_view = (
            getattr(settings, "PSST_FORCE_AUTH_VIEW", False) or d["require_auth_view"]
        )
        require_auth_submit = (
            getattr(settings, "PSST_FORCE_AUTH_SUBMIT", False)
            or d["require_auth_submit"]
        )

        access_enabled = _receive_access_enabled()
        creator_only = access_enabled and (
            getattr(settings, "PSST_FORCE_RECEIVE_ACCESS", False)
            or d.get(
                "creator_only", getattr(settings, "PSST_RECEIVE_ACCESS_DEFAULT", False)
            )
        )
        emails = d.get("allowed_reader_emails", [])
        if not access_enabled and (d.get("creator_only") or emails):
            return Response(
                {"error": _("Receive reader restrictions are not enabled.")}, status=400
            )
        if (creator_only or emails) and not request.user.is_authenticated:
            return Response(
                {"error": _("Sign in to manage reader access.")}, status=403
            )
        if emails and not creator_only:
            return Response(
                {"error": _("Enable restricted access before adding readers.")},
                status=400,
            )
        try:
            readers = _resolve_receive_readers(emails) if emails else set()
        except ValueError:
            return Response(
                {
                    "error": _(
                        "Enter the verified primary email of each additional reader."
                    )
                },
                status=400,
            )

        whisper_id = uuid.uuid4()
        try:
            with transaction.atomic():
                whisper = Whisper.objects.create(
                    id=whisper_id,
                    mode="receive",
                    submit_token=uuid.uuid4(),
                    max_views=d["max_views"],
                    allowed_cidr=d["allowed_cidr"],
                    require_auth_view=require_auth_view,
                    require_auth_submit=require_auth_submit,
                    expiry_option=d["expiry"],
                    expires_at=expires_at,
                    notify_email=d["notify_email"],
                    creator=(
                        request.user
                        if access_enabled and request.user.is_authenticated
                        else None
                    ),
                    creator_only=creator_only,
                )
                whisper.allowed_readers.set(readers)
                redis_store.store_crypto(
                    whisper.id,
                    delta.total_seconds(),
                    salt=d["salt"],
                    public_key=d["public_key"],
                    wrapped_key=d["wrapped_key"],
                    wrapped_key_iv=d["wrapped_key_iv"],
                    reveal_token_hash=d["reveal_token_hash"],
                    v=d.get("v", 0),
                )
        except redis.RedisError as exc:
            return _storage_unavailable(exc, whisper_id)

        return Response(
            {
                "id": str(whisper.id),
                "submit_url": request.build_absolute_uri(
                    f"/submit/{whisper.submit_token}"
                ),
                "view_url": request.build_absolute_uri(f"/whisper/{whisper.id}"),
                "expires_at": whisper.expires_at,
            }
        )


class ReceiveAccessView(APIView):
    permission_classes = [AllowAny, api_tokens.TokenScopePermission]
    required_scope = "request:manage"
    parser_classes = [JSONParser]
    throttle_classes = [
        WhisperViewThrottle,
        ReceiveAccessThrottle,
        api_tokens.ApiTokenUserThrottle,
    ]

    def _get_whisper(self, request, whisper_id):
        if not _receive_access_enabled() or not request.user.is_authenticated:
            raise Http404
        whisper = get_object_or_404(
            Whisper, id=whisper_id, mode="receive", creator_id=request.user.pk
        )
        if whisper.is_expired or redis_store.get_crypto(whisper.id) is None:
            raise Http404
        return whisper

    @extend_schema(responses={200: ReceiveAccessSerializer})
    def get(self, request, whisper_id):
        whisper = self._get_whisper(request, whisper_id)
        return Response(_receive_access_data(whisper))

    @extend_schema(
        request=ReceiveAccessSerializer, responses={200: ReceiveAccessSerializer}
    )
    def patch(self, request, whisper_id):
        whisper = self._get_whisper(request, whisper_id)
        serializer = ReceiveAccessSerializer(data=request.data)
        if not serializer.is_valid():
            return Response({"error": _first_error(serializer.errors)}, status=400)
        data = serializer.validated_data
        forced = getattr(settings, "PSST_FORCE_RECEIVE_ACCESS", False)
        if forced and data.get("creator_only") is False:
            return Response(
                {"error": _("Restricted receive access is required.")}, status=400
            )
        creator_only = forced or data.get("creator_only", whisper.creator_only)
        emails = data.get("allowed_reader_emails")
        if emails and not creator_only:
            return Response(
                {"error": _("Enable restricted access before adding readers.")},
                status=400,
            )
        try:
            readers = _resolve_receive_readers(emails) if emails is not None else None
        except ValueError:
            return Response(
                {
                    "error": _(
                        "Enter the verified primary email of each additional reader."
                    )
                },
                status=400,
            )
        with transaction.atomic():
            if not creator_only:
                whisper.allowed_readers.clear()
            elif readers is not None:
                whisper.allowed_readers.set(readers)
            whisper.creator_only = creator_only
            whisper.save(update_fields=["creator_only"])
        return Response(_receive_access_data(whisper))


class SubmitWhisperView(APIView):
    """
    Submit encrypted data for a receive-mode request.

    Called by the third party who fills in the whisper.
    """

    permission_classes = [AllowAny, api_tokens.TokenScopePermission]
    required_scope = "whisper:create"
    throttle_classes = [WhisperCreateThrottle, api_tokens.ApiTokenUserThrottle]
    serializer_class = SubmitWhisperSerializer

    def _open_request(self, request, submit_token):
        """Return ``(whisper, crypto, error_response)`` for a receive request."""
        whisper = get_object_or_404(Whisper, submit_token=submit_token, mode="receive")

        if whisper.is_expired:
            redis_store.delete_crypto(whisper.id)
            whisper.delete()
            return (
                None,
                None,
                Response(
                    {"error": "This request has expired"}, status=status.HTTP_410_GONE
                ),
            )

        # Authentication check for submitting
        if _requires_auth_submit(whisper) and not request.user.is_authenticated:
            return (
                None,
                None,
                Response(
                    {"error": "Authentication required"},
                    status=status.HTTP_403_FORBIDDEN,
                ),
            )

        if not check_ip_allowed(request, whisper):
            return (
                None,
                None,
                Response(
                    {"error": "Access denied from your IP address"},
                    status=status.HTTP_403_FORBIDDEN,
                ),
            )

        crypto = redis_store.get_crypto(whisper.id)
        if crypto is None:
            whisper.delete()
            return (
                None,
                None,
                Response(
                    {"error": "This request has expired"}, status=status.HTTP_410_GONE
                ),
            )

        if crypto.get("ciphertext"):
            return (
                None,
                None,
                Response(
                    {"error": "Already submitted"}, status=status.HTTP_409_CONFLICT
                ),
            )
        return whisper, crypto, None

    @extend_schema(
        description="Return the request's public key for a sender to encrypt to.",
        responses={200: SubmitRequestKeySerializer},
    )
    def get(self, request, submit_token):
        _whisper, crypto, error = self._open_request(request, submit_token)
        if error:
            return error
        return Response(
            {"public_key": crypto.get("public_key", ""), "v": crypto.get("v", 0)}
        )

    @extend_schema(
        request=SubmitWhisperSerializer,
        responses={200: SubmitWhisperResponseSerializer},
    )
    def post(self, request, submit_token):
        whisper, _crypto, error = self._open_request(request, submit_token)
        if error:
            return error

        from .serializers import SubmitWhisperSerializer

        serializer = SubmitWhisperSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                {"error": _first_error(serializer.errors)},
                status=status.HTTP_400_BAD_REQUEST,
            )

        d = serializer.validated_data
        result = redis_store.submit_crypto_once(
            whisper.id,
            ciphertext=d["ciphertext"],
            iv=d["iv"],
            encapsulated_key=d["encapsulated_key"],
            v=d.get("v", 0),
        )

        if result == "submitted":
            return Response(
                {"error": "Already submitted"}, status=status.HTTP_409_CONFLICT
            )
        if result == "missing":
            whisper.delete()
            return Response(
                {"error": "This request has expired"}, status=status.HTTP_410_GONE
            )

        record_stats(
            "submission",
            mode="receive",
            max_views=whisper.max_views,
            expiry=whisper.expiry_option,
        )

        if whisper.notify_email:
            view_url = request.build_absolute_uri(f"/whisper/{whisper.id}")
            send_whisper_submitted_email(whisper.notify_email, view_url)

        return Response({"success": True})
