import ipaddress
import logging

from django.conf import settings
from django.core.cache import cache
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import require_GET
from drf_spectacular.utils import extend_schema
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.throttling import AnonRateThrottle
from rest_framework.views import APIView

from whispers.constants import EXPIRY_DELTAS

from . import redis_store
from .models import Whisper
from .serializers import (
    CreateRequestResponseSerializer,
    CreateRequestSerializer,
    CreateWhisperResponseSerializer,
    CreateWhisperSerializer,
    RevealWhisperResponseSerializer,
    SubmitWhisperResponseSerializer,
    SubmitWhisperSerializer,
)

logger = logging.getLogger(__name__)


class WhisperCreateThrottle(AnonRateThrottle):
    scope = "whisper_create"


class WhisperViewThrottle(AnonRateThrottle):
    scope = "whisper_view"


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
    if getattr(settings, "PSST_FORCE_AUTH_VIEW", False):
        return True
    return whisper.require_auth_view


def _requires_auth_submit(whisper):
    """Check whether submitting to this whisper requires authentication."""
    if getattr(settings, "PSST_FORCE_AUTH_SUBMIT", False):
        return True
    return whisper.require_auth_submit


def _redirect_to_login(request):
    """Redirect to the login page, preserving the current URL as next."""
    login_url = getattr(settings, "LOGIN_URL", "/accounts/login/")
    return redirect(f"{login_url}?next={request.get_full_path()}")


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


@require_GET
def create(request):
    """Render the creation page."""
    return render(
        request,
        "whispers/create.html",
        {
            "enable_auth": getattr(settings, "ENABLE_AUTH", False),
            "force_auth_view": getattr(settings, "PSST_FORCE_AUTH_VIEW", False),
            "force_auth_submit": getattr(settings, "PSST_FORCE_AUTH_SUBMIT", False),
        },
    )


@require_GET
def about(request):
    """Render the about page."""
    return render(request, "whispers/about.html")


class CreateWhisperView(APIView):
    """
    Create a new encrypted whisper.

    Accepts client-side encrypted data and stores it. The server never
    sees the plaintext or the encryption key.
    """

    permission_classes = [AllowAny]
    throttle_classes = [WhisperCreateThrottle]
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

        whisper = Whisper.objects.create(
            burn_after_read=d["burn_after_read"],
            allowed_cidr=d["allowed_cidr"],
            require_auth_view=require_auth_view,
            expiry_option=d["expiry"],
            expires_at=expires_at,
        )

        redis_store.store_crypto(
            whisper.id,
            delta.total_seconds(),
            ciphertext=d["ciphertext"],
            iv=d["iv"],
            salt=d["salt"],
        )

        return Response(
            {
                "id": str(whisper.id),
                "url": request.build_absolute_uri(f"/whisper/{whisper.id}"),
            }
        )


@require_GET
def view_whisper(request, whisper_id):
    """
    Serve the whisper viewing page with ciphertext.
    If burn_after_read, mark as burned after first retrieval.
    For receive-mode whispers that haven't been submitted yet, show pending page.
    """
    # Rate-limit whisper views per IP to mitigate brute-force enumeration
    view_rate_str = settings.REST_FRAMEWORK.get("DEFAULT_THROTTLE_RATES", {}).get(
        "whisper_view", ""
    )
    if view_rate_str:
        client_ip = get_client_ip(request)
        cache_key = f"view_rate:{client_ip}"
        rate_limit = int(view_rate_str.split("/")[0])
        hits = cache.get(cache_key, 0)
        if hits >= rate_limit:
            return HttpResponse("Rate limit exceeded. Try again later.", status=429)
        cache.set(cache_key, hits + 1, 60)

    # Burn-after-read reveal redirect: the confirm page POSTed to the
    # reveal endpoint (which already deleted the DB row and Redis data)
    # then stored the crypto payload in sessionStorage and redirected here
    # with ?revealed=1.  The whisper no longer exists in the DB, so we
    # must handle this before the DB lookup.
    if request.GET.get("revealed"):
        return render(
            request,
            "whispers/view.html",
            {"burn_after_read": True, "paste_data": None},
        )

    whisper = get_object_or_404(Whisper, id=whisper_id)

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

    # Burn-after-read: show a confirmation page on first GET so that
    # link-preview bots (Teams, Slack, Outlook…) don't burn the content.
    # The actual reveal happens via a POST to the reveal endpoint, and the
    # user is then redirected back here with ?revealed=1 to decrypt from
    # sessionStorage.
    if whisper.burn_after_read:
        # First visit: just check the crypto still exists, don't consume it.
        crypto = redis_store.get_crypto(whisper_id)
        if crypto is None:
            whisper.delete()
            return render(request, "whispers/expired.html", status=410)
        # Receive mode: if no ciphertext yet, show pending page
        if whisper.mode == "receive" and not crypto.get("ciphertext"):
            return render(request, "whispers/pending.html", {"whisper": whisper})
        return render(
            request,
            "whispers/confirm_burn.html",
            {
                "whisper": whisper,
                "reveal_url": f"/api/whisper/{whisper_id}/reveal",
            },
        )

    # Non-burn path: return crypto data directly
    crypto = redis_store.get_crypto(whisper_id)
    if crypto is None:
        whisper.delete()
        return render(request, "whispers/expired.html", status=410)

    # Receive mode: if no ciphertext yet, show pending page
    if whisper.mode == "receive" and not crypto.get("ciphertext"):
        return render(
            request,
            "whispers/pending.html",
            {
                "whisper": whisper,
            },
        )

    context = {
        "whisper": whisper,
        "burn_after_read": False,
        "paste_data": {
            "ciphertext": crypto["ciphertext"],
            "iv": crypto["iv"],
            "salt": crypto["salt"],
        },
    }

    return render(request, "whispers/view.html", context)


class RevealWhisperView(APIView):
    """
    Atomically reveal a burn-after-read whisper.

    Called via JS from the confirmation page. Returns the crypto data
    as JSON and deletes the whisper so it can never be read again.
    Bots never POST, so this prevents link-preview services from
    burning the content.
    """

    permission_classes = [AllowAny]
    throttle_classes = [WhisperCreateThrottle]

    @extend_schema(
        request=None,
        responses={200: RevealWhisperResponseSerializer},
    )
    def post(self, request, whisper_id):
        whisper = get_object_or_404(Whisper, id=whisper_id)

        if whisper.is_expired:
            redis_store.delete_crypto(whisper_id)
            whisper.delete()
            return Response(
                {"error": "This psst has expired"}, status=status.HTTP_410_GONE
            )

        if not whisper.burn_after_read:
            return Response(
                {"error": "Not a burn-after-read psst"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if _requires_auth_view(whisper) and not request.user.is_authenticated:
            return Response(
                {"error": "Authentication required"},
                status=status.HTTP_403_FORBIDDEN,
            )

        if whisper.mode == "send" and not check_ip_allowed(request, whisper):
            return Response(
                {"error": "Access denied from your IP address"},
                status=status.HTTP_403_FORBIDDEN,
            )

        crypto = redis_store.get_and_delete_crypto(whisper_id)
        if crypto is None:
            whisper.delete()
            return Response(
                {"error": "This psst has expired"}, status=status.HTTP_410_GONE
            )

        whisper.delete()

        return Response(
            {
                "ciphertext": crypto["ciphertext"],
                "iv": crypto["iv"],
                "salt": crypto["salt"],
            }
        )


@require_GET
def submit_whisper(request, request_id):
    """
    Render the submit page for a receive-mode request.
    A third party visits this to enter a whisper for the operator.
    """
    whisper = get_object_or_404(Whisper, id=request_id, mode="receive")

    if whisper.is_expired:
        redis_store.delete_crypto(request_id)
        whisper.delete()
        return render(request, "whispers/expired.html", status=410)

    # Authentication check for submitting
    if _requires_auth_submit(whisper) and not request.user.is_authenticated:
        return _redirect_to_login(request)

    # IP restriction: in receive mode, restrict the submitter
    if not check_ip_allowed(request, whisper):
        return render(request, "whispers/forbidden.html", status=403)

    crypto = redis_store.get_crypto(request_id)
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
            "salt": crypto.get("salt", ""),
            "request_data": {
                "request_id": str(whisper.id),
                "salt": crypto.get("salt", ""),
                "password_verify_token": crypto.get("password_verify_token", ""),
                "password_verify_iv": crypto.get("password_verify_iv", ""),
            },
        },
    )


class CreateRequestView(APIView):
    """
    Create a receive-mode request.

    The operator sets options (expiry, password, burn) and gets back
    a submit URL (to share) and a view URL (to check later).
    """

    permission_classes = [AllowAny]
    throttle_classes = [WhisperCreateThrottle]
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

        whisper = Whisper.objects.create(
            mode="receive",
            burn_after_read=d["burn_after_read"],
            allowed_cidr=d["allowed_cidr"],
            require_auth_view=require_auth_view,
            require_auth_submit=require_auth_submit,
            expiry_option=d["expiry"],
            expires_at=expires_at,
        )

        redis_store.store_crypto(
            whisper.id,
            delta.total_seconds(),
            salt=d["salt"],
            password_verify_token=d["password_verify_token"],
            password_verify_iv=d["password_verify_iv"],
        )

        return Response(
            {
                "id": str(whisper.id),
                "submit_url": request.build_absolute_uri(f"/submit/{whisper.id}"),
                "view_url": request.build_absolute_uri(f"/whisper/{whisper.id}"),
            }
        )


class SubmitWhisperView(APIView):
    """
    Submit encrypted data for a receive-mode request.

    Called by the third party who fills in the whisper.
    """

    permission_classes = [AllowAny]
    throttle_classes = [WhisperCreateThrottle]
    serializer_class = SubmitWhisperSerializer

    @extend_schema(
        request=SubmitWhisperSerializer,
        responses={200: SubmitWhisperResponseSerializer},
    )
    def post(self, request, request_id):
        whisper = get_object_or_404(Whisper, id=request_id, mode="receive")

        if whisper.is_expired:
            redis_store.delete_crypto(request_id)
            whisper.delete()
            return Response(
                {"error": "This request has expired"}, status=status.HTTP_410_GONE
            )

        # Authentication check for submitting
        if _requires_auth_submit(whisper) and not request.user.is_authenticated:
            return Response(
                {"error": "Authentication required"},
                status=status.HTTP_403_FORBIDDEN,
            )

        if not check_ip_allowed(request, whisper):
            return Response(
                {"error": "Access denied from your IP address"},
                status=status.HTTP_403_FORBIDDEN,
            )

        crypto = redis_store.get_crypto(request_id)
        if crypto is None:
            whisper.delete()
            return Response(
                {"error": "This request has expired"}, status=status.HTTP_410_GONE
            )

        if crypto.get("ciphertext"):
            return Response(
                {"error": "Already submitted"}, status=status.HTTP_409_CONFLICT
            )

        from .serializers import SubmitWhisperSerializer

        serializer = SubmitWhisperSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                {"error": _first_error(serializer.errors)},
                status=status.HTTP_400_BAD_REQUEST,
            )

        d = serializer.validated_data
        redis_store.update_crypto(request_id, ciphertext=d["ciphertext"], iv=d["iv"])

        return Response({"success": True})
