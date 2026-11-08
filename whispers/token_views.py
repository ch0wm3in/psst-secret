"""Sign-in for the CLI and browser extension: loopback redirect + PKCE (RFC 8252, RFC 7636).

See docs/api.md#api-tokens.
"""

from urllib.parse import urlencode

from django.conf import settings
from django.http import Http404, HttpResponseRedirect
from django.shortcuts import redirect, render
from django.urls import reverse
from django.utils import timezone
from django.utils.translation import gettext as _
from django.views.decorators.http import require_GET, require_http_methods, require_POST
from drf_spectacular.utils import extend_schema
from rest_framework import status
from rest_framework.parsers import FormParser, JSONParser
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from .api_tokens import (
    SCOPES,
    ApiTokenUserThrottle,
    AuthorizationRequestError,
    TokenExchangeError,
    TokenExchangeThrottle,
    api_tokens_enabled,
    create_authorization_code,
    exchange_code,
    validate_authorization_request,
)
from .models import ApiToken
from .serializers import TokenExchangeSerializer, TokenResponseSerializer
from .views import _first_error, _redirect_to_login

_AUTHORIZE_FIELDS = (
    "response_type",
    "redirect_uri",
    "code_challenge",
    "code_challenge_method",
    "state",
    "client_name",
    "scope",
)


def _no_referrer(response):
    # Keep authorization codes and state out of Referer headers. The approval form
    # itself is not sent with this policy: browsers would send "Origin: null" on its
    # POST, which fails Django's CSRF origin check.
    response["Referrer-Policy"] = "no-referrer"
    response["Cache-Control"] = "no-store"
    return response


def _require_enabled():
    if not api_tokens_enabled():
        raise Http404


def _login_redirect(data):
    params = {
        field: data[field]
        for field in (
            "redirect_uri",
            "code_challenge",
            "code_challenge_method",
            "state",
        )
    }
    params["scope"] = data["scope"]
    if data["client_name"]:
        params["client_name"] = data["client_name"]
    next_url = f"{reverse('whispers:cli_authorize')}?{urlencode(params)}"
    login_url = getattr(settings, "LOGIN_URL", "/accounts/login/")
    return _no_referrer(redirect(f"{login_url}?{urlencode({'next': next_url})}"))


def _error_page(request, message, status_code=400):
    return _no_referrer(
        render(
            request, "whispers/cli_error.html", {"error": message}, status=status_code
        )
    )


@require_http_methods(["GET", "POST"])
def cli_authorize(request):
    """Ask the signed-in user to approve or deny an API client.

    Invalid requests get an error page and never a redirect, so the endpoint cannot be
    used as an open redirector.
    """
    _require_enabled()
    params = request.POST if request.method == "POST" else request.GET
    try:
        data = validate_authorization_request(
            {
                field: params.get(field, "")
                for field in _AUTHORIZE_FIELDS
                if field in params
            }
        )
    except AuthorizationRequestError as exc:
        return _error_page(request, str(exc))

    if not request.user.is_authenticated:
        return _login_redirect(data)

    if request.method == "GET":
        response = render(
            request,
            "whispers/cli_authorize.html",
            {
                "request_data": data,
                "client_name": data["client_name"],
                "scopes": [(scope, SCOPES[scope]) for scope in data["scopes"]],
                "redirect_host": (
                    None if data["manual"] else data["redirect_uri"].split("/")[2]
                ),
                "redirect_extension": data["redirect_uri"].startswith("https://"),
            },
        )
        response["Cache-Control"] = "no-store"
        return response

    approved = request.POST.get("action") == "approve"
    if data["manual"]:
        if not approved:
            return _error_page(request, _("You denied access."), status_code=200)
        code = create_authorization_code(request.user, data)
        return _no_referrer(
            render(
                request,
                "whispers/cli_code.html",
                {"code": code, "state": data["state"]},
            )
        )
    if approved:
        query = {"code": create_authorization_code(request.user, data)}
    else:
        query = {"error": "access_denied"}
    query["state"] = data["state"]
    return _no_referrer(
        HttpResponseRedirect(f"{data['redirect_uri']}?{urlencode(query)}")
    )


@require_GET
def api_token_list(request):
    """List the signed-in user's API tokens."""
    _require_enabled()
    if not request.user.is_authenticated:
        return _redirect_to_login(request)
    tokens = ApiToken.objects.filter(user=request.user, expires_at__gt=timezone.now())
    return render(
        request,
        "whispers/api_tokens.html",
        {
            "tokens": [
                {"token": token, "scopes": token.scope_list} for token in tokens
            ],
        },
    )


@require_POST
def api_token_revoke(request, token_id):
    _require_enabled()
    if not request.user.is_authenticated:
        return _redirect_to_login(request)
    ApiToken.objects.filter(user=request.user, pk=token_id).delete()
    return redirect("whispers:api_tokens")


class TokenExchangeView(APIView):
    """Exchange a single-use authorization code and its PKCE verifier for an API token."""

    # The code verifier is the credential; session cookies play no part.
    authentication_classes = []
    permission_classes = [AllowAny]
    parser_classes = [JSONParser, FormParser]
    throttle_classes = [TokenExchangeThrottle]

    @extend_schema(
        request=TokenExchangeSerializer, responses={200: TokenResponseSerializer}
    )
    def post(self, request):
        _require_enabled()
        serializer = TokenExchangeSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                {"error": _first_error(serializer.errors)},
                status=status.HTTP_400_BAD_REQUEST,
            )
        d = serializer.validated_data
        try:
            token, raw_token = exchange_code(
                d["code"], d["code_verifier"], d["redirect_uri"]
            )
        except TokenExchangeError as exc:
            return Response({"error": exc.message}, status=status.HTTP_400_BAD_REQUEST)
        return Response(
            {
                "access_token": raw_token,
                "token_type": "Bearer",
                "expires_in": int((token.expires_at - timezone.now()).total_seconds()),
                "expires_at": token.expires_at,
                "scope": token.scopes,
            }
        )


class RevokeTokenView(APIView):
    """Revoke the API token that authenticates this request (``psst logout``)."""

    permission_classes = [AllowAny]
    throttle_classes = [ApiTokenUserThrottle]

    @extend_schema(request=None, responses={204: None})
    def post(self, request):
        _require_enabled()
        if not isinstance(request.auth, ApiToken):
            return Response(
                {
                    "error": _(
                        "Send the API token to revoke in the Authorization header."
                    )
                },
                status=status.HTTP_401_UNAUTHORIZED,
            )
        request.auth.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
