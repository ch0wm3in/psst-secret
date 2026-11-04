from django.urls import path

from . import token_views, views

app_name = "whispers"

urlpatterns = [
    path("", views.create, name="create"),
    path("about", views.about, name="about"),
    path("stats", views.stats, name="stats"),
    path(
        "whisper/<uuid:whisper_id>",
        views.RevealWhisperView.as_view(),
        name="view",
    ),
    path("submit/<uuid:submit_token>", views.submit_whisper, name="submit"),
    path("cli/authorize", token_views.cli_authorize, name="cli_authorize"),
    path("cli/tokens", token_views.api_token_list, name="api_tokens"),
    path(
        "cli/tokens/<int:token_id>/revoke",
        token_views.api_token_revoke,
        name="api_token_revoke",
    ),
    path("api/v1/info", views.ApiInfoView.as_view(), name="api_v1_info"),
    path(
        "api/v1/cli/token",
        token_views.TokenExchangeView.as_view(),
        name="api_v1_cli_token",
    ),
    path(
        "api/v1/cli/revoke",
        token_views.RevokeTokenView.as_view(),
        name="api_v1_cli_revoke",
    ),
    path("api/v1/whisper", views.CreateWhisperView.as_view(), name="api_v1_create"),
    path(
        "api/v1/whisper/request",
        views.CreateRequestView.as_view(),
        name="api_v1_create_request",
    ),
    path(
        "api/v1/whisper/<uuid:whisper_id>/reveal",
        views.RevealWhisperAPIView.as_view(),
        name="api_v1_reveal",
    ),
    path(
        "api/v1/whisper/<uuid:whisper_id>/access",
        views.ReceiveAccessView.as_view(),
        name="api_v1_receive_access",
    ),
    path(
        "api/v1/whisper/submit/<uuid:submit_token>",
        views.SubmitWhisperView.as_view(),
        name="api_v1_submit",
    ),
    # Deprecated unversioned aliases of the v1 endpoints; see docs/api.md.
    path("api/whisper", views.CreateWhisperView.as_view(), name="api_create"),
    path(
        "api/whisper/request",
        views.CreateRequestView.as_view(),
        name="api_create_request",
    ),
    path(
        "api/whisper/<uuid:whisper_id>/access",
        views.ReceiveAccessView.as_view(),
        name="api_receive_access",
    ),
    path(
        "api/whisper/submit/<uuid:submit_token>",
        views.SubmitWhisperView.as_view(),
        name="api_submit",
    ),
]
