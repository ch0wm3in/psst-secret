from django.urls import path

from . import views

app_name = "whispers"

urlpatterns = [
    path("", views.create, name="create"),
    path("about", views.about, name="about"),
    path(
        "whisper/<uuid:whisper_id>",
        views.RevealWhisperView.as_view(),
        name="view",
    ),
    path("submit/<uuid:request_id>", views.submit_whisper, name="submit"),
    path("api/whisper", views.CreateWhisperView.as_view(), name="api_create"),
    path(
        "api/whisper/request",
        views.CreateRequestView.as_view(),
        name="api_create_request",
    ),
    path(
        "api/whisper/submit/<uuid:request_id>",
        views.SubmitWhisperView.as_view(),
        name="api_submit",
    ),
]
