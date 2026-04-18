from django.conf import settings
from django.contrib.auth import authenticate, login
from django.shortcuts import redirect, render
from django.utils.http import url_has_allowed_host_and_scheme

# Human-friendly display names for common social providers.
PROVIDER_DISPLAY = {
    "apple": "Apple",
    "azure": "Microsoft Azure",
    "github": "GitHub",
    "gitlab": "GitLab",
    "google": "Google",
    "microsoft": "Microsoft",
    "okta": "Okta",
    "openid_connect": "OpenID Connect",
    "saml": "SAML",
}


def _build_providers():
    providers = []
    for provider_id in getattr(settings, "SOCIAL_AUTH_PROVIDERS", []):
        providers.append(
            {
                "id": provider_id,
                "name": PROVIDER_DISPLAY.get(
                    provider_id, provider_id.replace("_", " ").title()
                ),
            }
        )
    return providers


def login_view(request):
    """Custom login page that renders social-provider buttons and an
    optional local username/password form."""
    next_url = request.GET.get("next", request.POST.get("next", "/"))
    if not url_has_allowed_host_and_scheme(
        next_url,
        allowed_hosts={request.get_host()},
        require_https=request.is_secure(),
    ):
        next_url = "/"
    enable_local_login = getattr(settings, "ENABLE_LOCAL_LOGIN", False)
    error = ""

    if request.method == "POST" and enable_local_login:
        username = request.POST.get("username", "").strip()
        password = request.POST.get("password", "")
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect(next_url)
        error = "Invalid username or password."

    return render(
        request,
        "whispers/login.html",
        {
            "providers": _build_providers(),
            "next": next_url,
            "enable_local_login": enable_local_login,
            "error": error,
        },
    )
