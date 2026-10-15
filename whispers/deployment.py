"""Plain-language summary of deployment settings shown on the About page.

Only behavior that affects users is described. Secrets, hostnames, rate limits
and infrastructure details are never exposed.
"""

import re
import uuid

from django.conf import settings
from django.utils.translation import gettext as _

from whispers.auth_views import _build_providers
from whispers.templatetags.whispers_extras import filesizeformat

_LOGIN_MIDDLEWARE = "whispers.middleware.LoginRequiredMiddleware"
_SAMPLE_ID = str(uuid.UUID(int=0))


def _login_required_for(path):
    """Mirror LoginRequiredMiddleware for an anonymous request to ``path``."""
    if not getattr(settings, "ENABLE_AUTH", False):
        return False
    if _LOGIN_MIDDLEWARE not in settings.MIDDLEWARE:
        return False
    patterns = getattr(settings, "LOGIN_REQUIRED_EXEMPT_URLS", [])
    return not any(re.match(pattern, path) for pattern in patterns)


def _feature(key, icon, title, status, state, description, detail=""):
    return {
        "key": key,
        "icon": icon,
        "title": title,
        "status": status,
        "state": state,
        "description": description,
        "detail": detail,
    }


def _sign_in_methods():
    methods = [provider["name"] for provider in _build_providers()]
    if getattr(settings, "ENABLE_LOCAL_LOGIN", False):
        methods.append(_("username and password"))
    if not methods:
        return ""
    return _("Sign-in options: %(methods)s") % {"methods": ", ".join(methods)}


def _auth_features():
    if not getattr(settings, "ENABLE_AUTH", False):
        return [
            _feature(
                "sign_in",
                "🔐",
                _("Sign-in"),
                _("Not used"),
                "off",
                _(
                    "Anyone who can reach this site can create whispers. Viewing a "
                    "whisper or submitting to a request only needs the link."
                ),
            )
        ]

    if _login_required_for(""):
        sign_in = _feature(
            "sign_in",
            "🔐",
            _("Sign-in"),
            _("Required"),
            "on",
            _("You must sign in to create whispers and requests."),
            _sign_in_methods(),
        )
    else:
        sign_in = _feature(
            "sign_in",
            "🔐",
            _("Sign-in"),
            _("Optional"),
            "neutral",
            _("You can create whispers without signing in."),
            _sign_in_methods(),
        )

    if getattr(settings, "PSST_FORCE_AUTH_VIEW", False) or _login_required_for(
        f"whisper/{_SAMPLE_ID}"
    ):
        view = _feature(
            "view_auth",
            "👁️",
            _("Viewing whispers"),
            _("Sign-in required"),
            "on",
            _("You must sign in to view any whisper, in addition to having its link."),
        )
    else:
        view = _feature(
            "view_auth",
            "👁️",
            _("Viewing whispers"),
            _("Link only"),
            "off",
            _(
                "Anyone with the full link can view a whisper without signing in, "
                "unless its creator requires sign-in for that whisper."
            ),
        )

    if getattr(settings, "PSST_FORCE_AUTH_SUBMIT", False) or _login_required_for(
        f"submit/{_SAMPLE_ID}"
    ):
        submit = _feature(
            "submit_auth",
            "📨",
            _("Submitting to requests"),
            _("Sign-in required"),
            "on",
            _("You must sign in to submit a whisper to a receive request."),
        )
    else:
        submit = _feature(
            "submit_auth",
            "📨",
            _("Submitting to requests"),
            _("Link only"),
            "off",
            _(
                "Anyone with a submit link can submit a whisper without signing in, "
                "unless the request's creator requires sign-in."
            ),
        )

    title = _("Restricted receive access")
    if not getattr(settings, "PSST_ENABLE_RECEIVE_ACCESS", False):
        access = _feature(
            "receive_access",
            "👥",
            title,
            _("Off"),
            "off",
            _("Receive requests cannot be limited to specific accounts."),
        )
    elif getattr(settings, "PSST_FORCE_RECEIVE_ACCESS", False):
        access = _feature(
            "receive_access",
            "👥",
            title,
            _("Always on"),
            "on",
            _(
                "Receive requests can only be read by their creator and the "
                "accounts they approve."
            ),
        )
    elif getattr(settings, "PSST_RECEIVE_ACCESS_DEFAULT", False):
        access = _feature(
            "receive_access",
            "👥",
            title,
            _("On by default"),
            "on",
            _(
                "New receive requests are limited to their creator and approved "
                "accounts unless the creator turns this off."
            ),
        )
    else:
        access = _feature(
            "receive_access",
            "👥",
            title,
            _("Optional"),
            "neutral",
            _(
                "Creators can limit receive requests to themselves and the accounts "
                "they approve."
            ),
        )

    return [sign_in, view, submit, access]


def deployment_features():
    features = _auth_features()

    if getattr(settings, "PSST_ENABLE_EMAIL", False):
        features.append(
            _feature(
                "email",
                "✉️",
                _("Email notifications"),
                _("Available"),
                "on",
                _(
                    "You can have an email sent when a whisper is created or "
                    "submitted. The email never contains the decryption key."
                ),
            )
        )
    else:
        features.append(
            _feature(
                "email",
                "✉️",
                _("Email notifications"),
                _("Off"),
                "off",
                _("This site does not send email notifications."),
            )
        )

    if getattr(settings, "PSST_ENABLE_STATS", False):
        features.append(
            _feature(
                "stats",
                "📊",
                _("Usage statistics"),
                _("On"),
                "on",
                _(
                    "Anonymous hourly counts of created and revealed whispers are kept "
                    "for up to a year. No content, keys, identifiers, IP addresses, or "
                    "accounts are recorded."
                ),
            )
        )
    else:
        features.append(
            _feature(
                "stats",
                "📊",
                _("Usage statistics"),
                _("Off"),
                "off",
                _("No usage statistics are collected."),
            )
        )

    features.append(
        _feature(
            "upload_limit",
            "📎",
            _("File size limit"),
            filesizeformat(settings.DATA_UPLOAD_MAX_MEMORY_SIZE),
            "neutral",
            _("Maximum total size of the files attached to a single whisper."),
        )
    )

    if getattr(settings, "ABOUT_PAGE_PERSISTENCE_ENABLED", False):
        features.append(
            _feature(
                "storage",
                "💾",
                _("Encrypted storage"),
                _("Saved to disk"),
                "neutral",
                _(
                    "Encrypted whispers are stored in Redis with persistence enabled, "
                    "so they survive server restarts until they expire."
                ),
            )
        )
    else:
        features.append(
            _feature(
                "storage",
                "💾",
                _("Encrypted storage"),
                _("Memory only"),
                "neutral",
                _(
                    "Encrypted whispers live only in memory and are lost if the "
                    "server restarts."
                ),
            )
        )

    return features
