from .settings import *  # noqa: F401, F403

PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]

PSST_ENABLE_RECEIVE_ACCESS = False
PSST_RECEIVE_ACCESS_DEFAULT = False
PSST_FORCE_RECEIVE_ACCESS = False

CACHES = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}

# Tests don't run collectstatic, so there is no manifest.
STORAGES = {
    **STORAGES,  # noqa: F405
    "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"},
}
