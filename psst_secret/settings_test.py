import environ

from whispers.apps import WhispersConfig

from .settings import *  # noqa: F401, F403

env = environ.Env(
    # Set casting, default value
    DEBUG=(bool, False)
)


class WhispersTestConfig(WhispersConfig):
    def ready(self):
        pass


INSTALLED_APPS = [
    "psst_secret.settings_test.WhispersTestConfig" if app == "whispers" else app
    for app in INSTALLED_APPS  # noqa: F405
]

PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]

PSST_ENABLE_RECEIVE_ACCESS = False
PSST_RECEIVE_ACCESS_DEFAULT = False
PSST_FORCE_RECEIVE_ACCESS = False

# Keep tests independent of white-label and deployment values in a developer's .env.
PSST_BRAND_NAME = "psst-secret"
PSST_BRAND_LOGO_URL = ""
PSST_BRAND_FAVICON_URL = ""
PSST_HIDE_SOCIAL_LINKS = False
PSST_HIDE_FOOTER_TEXT = False
PSST_HIDE_NAV_BRAND_NAME = False
ABOUT_PAGE_PERSISTENCE_ENABLED = False

CACHES = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}

# Tests don't run collectstatic, so there is no manifest.
STORAGES = {
    **STORAGES,  # noqa: F405
    "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"},
}
DATABASES = {
    "default": env.db_url("DATABASE_URL", default="sqlite:///:memory"),
}
