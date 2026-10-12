import pytest
from django.core.cache import cache
from django.test.testcases import QuietWSGIRequestHandler
from playwright.sync_api import expect
from pytest_django.live_server_helper import LiveServer

from whispers.tests.test_whisper import _patch_redis


class BrowserRequestHandler(QuietWSGIRequestHandler):
    timeout = 1


@pytest.fixture(scope="session", autouse=True)
def browser_environment(pytestconfig):
    if pytestconfig.getoption("--browser-tests"):
        with pytest.MonkeyPatch.context() as environment:
            environment.setenv("DJANGO_ALLOW_ASYNC_UNSAFE", "true")
            yield
    else:
        yield


@pytest.fixture
def browser_app(settings, transactional_db, request):
    settings.ENABLE_AUTH = False
    settings.MIDDLEWARE = [
        middleware
        for middleware in settings.MIDDLEWARE
        if middleware != "whispers.middleware.LoginRequiredMiddleware"
    ]
    settings.PSST_ENABLE_EMAIL = False
    settings.PSST_ENABLE_STATS = False
    settings.PSST_ENABLE_RECEIVE_ACCESS = False
    settings.PSST_RECEIVE_ACCESS_DEFAULT = False
    settings.PSST_FORCE_RECEIVE_ACCESS = False
    settings.PSST_FORCE_AUTH_VIEW = False
    settings.PSST_FORCE_AUTH_SUBMIT = False
    settings.LANGUAGE_CODE = "en"
    settings.ALLOWED_HOSTS = ["localhost", "127.0.0.1", "testserver"]
    overrides = request.node.get_closest_marker("browser_settings")
    if overrides:
        for name, value in overrides.kwargs.items():
            setattr(settings, name, value)
    cache.clear()
    patcher, redis = _patch_redis()
    with patcher:
        yield redis
    cache.clear()


@pytest.fixture
def live_server(browser_app):
    server = LiveServer("localhost")
    server.thread.httpd.RequestHandlerClass = BrowserRequestHandler
    server.thread.httpd.daemon_threads = False
    try:
        yield server
    finally:
        server.stop()


@pytest.fixture
def app_url(browser_app, live_server):
    return live_server.url


@pytest.fixture
def context(app_url, new_context):
    return new_context()


@pytest.fixture
def create_whisper(page, app_url):
    def create(
        kind="send", content="A private browser-only whisper", files=None, **fields
    ):
        page.goto(app_url)
        if kind == "receive":
            page.locator("#tab-receive").click()
        elif files:
            page.locator("#tab-file").click()
            page.locator("#file-input").set_input_files(files)
        else:
            page.locator("#whisper").fill(content)
        for name, value in fields.items():
            if name not in ("expiry", "max_views", "max_views_custom"):
                page.locator("#advanced-options").evaluate(
                    "element => element.open = true"
                )
            field = page.locator("#" + name.replace("_", "-"))
            if isinstance(value, bool):
                field.set_checked(value)
            elif name in ("expiry", "max_views"):
                field.select_option(str(value))
            else:
                field.fill(str(value))
        if kind == "receive":
            page.locator("#request-btn").click()
            expect(page.locator("#receive-result")).to_be_visible()
            return (
                page.locator("#submit-url").input_value(),
                page.locator("#view-url").input_value(),
            )
        page.locator("#encrypt-btn").click()
        expect(page.locator("#result")).to_be_visible()
        return page.locator("#result-url").input_value()

    return create


@pytest.fixture
def verified_user(browser_app, django_user_model):
    from allauth.account.models import EmailAddress

    def create(username="browser-reader"):
        user = django_user_model.objects.create_user(
            username=username,
            email=f"{username}@example.com",
            password="Browser-login-password-42!",
        )
        EmailAddress.objects.create(
            user=user, email=user.email, verified=True, primary=True
        )
        return user

    return create


@pytest.fixture
def sign_in(page, app_url):
    def login(user):
        page.goto(app_url + "/login/")
        page.locator("#username").fill(user.username)
        page.locator("#password").fill("Browser-login-password-42!")
        page.locator('button[type="submit"]').click()
        expect(page).to_have_url(app_url + "/")

    return login
