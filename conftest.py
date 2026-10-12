import pytest


def pytest_addoption(parser):
    parser.addoption(
        "--browser-tests", action="store_true", help="Run Playwright browser tests"
    )


def pytest_collection_modifyitems(config, items):
    if config.getoption("--browser-tests"):
        return
    skip = pytest.mark.skip(reason="Enable Playwright tests with --browser-tests")
    for item in items:
        if "browser" in item.keywords:
            item.add_marker(skip)
