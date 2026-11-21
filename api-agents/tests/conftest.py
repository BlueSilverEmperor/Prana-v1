"""Shared test setup: every test starts with an empty vaccine registry, so one test's blocked attacks never
immunise the next test's vaults."""

import pytest

from api_agents.vaccination import REGISTRY


@pytest.fixture(autouse=True)
def _empty_vaccine_registry():
    REGISTRY.reset()
    yield
    REGISTRY.reset()
