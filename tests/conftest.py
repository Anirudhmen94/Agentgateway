import pytest

from src.policy import get_engine
from src.quota import reset_store_for_tests as reset_quota_store_for_tests
from src.revocation import reset_store_for_tests

TEST_TOKEN = "test-gateway-token"


@pytest.fixture(autouse=True)
def isolated_p0_env(monkeypatch, tmp_path):
    monkeypatch.setenv("GATEWAY_TOKEN", TEST_TOKEN)
    monkeypatch.delenv("GATEWAY_HOST", raising=False)
    monkeypatch.setenv("REVOCATION_STORE_PATH", str(tmp_path / "revocations.json"))
    monkeypatch.setenv("QUOTA_STORE_PATH", str(tmp_path / "quotas.json"))
    reset_store_for_tests()
    reset_quota_store_for_tests()
    get_engine().reset_rate_limits()
    yield
    reset_store_for_tests()
    reset_quota_store_for_tests()
    get_engine().reset_rate_limits()


@pytest.fixture
def auth_headers():
    return {"Authorization": f"Bearer {TEST_TOKEN}"}
