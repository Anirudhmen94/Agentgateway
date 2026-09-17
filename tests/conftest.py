import pytest

from src.revocation import reset_store_for_tests

TEST_TOKEN = "test-gateway-token"


@pytest.fixture(autouse=True)
def isolated_p0_env(monkeypatch, tmp_path):
    monkeypatch.setenv("GATEWAY_TOKEN", TEST_TOKEN)
    monkeypatch.delenv("GATEWAY_HOST", raising=False)
    monkeypatch.setenv("REVOCATION_STORE_PATH", str(tmp_path / "revocations.json"))
    reset_store_for_tests()
    yield
    reset_store_for_tests()


@pytest.fixture
def auth_headers():
    return {"Authorization": f"Bearer {TEST_TOKEN}"}
