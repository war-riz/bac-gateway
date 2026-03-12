import pytest
from unittest.mock import MagicMock
from gateway.detection.forceful_browsing import ForcefulBrowsingDetector

def mock_request(path, authenticated):
    r = MagicMock()
    r.url.path = path
    r.client.host = "127.0.0.1"
    r.state.is_authenticated = authenticated
    return r

@pytest.mark.asyncio
async def test_blocks_unauthenticated_admin_access():
    r = mock_request("/admin/dashboard", authenticated=False)
    result = await ForcefulBrowsingDetector().detect(r)
    assert result.detected is True

@pytest.mark.asyncio
async def test_allows_authenticated_admin_access():
    r = mock_request("/admin/dashboard", authenticated=True)
    result = await ForcefulBrowsingDetector().detect(r)
    assert result.detected is False

@pytest.mark.asyncio
async def test_public_routes_always_allowed():
    for path in ["/api/v1/auth/login", "/api/v1/health", "/docs"]:
        r = mock_request(path, authenticated=False)
        result = await ForcefulBrowsingDetector().detect(r)
        assert result.detected is False, f"Should allow public: {path}"
