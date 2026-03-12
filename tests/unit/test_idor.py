import pytest
from unittest.mock import MagicMock
from gateway.detection.idor import IDORDetector

def mock_request(path, user_id, query=""):
    r = MagicMock()
    r.url.path = path
    r.url.query = query
    r.url.__str__ = lambda self: f"http://test{path}{'?' + query if query else ''}"
    r.state.user_id = user_id
    r.state.is_authenticated = user_id is not None
    return r

@pytest.mark.asyncio
async def test_idor_detected():
    r = mock_request("/users/999/profile", user_id="123")
    result = await IDORDetector().detect(r)
    assert result.detected is True
    assert result.attack_type == "IDOR"

@pytest.mark.asyncio
async def test_own_resource_allowed():
    r = mock_request("/users/123/profile", user_id="123")
    result = await IDORDetector().detect(r)
    assert result.detected is False

@pytest.mark.asyncio
async def test_non_resource_url_ignored():
    r = mock_request("/api/v1/health", user_id="123")
    result = await IDORDetector().detect(r)
    assert result.detected is False
