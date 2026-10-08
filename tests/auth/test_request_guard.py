import pytest
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from auth.request_guard_middleware import RequestGuardMiddleware, local_hosts

TOKEN = "test-token-123"
PORT = 8020
BASE = f"http://127.0.0.1:{PORT}"


async def ok(request):
    return JSONResponse({"ok": True})


@pytest.fixture
def client():
    app = Starlette(
        routes=[
            Route("/mcp", ok, methods=["GET", "POST"]),
            Route("/health", ok),
            Route("/oauth2callback", ok),
        ],
        middleware=[
            Middleware(RequestGuardMiddleware, token=TOKEN, allowed_hosts=local_hosts(PORT))
        ],
    )
    return TestClient(app, base_url=BASE)


def bearer(token=TOKEN):
    return {"Authorization": f"Bearer {token}"}


def test_mcp_with_token_and_local_host_passes(client):
    assert client.post("/mcp", headers=bearer()).status_code == 200


def test_localhost_name_is_allowed(client):
    r = client.post("/mcp", headers={**bearer(), "Host": f"localhost:{PORT}"})
    assert r.status_code == 200


def test_mcp_without_token_is_401(client):
    r = client.post("/mcp")
    assert r.status_code == 401
    assert r.headers["www-authenticate"].startswith("Bearer")


def test_mcp_with_wrong_token_is_401(client):
    assert client.post("/mcp", headers=bearer("wrong")).status_code == 401


def test_mcp_with_origin_is_403_even_with_token(client):
    r = client.post("/mcp", headers={**bearer(), "Origin": "http://evil.example"})
    assert r.status_code == 403


def test_foreign_host_is_403_even_with_token(client):
    r = client.post("/mcp", headers={**bearer(), "Host": f"evil.example:{PORT}"})
    assert r.status_code == 403


def test_wrong_port_in_host_is_403(client):
    r = client.post("/mcp", headers={**bearer(), "Host": "127.0.0.1:9999"})
    assert r.status_code == 403


def test_health_needs_no_token(client):
    assert client.get("/health").status_code == 200


def test_oauth_callback_needs_no_token_but_checks_host(client):
    assert client.get("/oauth2callback").status_code == 200
    r = client.get("/oauth2callback", headers={"Host": f"evil.example:{PORT}"})
    assert r.status_code == 403


def test_empty_token_is_refused():
    with pytest.raises(ValueError):
        RequestGuardMiddleware(lambda *a: None, token="", allowed_hosts=local_hosts(PORT))


class TestServerWiring:
    """The real server's http_app() must include the guard and fail closed without a token."""

    def test_http_app_refuses_without_token(self, monkeypatch):
        monkeypatch.delenv("WORKSPACE_MCP_BEARER_TOKEN", raising=False)
        monkeypatch.delenv("MCP_ENABLE_OAUTH21", raising=False)
        from core.server import server

        with pytest.raises(RuntimeError):
            server.http_app(transport="streamable-http")

    def test_http_app_guards_mcp_path(self, monkeypatch):
        monkeypatch.setenv("WORKSPACE_MCP_BEARER_TOKEN", TOKEN)
        monkeypatch.setenv("WORKSPACE_MCP_PORT", str(PORT))
        monkeypatch.delenv("PORT", raising=False)
        monkeypatch.delenv("MCP_ENABLE_OAUTH21", raising=False)
        from auth.oauth_config import reload_oauth_config
        from core.server import server

        reload_oauth_config()
        app = server.http_app(transport="streamable-http")
        c = TestClient(app, base_url=BASE)
        assert c.post("/mcp", json={}).status_code == 401
        assert c.post("/mcp", json={}, headers={**bearer(), "Origin": "http://evil.example"}).status_code == 403
