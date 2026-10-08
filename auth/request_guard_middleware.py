"""Request guard for the local streamable-HTTP server.

Single-user HTTP mode runs with ``auth=None``, so anything that can reach the port
acts as the signed-in Google user. This ASGI middleware closes the two ways in:

* Browser pages (cross-origin POST, DNS rebinding): every request must carry a
  local Host header, and the MCP endpoint rejects any request with an Origin
  header. Native MCP clients send no Origin.
* Local workloads that can reach localhost but cannot read the user's files: the
  MCP endpoint requires ``Authorization: Bearer <WORKSPACE_MCP_BEARER_TOKEN>``.

``/health`` and ``/oauth2callback`` only get the Host check, because a browser
navigation to the OAuth callback carries neither a token nor an Origin.

Written as plain ASGI (not BaseHTTPMiddleware) so streamed MCP responses pass
through untouched.
"""

import hmac
import json
import logging
import os
from typing import Iterable

logger = logging.getLogger(__name__)

BEARER_TOKEN_ENV = "WORKSPACE_MCP_BEARER_TOKEN"


def get_bearer_token() -> str | None:
    token = os.getenv(BEARER_TOKEN_ENV, "").strip()
    return token or None


class RequestGuardMiddleware:
    def __init__(
        self,
        app,
        token: str,
        allowed_hosts: Iterable[str],
        mcp_path: str = "/mcp",
    ):
        if not token:
            raise ValueError("RequestGuardMiddleware needs a non-empty bearer token")
        self.app = app
        self._token = token.encode()
        self._allowed_hosts = {h.lower() for h in allowed_hosts}
        self._mcp_path = mcp_path.rstrip("/") or "/"

    def _is_mcp_path(self, path: str) -> bool:
        return path == self._mcp_path or path.startswith(self._mcp_path + "/")

    async def __call__(self, scope, receive, send):
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", [])}
        path = scope.get("path", "")

        host = headers.get("host", "").lower()
        if host not in self._allowed_hosts:
            logger.warning(f"[request_guard] rejected host {host!r} for {path}")
            await self._reject(scope, send, 403, "forbidden host")
            return

        if self._is_mcp_path(path):
            if "origin" in headers:
                logger.warning(f"[request_guard] rejected request with Origin {headers['origin']!r}")
                await self._reject(scope, send, 403, "cross-origin requests are not allowed")
                return
            auth = headers.get("authorization", "")
            scheme, _, presented = auth.partition(" ")
            if scheme.lower() != "bearer" or not hmac.compare_digest(presented.strip().encode(), self._token):
                await self._reject(scope, send, 401, "missing or invalid bearer token", bearer=True)
                return

        await self.app(scope, receive, send)

    async def _reject(self, scope, send, status: int, message: str, bearer: bool = False):
        if scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 1008})
            return
        body = json.dumps({"error": message}).encode()
        headers = [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode()),
        ]
        if bearer:
            headers.append((b"www-authenticate", b'Bearer realm="workspace-mcp"'))
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": body})


def local_hosts(port: int) -> list[str]:
    return [f"127.0.0.1:{port}", f"localhost:{port}"]
