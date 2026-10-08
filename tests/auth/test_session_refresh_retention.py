"""A session-store refresh must keep the client fields, so the NEXT refresh still works.

Regression for the stale in-memory token bug: after the first in-memory refresh,
store_session() dropped client_id/client_secret/token_uri, so the second expiry
could not refresh and the server fell through to a fresh OAuth flow.
"""

from datetime import datetime, timedelta

import pytest
from google.oauth2.credentials import Credentials

import auth.google_auth as google_auth
from auth.oauth21_session_store import OAuth21SessionStore

SCOPE = "https://www.googleapis.com/auth/gmail.readonly"
EMAIL = "user@example.com"
SESSION = "mcp-session-1"


@pytest.fixture
def store(monkeypatch):
    s = OAuth21SessionStore()
    monkeypatch.setattr(google_auth, "get_oauth21_session_store", lambda: s)
    s.store_session(
        user_email=EMAIL,
        access_token="access-0",
        refresh_token="refresh-token",
        client_id="client-id",
        client_secret="client-secret",
        scopes=[SCOPE],
        expiry=datetime.utcnow() - timedelta(minutes=5),
        mcp_session_id=SESSION,
    )
    return s


def test_second_in_memory_refresh_succeeds(store, monkeypatch):
    calls = []

    def fake_refresh(self, request):
        # Google's token endpoint rejects a refresh without the client fields.
        if not (self.client_id and self.client_secret and self.refresh_token and self.token_uri):
            raise google_auth.RefreshError("invalid_client")
        calls.append(self.client_id)
        self.token = f"access-{len(calls)}"
        # Already expired again, so the next call must refresh from the stored session.
        self.expiry = datetime.utcnow() - timedelta(minutes=1)

    monkeypatch.setattr(Credentials, "refresh", fake_refresh)
    monkeypatch.delenv("MCP_SINGLE_USER_MODE", raising=False)

    first = google_auth.get_credentials(EMAIL, [SCOPE], session_id=SESSION)
    assert first is not None and first.token == "access-1"

    stored = store.get_credentials(EMAIL)
    assert stored.client_id == "client-id"
    assert stored.client_secret == "client-secret"
    assert stored.token_uri

    second = google_auth.get_credentials(EMAIL, [SCOPE], session_id=SESSION)
    assert second is not None and second.token == "access-2"
    assert calls == ["client-id", "client-id"]
