import json
import os
import stat
import threading
from datetime import datetime, timedelta

import pytest
from google.oauth2.credentials import Credentials

import auth.credential_store as cs
from auth.credential_store import LocalDirectoryCredentialStore

EMAIL = "user@example.com"


def make_creds(token: str) -> Credentials:
    return Credentials(
        token=token,
        refresh_token="refresh-token",
        token_uri="https://oauth2.googleapis.com/token",
        client_id="client-id",
        client_secret="client-secret",
        scopes=["https://www.googleapis.com/auth/gmail.readonly"],
        expiry=datetime.utcnow() + timedelta(hours=1),
    )


def mode(path) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


def test_new_directory_is_0700_and_file_is_0600(tmp_path):
    base = tmp_path / "creds"
    store = LocalDirectoryCredentialStore(str(base))
    assert store.store_credential(EMAIL, make_creds("a"))
    assert mode(base) == 0o700
    assert mode(base / f"{EMAIL}.json") == 0o600


def test_rewrite_tightens_an_existing_0644_file(tmp_path):
    store = LocalDirectoryCredentialStore(str(tmp_path))
    path = tmp_path / f"{EMAIL}.json"
    path.write_text("{}")
    os.chmod(path, 0o644)
    assert store.store_credential(EMAIL, make_creds("a"))
    assert mode(path) == 0o600


def test_failed_write_leaves_previous_file_intact(tmp_path, monkeypatch):
    store = LocalDirectoryCredentialStore(str(tmp_path))
    assert store.store_credential(EMAIL, make_creds("old"))
    before = (tmp_path / f"{EMAIL}.json").read_text()

    def boom(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(cs.json, "dump", boom)
    assert store.store_credential(EMAIL, make_creds("new")) is False
    assert (tmp_path / f"{EMAIL}.json").read_text() == before
    assert [p.name for p in tmp_path.iterdir()] == [f"{EMAIL}.json"]  # no temp file left


def test_concurrent_writes_leave_valid_json(tmp_path):
    store = LocalDirectoryCredentialStore(str(tmp_path))
    errors = []

    def writer(i):
        for j in range(25):
            if not store.store_credential(EMAIL, make_creds(f"t{i}-{j}")):
                errors.append((i, j))

    threads = [threading.Thread(target=writer, args=(i,)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == []
    data = json.loads((tmp_path / f"{EMAIL}.json").read_text())
    assert data["token"].startswith("t") and data["refresh_token"] == "refresh-token"
    assert [p.name for p in tmp_path.iterdir()] == [f"{EMAIL}.json"]


def test_temp_files_are_not_listed_as_users(tmp_path):
    (tmp_path / ".tmp-abc.tmp").write_text("{}")
    store = LocalDirectoryCredentialStore(str(tmp_path))
    store.store_credential(EMAIL, make_creds("a"))
    assert store.list_users() == [EMAIL]
