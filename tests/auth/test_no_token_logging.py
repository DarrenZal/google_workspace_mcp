"""No log call may format any part of a bearer/access token.

The HTTP request guard uses a static bearer token; AuthInfoMiddleware used to log its
first 20 characters at INFO on every request, which put half the token in the service log.
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PATTERN = re.compile(r"logger\.\w+\(.*\btoken\w*\s*\[", re.IGNORECASE)


def test_no_logger_call_slices_a_token():
    offenders = []
    for path in list((ROOT / "auth").rglob("*.py")) + list((ROOT / "core").rglob("*.py")):
        for n, line in enumerate(path.read_text().splitlines(), 1):
            if PATTERN.search(line):
                offenders.append(f"{path.relative_to(ROOT)}:{n}")
    assert offenders == []
