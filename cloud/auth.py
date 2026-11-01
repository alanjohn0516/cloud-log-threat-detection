# cloud/auth.py
# API key protection for the cloud API.
# If the API_KEY environment variable is set, protected endpoints need the header
#   X-API-Key: <the key>
# If API_KEY is not set, the API is open (development mode).
import hmac
import os

from fastapi import Header, HTTPException


def require_api_key(x_api_key: str | None = Header(default=None)):
    expected = os.environ.get("API_KEY")
    if not expected:
        return                                   # development mode: no key needed
    supplied = x_api_key or ""
    if not hmac.compare_digest(supplied.encode(), expected.encode()):
        raise HTTPException(status_code=401, detail="Invalid or missing API key")
