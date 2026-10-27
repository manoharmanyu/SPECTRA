import secrets
from fastapi import Header, HTTPException, status, Request
from app.config import settings


def verify_internal_token(authorization: str = Header(None)) -> bool:
    """
    Require Authorization: Bearer SPECTRA_INTERNAL_TOKEN; reject missing/invalid
    tokens using constant-time comparison to prevent timing attacks.
    """
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header."
        )

    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authorization scheme. Bearer token required."
        )

    expected_token = settings.SPECTRA_INTERNAL_TOKEN
    # Constant-time comparison
    if not secrets.compare_digest(token.strip(), expected_token.strip()):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Invalid internal authorization token."
        )

    return True


def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"
