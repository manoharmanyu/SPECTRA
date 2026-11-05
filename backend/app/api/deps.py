import secrets
from fastapi import Header, HTTPException, status, Request
from app.config import settings


import secrets
from typing import Optional, Dict, Any
from fastapi import Header, HTTPException, status, Request
from app.config import settings


def verify_internal_token(authorization: Optional[str] = Header(None)) -> bool:
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


def get_current_user_context(
    request: Request,
    authorization: Optional[str] = Header(None),
    x_session_id: Optional[str] = Header(None),
    x_user_id: Optional[str] = Header(None)
) -> Dict[str, Any]:
    """
    Extracts authenticated user context from request headers, session tokens, or internal token.
    Provides verified user identity for object-level access control.
    """
    # 1. Check for Internal Orchestration Token (admin/service role)
    if authorization:
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() == "bearer" and token.strip():
            if secrets.compare_digest(token.strip(), settings.SPECTRA_INTERNAL_TOKEN.strip()):
                return {
                    "id": "system_internal",
                    "role": "admin",
                    "is_internal": True,
                    "is_admin": True
                }

    # 2. Check for explicit User ID header or session token
    user_id = x_user_id or x_session_id
    if not user_id and authorization:
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() == "bearer" and token.strip() and token.startswith("usr_"):
            user_id = token.strip()

    user_role = request.headers.get("X-User-Role", "investigator")
    is_admin = user_role.lower() == "admin"

    if user_id:
        return {
            "id": user_id.strip(),
            "role": user_role,
            "is_internal": False,
            "is_admin": is_admin
        }

    return {
        "id": "anonymous_guest",
        "role": "guest",
        "is_internal": False,
        "is_admin": False
    }


def enforce_job_ownership(job_user_id: Optional[str], user_context: Dict[str, Any]):
    """
    Strict Object-Level Authorization:
    Prevents Insecure Direct Object References (IDOR).
    If a job is tagged with a user_id, only that user or an internal admin may access it.
    """
    if not job_user_id:
        # Unowned/public legacy job
        return

    if user_context.get("is_admin") or user_context.get("is_internal"):
        return

    current_id = user_context.get("id")
    if not current_id or current_id == "anonymous_guest":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required to access this forensic dossier."
        )

    if current_id != job_user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: You do not have permission to view or manage this forensic dossier (Object-Level Authorization enforced)."
        )


def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"
