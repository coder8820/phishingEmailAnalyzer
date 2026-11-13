"""
Standard API response helpers for PhishGuard AI.
"""
from typing import Any, Optional
from fastapi.responses import JSONResponse
from fastapi import status


def success_response(data: Any = None, status_code: int = status.HTTP_200_OK, message: Optional[str] = None) -> JSONResponse:
    """Return standard success JSON response."""
    content = {
        "success": True,
        "data": data,
        "error": None,
    }
    if message:
        content["message"] = message
    return JSONResponse(status_code=status_code, content=content)


def error_response(code: str, message: str, status_code: int = status.HTTP_400_BAD_REQUEST, details: Any = None) -> JSONResponse:
    """Return standard error JSON response."""
    content = {
        "success": False,
        "data": None,
        "error": {
            "code": code,
            "message": message,
            "details": details,
        },
    }
    return JSONResponse(status_code=status_code, content=content)


def paginated_response(
    items: list[Any],
    total: int,
    page: int,
    page_size: int,
    status_code: int = status.HTTP_200_OK,
) -> JSONResponse:
    """Return paginated items JSON response."""
    total_pages = (total + page_size - 1) // page_size if page_size > 0 else 1
    content = {
        "success": True,
        "data": {
            "items": items,
            "pagination": {
                "total": total,
                "page": page,
                "page_size": page_size,
                "total_pages": total_pages,
            },
        },
        "error": None,
    }
    return JSONResponse(status_code=status_code, content=content)
