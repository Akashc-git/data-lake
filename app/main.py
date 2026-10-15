"""
Main FastAPI Application Entrypoint for CF-PS-15 Data Lake Access Control.
Initializes database tables, configures CORS, security headers, structured exception handling,
and mounts all REST API routers.
"""

from contextlib import asynccontextmanager
from datetime import datetime, timezone
import logging
from fastapi import FastAPI, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.auth.dependencies import engine
from app.auth.models import Base
from app.config import get_settings
from app.api.auth import router as auth_router
from app.api.dashboard import router as dashboard_router
from app.api.datasets import router as datasets_router
from app.api.access_tests import router as access_tests_router
from app.api.audit import router as audit_router

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("app.main")
settings = get_settings()


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Appends hardened HTTP response headers for defense in depth."""
    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        return response


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan context for setup and teardown."""
    logger.info("Initializing SQLite database tables...")
    Base.metadata.create_all(bind=engine)
    logger.info(f"Database schema initialized at {settings.DATABASE_URL}")

    if settings.is_b2_configured:
        logger.info(f"Backblaze B2 S3 API configured for endpoint: {settings.B2_ENDPOINT_URL}")
    else:
        logger.warning("Backblaze B2 is not configured in .env. Cloud access checks will return INCONCLUSIVE.")
    yield
    logger.info("Application shutting down...")


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Role-Based Cloud Data-Lake Access Control Dashboard backed by Backblaze B2 S3-Compatible API.",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/api/openapi.json",
    lifespan=lifespan,
)

# CORS Middleware (Support local Streamlit frontend on port 8501)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:8501",
        "http://127.0.0.1:8501",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(SecurityHeadersMiddleware)


@app.exception_handler(HTTPException)
async def custom_http_exception_handler(request: Request, exc: HTTPException):
    """Provides structured, consistent error responses across all endpoints."""
    detail = exc.detail
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": True,
            "status_code": exc.status_code,
            "detail": detail,
            "path": request.url.path,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
        headers=exc.headers,
    )


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Catches unhandled server errors and logs them safely."""
    logger.error(f"Unhandled server error on {request.url.path}: {exc}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": True,
            "status_code": 500,
            "detail": "Internal server error occurred.",
            "path": request.url.path,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
    )


# Mount API routers under /api
app.include_router(auth_router, prefix="/api")
app.include_router(dashboard_router, prefix="/api")
app.include_router(datasets_router, prefix="/api")
app.include_router(access_tests_router, prefix="/api")
app.include_router(audit_router, prefix="/api")


@app.get("/")
def root():
    """Root redirect message."""
    return {
        "message": "CF-PS-15 Data Lake Access Control API is running.",
        "docs": "/docs",
        "status": "/api/health",
    }
