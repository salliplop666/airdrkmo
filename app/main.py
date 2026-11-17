import logging
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.api import admin, auth, scans
from app.core.config import settings

logging.basicConfig(level=logging.INFO if settings.env == "production" else logging.DEBUG, format="%(asctime)s %(levelname)s [%(name)s] %(message)s")
log = logging.getLogger("vulnaudit")

prod = settings.env == "production"

app = FastAPI(title="VulnAudit", version="0.1.0", docs_url=None if prod else "/docs", redoc_url=None, openapi_url=None if prod else "/openapi.json")

if settings.cors_origins:
    app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origins, allow_credentials=False, allow_methods=["GET", "POST", "DELETE"], allow_headers=["Authorization", "Content-Type"])

if prod:
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.trusted_hosts)

@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    resp.headers.setdefault("Cache-Control", "no-store")
    if prod:
        resp.headers.setdefault("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
    return resp

@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    log.exception("Error no manejado en %s %s", request.method, request.url.path)
    return JSONResponse(status_code=500, content={"detail": "Error interno del servidor"} if prod else {"detail": str(exc)})

for r in (auth.router, admin.router, scans.router):
    app.include_router(r, prefix="/api/v1")

@app.get("/healthz", include_in_schema=False)
def healthz():
    return {"status": "ok"}