"""FastAPI entry point: `uvicorn app.main:app --reload` from backend-prefect/."""

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from app.flows.errors import (
    InvalidCredentials,
    InvalidPreAuthState,
    InvalidSecondFactor,
    InvalidTransition,
    PreAuthTokenAlreadyUsed,
    ReplayAttackDetected,
    TooManyAttempts,
)
from app.repositories import UsernameTaken
from app.routers import auth, mfa, vault
from app.security.tokens import InvalidToken

WEB_DIR = Path(__file__).resolve().parent.parent / "web"

app = FastAPI(title="2FA Step-Up Auth + Prefect", version="0.1.0")

# Domain exception -> (HTTP status, machine-readable error code for the web app).
_ERRORS: dict[type[Exception], tuple[int, str]] = {
    InvalidCredentials: (401, "invalid_credentials"),
    InvalidToken: (401, "invalid_token"),
    InvalidPreAuthState: (401, "invalid_pre_auth"),
    PreAuthTokenAlreadyUsed: (401, "pre_auth_token_used"),
    InvalidSecondFactor: (401, "invalid_code"),
    ReplayAttackDetected: (409, "replay_detected"),
    InvalidTransition: (409, "invalid_state_transition"),
    UsernameTaken: (409, "username_taken"),
    TooManyAttempts: (429, "too_many_attempts"),
}


def _handler(status_code: int, error: str):
    async def handle(request: Request, exc: Exception) -> JSONResponse:
        detail = "invalid username or password" if error == "invalid_credentials" else str(exc)
        return JSONResponse({"error": error, "detail": detail}, status_code=status_code)

    return handle


for exc_type, (status_code, error) in _ERRORS.items():
    app.add_exception_handler(exc_type, _handler(status_code, error))


@app.middleware("http")
async def no_store_for_api(request: Request, call_next):
    """Responses carrying tokens or secrets must not be cached by the browser."""
    response = await call_next(request)
    if request.url.path.startswith(("/auth", "/2fa", "/api")):
        response.headers["Cache-Control"] = "no-store"
    return response


app.include_router(auth.router)
app.include_router(mfa.router)
app.include_router(vault.router)


@app.get("/health", tags=["meta"])
def health() -> dict:
    return {"status": "ok"}


# Mounted last so the API routes above take precedence.
app.mount("/", StaticFiles(directory=WEB_DIR, html=True), name="web")
