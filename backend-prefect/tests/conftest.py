import os

# Set before `app` is imported: app/__init__.py loads .env without overriding,
# so unit tests never use the real JWT secret or touch Supabase by accident.
os.environ["JWT_SECRET"] = "test-secret-" + "x" * 40
os.environ["DATABASE_URL"] = "postgresql://unused-in-unit-tests"
os.environ["PRE_AUTH_TOKEN_TTL_SECONDS"] = "300"
os.environ["ACCESS_TOKEN_TTL_SECONDS"] = "900"
os.environ["TOTP_ISSUER"] = "Lab2FA"
