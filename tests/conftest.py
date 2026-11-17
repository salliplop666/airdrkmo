import os

from cryptography.fernet import Fernet

# Valores de prueba ANTES de importar la app. Los tests con BD requieren TEST_DATABASE_URL.
os.environ.setdefault("DATABASE_URL", os.environ.get("TEST_DATABASE_URL", "postgresql+psycopg://x:x@localhost/x"))
os.environ.setdefault("JWT_SECRET", "test-secret-" + "x" * 40)
os.environ.setdefault("DATA_ENCRYPTION_KEY", Fernet.generate_key().decode())
os.environ.setdefault("ZAP_API_KEY", "test")
os.environ.setdefault("REQUIRE_TARGET_VERIFICATION", "false")
os.environ.setdefault("REPORTS_DIR", "/tmp/vulnaudit-test-reports")
