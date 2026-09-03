import os


DATABASE_URL = "sqlite:///./vulntracker.db"

SECRET_KEY = os.environ["SECRET_KEY"]
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

NOTIFY_SERVICE_URL = "http://localhost:3001"
NOTIFY_SERVICE_KEY = os.environ["NOTIFY_SERVICE_KEY"]

# This value must come from trusted deployment configuration, never from a request.
PUBLIC_BASE_URL = os.environ.get("PUBLIC_BASE_URL", "http://localhost:8000").rstrip("/")
