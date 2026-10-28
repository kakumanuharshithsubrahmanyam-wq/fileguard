"""FileGuard configuration.

Values live here so routes and database code do not hardcode paths,
size limits, or server settings.
"""

import os

# Directory that contains this file (the backend folder).
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# SQLite file created automatically on startup if it is missing.
DATABASE_PATH = os.path.join(BASE_DIR, "fileguard.db")

# Reject uploads larger than this. Flask enforces it via MAX_CONTENT_LENGTH.
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB

API_NAME = "FileGuard API"
API_VERSION = "1.0.0"

# Local / platform server settings.
# Render sets PORT. Local override when port 5000 is busy (e.g. macOS AirPlay):
#   FILEGUARD_PORT=5050 python app.py
# Gunicorn on Render uses: gunicorn app:app --bind 0.0.0.0:$PORT
HOST = os.environ.get("FILEGUARD_HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", os.environ.get("FILEGUARD_PORT", "5000")))

# Production (Render/Gunicorn) must not run the Flask debug reloader.
# Optional local debugging: FILEGUARD_DEBUG=1 python app.py
DEBUG = os.environ.get("FILEGUARD_DEBUG", "0").lower() in ("1", "true", "yes")

# Development default: allow any origin so a separately hosted frontend
# (Live Server, Vite, a static file server, another port) can call the API.
#
# To restrict origins later, replace "*" with an explicit list, for example:
# CORS_ORIGINS = [
#     "http://127.0.0.1:5500",
#     "http://localhost:5500",
#     "http://127.0.0.1:5173",
#     "http://localhost:5173",
# ]
CORS_ORIGINS = "*"
