import os
import re
import logging
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import requests

# Google auth for backend authentication
from google.auth.transport.requests import Request as GoogleRequest
from google.oauth2 import id_token as google_id_token

# ----------------------
# Configuration
# ----------------------
BACKEND_URL = os.getenv("BACKEND_URL")
FRONTEND_ORIGIN = os.getenv("FRONTEND_ORIGIN", "https://oravec.io")
RATE_LIMIT = os.getenv("RATE_LIMIT", "10 per minute")
MAX_MESSAGE_LENGTH = int(os.getenv("MAX_MESSAGE_LENGTH", "1000"))

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("nifty-proxy")

# ----------------------
# App Setup
# ----------------------
app = Flask(__name__)
CORS(app, origins=[FRONTEND_ORIGIN])

# ----------------------
# Rate Limiter
# ----------------------
def client_key_func():
    """Rate limit by user_id if present, otherwise by IP."""
    try:
        data = request.get_json(silent=True) or {}
        user_id = data.get("user_id")
        if user_id:
            return str(user_id)
    except Exception:
        pass
    return get_remote_address()

limiter = Limiter(
    app=app,
    key_func=client_key_func,
    default_limits=[RATE_LIMIT]
)

# ----------------------
# Helpers
# ----------------------
def sanitize_text(text: str) -> str:
    """Strip HTML tags and control chars."""
    if text is None:
        return ""
    text = re.sub(r"<.*?>", "", text)
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)
    return text.strip()

def get_id_token_for_backend(audience: str) -> str:
    """Get Google ID token for backend authentication."""
    req = GoogleRequest()
    return google_id_token.fetch_id_token(req, audience)

# ----------------------
# Endpoints
# ----------------------
@app.route("/", methods=["GET"])
def health_check():
    return jsonify({"status": "proxy-running"}), 200

@app.route("/chat", methods=["POST"])
@limiter.limit(RATE_LIMIT)
def chat_proxy():
    # Validate JSON body
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid JSON body"}), 400

    user_id = data.get("user_id")
    message = data.get("message")
    if not user_id or not message:
        return jsonify({"error": "user_id and message required"}), 400

    # Validate message length
    if len(message) > MAX_MESSAGE_LENGTH:
        return jsonify({"error": f"message too long (max {MAX_MESSAGE_LENGTH} characters)"}), 400

    # Prepare payload
    payload = {
        "user_id": user_id,
        "message": sanitize_text(message)
    }

    # Get backend auth token
    if not BACKEND_URL:
        logger.error("BACKEND_URL is not configured")
        return jsonify({"error": "Server misconfiguration"}), 500

    try:
        id_tok = get_id_token_for_backend(BACKEND_URL)
    except Exception as e:
        logger.exception("Failed to obtain ID token for backend: %s", e)
        return jsonify({"error": "Failed to authenticate to backend"}), 500

    # Forward to backend
    try:
        resp = requests.post(
            f"{BACKEND_URL.rstrip('/')}/chat",
            json=payload,
            headers={
                "Authorization": f"Bearer {id_token}",
                "Content-Type": "application/json"
            },
            timeout=15
        )
        return jsonify(resp.json()), resp.status_code
    except requests.RequestException as e:
        logger.exception("Backend request failed: %s", e)
        return jsonify({"error": "Failed to reach backend"}), 502
    except ValueError:
        return resp.text, resp.status_code
