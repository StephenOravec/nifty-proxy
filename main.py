"""
Production-ready proxy for Nifty-Bot.

Responsibilities:
- Accepts frontend requests (POST /chat)
- Validates input, rate-limits, sanitizes
- Optionally validates a session token stored in Firestore
- Obtains a Google-signed ID token and forwards the request to the backend
- Returns backend response to the client

Deploy to Cloud Run (or Cloud Functions). This proxy expects to run
on Google Cloud with Application Default Credentials available.
"""

import os
import re
import json
import uuid
import logging
from flask import Flask, request, jsonify
import requests

# Google auth libs for ID token creation
from google.auth.transport.requests import Request as GoogleRequest
from google.oauth2 import id_token as google_id_token
import google.auth

# Firestore (optional session-token validation)
from google.cloud import firestore

# Rate limiting
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# ----------------------
# Configuration via ENV
# ----------------------
BACKEND_URL = os.getenv("BACKEND_URL")  # e.g. https://nifty-bot-566869872467.us-east5.run.app
FRONTEND_ORIGIN = os.getenv("FRONTEND_ORIGIN", "https://oravec.io")
RATE_LIMIT = os.getenv("RATE_LIMIT", "10 per minute")  # string accepted by flask-limiter
MAX_MESSAGE_LENGTH = int(os.getenv("MAX_MESSAGE_LENGTH", "1000"))
REDIS_URL = os.getenv("REDIS_URL")  # optional: e.g. redis://:password@host:6379/0
REQUIRE_SESSION_TOKEN = os.getenv("REQUIRE_SESSION_TOKEN", "false").lower() == "true"
SESSION_TOKEN_COLLECTION = os.getenv("SESSION_TOKEN_COLLECTION", "session_tokens")  # Firestore collection name
ENV = os.getenv("ENV", "production")

# Basic logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("nifty-proxy")

# ----------------------
# App + CORS (simple)
# ----------------------
from flask_cors import CORS

app = Flask(__name__)
CORS(app, origins=[FRONTEND_ORIGIN])

# ----------------------
# Rate limiter setup
# ----------------------
def client_key_func():
    """
    Use user_id from JSON if present (so rate-limits apply per anonymous user),
    otherwise fallback to IP address.
    """
    try:
        js = request.get_json(silent=True) or {}
        uid = js.get("user_id")
        if uid:
            return str(uid)
    except Exception:
        pass
    return get_remote_address()

if REDIS_URL:
    limiter = Limiter(
        app,
        key_func=client_key_func,
        storage_uri=REDIS_URL,
        default_limits=[RATE_LIMIT]
    )
else:
    # In-memory limiter (per instance). OK for small workloads/testing.
    limiter = Limiter(
        app=app,
        key_func=client_key_func,
        default_limits=[RATE_LIMIT]
    )

# ----------------------
# Firestore client (optional)
# ----------------------
firestore_client = None
if REQUIRE_SESSION_TOKEN:
    # Firestore client will use ADC (Cloud Run service account) in production
    firestore_client = firestore.Client()

# ----------------------
# Helpers
# ----------------------
def sanitize_text(text: str) -> str:
    """Simple sanitization: strip HTML tags and control chars."""
    if text is None:
        return ""
    # Remove any HTML tags
    text = re.sub(r"<.*?>", "", text)
    # Remove control characters except newline/tab
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)
    return text.strip()

def validate_user_id(user_id: str) -> bool:
    """Expect a UUID v4 user_id (anonymous). Return True if valid."""
    try:
        uuid_obj = uuid.UUID(user_id, version=4)
        return True
    except Exception:
        return False

def validate_session_token(token: str) -> bool:
    """
    If REQUIRE_SESSION_TOKEN is enabled, check Firestore collection
    for a token document with active==True.
    """
    if not REQUIRE_SESSION_TOKEN:
        return True  # not required
    if not token:
        return False
    try:
        doc = firestore_client.collection(SESSION_TOKEN_COLLECTION).document(token).get()
        if doc.exists:
            data = doc.to_dict() or {}
            return bool(data.get("active", False))
    except Exception as e:
        logger.exception("Error validating session token: %s", e)
    return False

def get_id_token_for_backend(audience: str) -> str:
    """
    Obtain an identity token with the Cloud Run backend URL as audience.
    This uses Application Default Credentials (the service account of the proxy).
    """
    # Use google.oauth2.id_token.fetch_id_token backed by ADC
    # GoogleRequest is required as the transport.
    req = GoogleRequest()
    token = google_id_token.fetch_id_token(req, audience)
    return token

# ----------------------
# Endpoints
# ----------------------
@app.route("/", methods=["GET"])
def health_check():
    return jsonify({"status": "proxy-running"}), 200

@app.route("/chat", methods=["POST"])
@limiter.limit(RATE_LIMIT)  # explicit per-route limit (same as default)
def chat_proxy():
    # Validate JSON body
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid JSON body"}), 400

    user_id = data.get("user_id")
    message = data.get("message")
    if not user_id or not message:
        return jsonify({"error": "user_id and message required"}), 400

    # Validate user_id format (UUID v4)
    if not validate_user_id(user_id):
        return jsonify({"error": "user_id must be a UUID v4"}), 400

    # Validate message length
    if len(message) > MAX_MESSAGE_LENGTH:
        return jsonify({"error": f"message too long (max {MAX_MESSAGE_LENGTH} characters)"}), 400

    # Optional: validate session token header
    session_token = request.headers.get("x-session-token")
    if REQUIRE_SESSION_TOKEN:
        if not validate_session_token(session_token):
            return jsonify({"error": "Invalid or missing session token"}), 401

    # Sanitize message
    safe_message = sanitize_text(message)

    # Prepare payload to backend (we pass user_id and sanitized message)
    payload = {"user_id": user_id, "message": safe_message}

    # Acquire an ID token for backend authentication (Cloud Run IAM)
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
                "Authorization": f"Bearer {id_tok}",
                "Content-Type": "application/json"
            },
            timeout=15
        )
    except requests.RequestException as e:
        logger.exception("Request to backend failed: %s", e)
        return jsonify({"error": "Failed to reach backend"}), 502

    # Proxy the backend response (assume JSON)
    try:
        content = resp.json()
    except ValueError:
        # Backend did not return JSON
        return (resp.text, resp.status_code, resp.headers.items())

    return (jsonify(content), resp.status_code)

# ----------------------
# Run locally for testing (not used in Cloud Run)
# ----------------------
if __name__ == "__main__":
    # In development you might allow CORS from localhost, but avoid this in prod
    if ENV != "production":
        app.run(host="0.0.0.0", port=8080, debug=True)
    else:
        app.run(host="0.0.0.0", port=8080)

