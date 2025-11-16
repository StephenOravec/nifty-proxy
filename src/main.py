from flask import Flask, request, jsonify
import os

app = Flask(__name__)

@app.get("/")
def health_check():
    return {"status": "proxy-running"}

# TODO: Add secure proxy endpoint later
# - IAM verification
# - Fetch API key from Google Secret Manager
# - Forward request to backend

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
