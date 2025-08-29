
# secure_api.py
# Simple Flask API implementing:
# - POST /register
# - POST /login
# - GET /profile (protected)
#
# Uses PyJWT for token creation and Werkzeug for password hashing.
# Configure SECRET_KEY via environment variable SECURE_API_SECRET (fallback to default for demo).
#
# Run: pip install flask pyjwt werkzeug
# Then: python secure_api.py

import os
from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps

app = Flask(__name__)
SECRET = os.environ.get("SECURE_API_SECRET", "PleaseChangeThisDemoSecret_ReplaceInProd")
ALGORITHM = "HS256"
ACCESS_EXPIRE_MINUTES = 60

# In-memory "database" for demo purposes
USERS = {}

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization", None)
        if not auth:
            return jsonify({"msg":"Missing Authorization header"}), 401
        parts = auth.split()
        if parts[0].lower() != "bearer" or len(parts) != 2:
            return jsonify({"msg":"Invalid Authorization header format. Use: Bearer <token>"}), 401
        token = parts[1]
        try:
            payload = jwt.decode(token, SECRET, algorithms=[ALGORITHM])
            # optional: check token type, jti, nbf, iat, etc.
            request.user = payload.get("sub")
        except jwt.ExpiredSignatureError:
            return jsonify({"msg":"Token expired"}), 401
        except jwt.InvalidTokenError as e:
            return jsonify({"msg":"Invalid token", "error": str(e)}), 401
        return f(*args, **kwargs)
    return decorated

@app.route("/register", methods=["POST"])
def register():
    data = request.get_json() or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    if not username or not password:
        return jsonify({"msg":"username and password required"}), 400
    if username in USERS:
        return jsonify({"msg":"user already exists"}), 400
    # Basic input validation
    if len(password) < 8:
        return jsonify({"msg":"password must be at least 8 characters"}), 400
    pwd_hash = generate_password_hash(password)
    USERS[username] = {"password_hash": pwd_hash, "created_at": datetime.datetime.utcnow().isoformat()}
    return jsonify({"msg":"user registered"}), 201

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    if not username or not password:
        return jsonify({"msg":"username and password required"}), 400
    user = USERS.get(username)
    if not user or not check_password_hash(user["password_hash"], password):
        return jsonify({"msg":"invalid credentials"}), 401
    now = datetime.datetime.utcnow()
    exp = now + datetime.timedelta(minutes=ACCESS_EXPIRE_MINUTES)
    payload = {
        "sub": username,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "roles": ["user"]
    }
    token = jwt.encode(payload, SECRET, algorithm=ALGORITHM)
    return jsonify({"access_token": token, "token_type":"bearer", "expires_in": ACCESS_EXPIRE_MINUTES*60}), 200

@app.route("/profile", methods=["GET"])
@token_required
def profile():
    username = getattr(request, "user", None)
    if not username or username not in USERS:
        return jsonify({"msg":"user not found"}), 404
    # Return minimal profile
    return jsonify({"username": username, "created_at": USERS[username]["created_at"]}), 200

if __name__ == "__main__":
    # Only for demo/testing. Use gunicorn or similar in production.
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
