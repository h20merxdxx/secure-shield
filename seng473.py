from flask import Flask, request, jsonify
from flask_bcrypt import Bcrypt
import jwt
import json
import os
import logging
from datetime import datetime, timedelta, timezone
from functools import wraps

app = Flask(__name__)
bcrypt = Bcrypt(app)

SECRET_KEY = "supersecretkey_secureshield_2025"
DB_FILE = "users.json"
BLACKLIST = set()

# ─── Logging Setup (Task 6) ───────────────────────────────────────────────────
logging.basicConfig(
    filename="security.log",
    level=logging.WARNING,
    format="%(asctime)s - %(message)s"
)

def log_unauthorized(action):
    logging.warning(f"UNAUTHORIZED attempt: {action}")

# ─── Simple JSON "Database" ───────────────────────────────────────────────────
def load_users():
    if not os.path.exists(DB_FILE):
        return {}
    with open(DB_FILE, "r") as f:
        return json.load(f)

def save_users(users):
    with open(DB_FILE, "w") as f:
        json.dump(users, f, indent=2)

# ─── JWT Middleware Decorator (Task 3) ────────────────────────────────────────
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            log_unauthorized(f"Missing token on {request.path}")
            return jsonify({"error": "Token missing"}), 401

        token = auth_header.split(" ")[1]

        if token in BLACKLIST:
            log_unauthorized(f"Blacklisted token used on {request.path}")
            return jsonify({"error": "Token has been revoked (logged out)"}), 401

        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            log_unauthorized(f"Invalid/tampered token on {request.path}")
            return jsonify({"error": "Invalid token"}), 401

        request.current_user = payload
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.current_user.get("role") != "admin":
            log_unauthorized(
                f"User '{request.current_user.get('username')}' tried to access admin route {request.path}"
            )
            return jsonify({"error": "Forbidden: Admins only"}), 403
        return f(*args, **kwargs)
    return decorated

# ─── Task 1: Register ─────────────────────────────────────────────────────────
@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    role = data.get("role", "user")  # default role: user

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    users = load_users()
    if username in users:
        return jsonify({"error": "User already exists"}), 409

    hashed_pw = bcrypt.generate_password_hash(password).decode("utf-8")
    users[username] = {"password": hashed_pw, "role": role}
    save_users(users)

    return jsonify({"message": f"User '{username}' registered successfully with role '{role}'"}), 201

# ─── Task 2: Login / JWT Issuance ────────────────────────────────────────────
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    users = load_users()
    user = users.get(username)

    if not user or not bcrypt.check_password_hash(user["password"], password):
        return jsonify({"error": "Invalid credentials"}), 401

    payload = {
        "username": username,
        "role": user["role"],
        "exp": datetime.now(timezone.utc) + timedelta(hours=1)
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    return jsonify({"token": token, "role": user["role"]}), 200

# ─── Task 5: Logout / Token Blacklist ────────────────────────────────────────
@app.route("/logout", methods=["POST"])
@token_required
def logout():
    token = request.headers.get("Authorization").split(" ")[1]
    BLACKLIST.add(token)
    return jsonify({"message": "Logged out successfully. Token revoked."}), 200

# ─── Task 4: Protected Routes ─────────────────────────────────────────────────
@app.route("/profile", methods=["GET"])
@token_required
def profile():
    user = request.current_user
    return jsonify({
        "message": f"Welcome, {user['username']}!",
        "role": user["role"]
    }), 200

@app.route("/user/<int:user_id>", methods=["DELETE"])
@token_required
@admin_required
def delete_user(user_id):
    users = load_users()
    usernames = list(users.keys())
    if user_id < 1 or user_id > len(usernames):
        return jsonify({"error": "User not found"}), 404
    deleted = usernames[user_id - 1]
    del users[deleted]
    save_users(users)
    return jsonify({"message": f"User '{deleted}' deleted by admin."}), 200

if __name__ == "__main__":
    app.run(debug=True)
