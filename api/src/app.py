import os
import time
import bcrypt
from dotenv import load_dotenv

load_dotenv()

from flask import Flask, request, jsonify
from flask_migrate import Migrate
from models import Users, db
from flask_cors import CORS
from sqlalchemy import or_
from flask_jwt_extended import (
    create_access_token,
    get_csrf_token,
    jwt_required,
    JWTManager,
    set_access_cookies,
    unset_jwt_cookies,
)

load_dotenv()
app = Flask(__name__)
start_time = time.time()

db_url = os.getenv("DATABASE_URL")

if db_url is not None:
    app.config["SQLALCHEMY_DATABASE_URI"] = db_url
else:
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:////tmp/test.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

jwt_key = os.getenv("JWT_SECRET_KEY") or "akjflsdj"

print(db_url)
# JWT
app.config["JWT_SECRET_KEY"] = jwt_key
app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
app.config["JWT_COOKIE_CSRF_PROTECT"] = True
app.config["JWT_CSRF_IN_COOKIES"] = True
app.config["JWT_COOKIE_SECURE"] = True

jwt = JWTManager(app)

MIGRATE = Migrate(app, db)
db.init_app(app)
app.config["CORS_HEADERS"] = "Content-Type"
CORS(app, supports_credentials=True)


@app.route("/health", methods=["GET"])
def health_check():
    users = Users.query.all()
    print(users)
    return jsonify({"status": "ok", "uptime": round(time.time() - start_time, 2)}), 200


@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    user_name = data.get("user_name")
    email = data.get("email")
    password = data.get("password")

    required_fields = ["user_name", "email", "password"]

    if not all(field in data for field in required_fields):
        return jsonify({"error": "Missing required fields"}), 400

    existing_user = (
        db.session.query(Users)
        .filter(or_(Users.user_name == user_name, Users.email == email))
        .first()
    )
    if existing_user:
        return jsonify({"error": "Username or Email already registered"}), 400

    hashedPassword = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode(
        "utf-8"
    )

    new_user = Users(user_name=user_name, email=email, password=hashedPassword)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "User registered successfully"}), 201


@app.route("/login", methods=["POST"])
def get_login():
    data = request.get_json()

    email = data["email"]
    password = data["password"]

    required_fields = ["email", "password"]
    if not all(field in data for field in required_fields):
        return jsonify({"error": "Missing required fields"}), 400

    user = Users.query.filter_by(email=email).first()

    if not user:
        return jsonify({"error": "User not found"}), 400

    is_password_valid = bcrypt.checkpw(
        password.encode("utf-8"), user.password.encode("utf-8")
    )

    if not is_password_valid:
        return jsonify({"error": "Password not correct"}), 400

    access_token = create_access_token(identity=str(user.id))
    csrf_token = get_csrf_token(access_token)
    response = jsonify(
        {"msg": "login successful", "user": user, "csrf_token": csrf_token}
    )
    set_access_cookies(response, access_token)

    return response


@app.route("/logout", methods=["POST"])
@jwt_required()
def logout_with_cookies():
    response = jsonify({"msg": "logout successful"})
    unset_jwt_cookies(response)
    return response


if __name__ == "__main__":
    PORT = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=PORT, debug=False)
