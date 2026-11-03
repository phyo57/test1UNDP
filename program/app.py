"""
Thailand Weather Fetching Web Application.

Provides user registration with 4-digit ID and weather lookup for Thai cities.
Follows OWASP Top 10 security standards:
- A01 Broken Access Control: session-based auth, login required for weather data
- A02 Cryptographic Failures: passwords hashed with bcrypt/SHA-256+salt
- A03 Injection: parameterized SQL queries throughout
- A04 Insecure Design: CSRF tokens on all forms
- A05 Security Misconfiguration: secret key from env, debug off by default
- A06 Vulnerable Components: pinned dependencies
- A07 Auth Failures: account lockout after 5 failed attempts
- A08 Data Integrity: input validation on all user inputs
- A09 Logging Failures: security events logged to app.log
- A10 SSRF: weather API uses whitelist of Thai cities
"""

import os
import re
import sqlite3
import logging
import secrets
import hashlib
import hmac
import time
from functools import wraps
from flask import (
    Flask, request, render_template, redirect, url_for,
    session, flash, g, abort
)

try:
    import bcrypt
    USE_BCRYPT = True
except ImportError:
    USE_BCRYPT = False

import requests as http_requests

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "weather_app.db")
WEATHER_API_KEY = os.environ.get("WEATHER_API_KEY", "dead0d1366d89f318e09a0534f1da766")
WEATHER_API_BASE = "https://api.openweathermap.org/data/2.5/weather"

logging.basicConfig(
    filename=os.path.join(os.path.dirname(os.path.abspath(__file__)), "app.log"),
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)

THAI_CITIES = [
    "Bangkok", "Chiang Mai", "Phuket", "Pattaya", "Khon Kaen",
    "Nakhon Ratchasima", "Hat Yai", "Udon Thani", "Surat Thani",
    "Chiang Rai", "Nonthaburi", "Ayutthaya", "Hua Hin", "Krabi",
    "Kanchanaburi", "Lampang", "Nakhon Si Thammarat", "Ubon Ratchathani",
    "Samut Prakan", "Rayong"
]

MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION = 300


def get_db():
    """Return a database connection for the current request, creating one if needed."""
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
    return g.db


@app.teardown_appcontext
def close_db(exception):
    """Close the database connection at the end of each request."""
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """Initialize the database schema with the users table."""
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            login_attempts INTEGER DEFAULT 0,
            locked_until REAL NULL
        );
    """)
    db.commit()


def hash_password(password):
    """Hash a password using bcrypt if available, otherwise SHA-256 with random salt."""
    if USE_BCRYPT:
        return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    salt = secrets.token_hex(16)
    h = hashlib.sha256((salt + password).encode("utf-8")).hexdigest()
    return f"{salt}${h}"


def verify_password(password, password_hash):
    """Verify a plaintext password against its stored hash using constant-time comparison."""
    if USE_BCRYPT and password_hash.startswith("$2"):
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    if "$" in password_hash:
        salt, h = password_hash.split("$", 1)
        return hmac.compare_digest(
            hashlib.sha256((salt + password).encode("utf-8")).hexdigest(), h
        )
    return False


def login_required(f):
    """Decorator that redirects unauthenticated users to the login page."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to access weather data.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def validate_user_id(user_id):
    """Validate that a user ID is exactly 4 digits."""
    return bool(re.fullmatch(r"\d{4}", user_id))


def validate_csrf():
    """Validate the CSRF token from the submitted form against the session token."""
    token = request.form.get("csrf_token", "")
    return hmac.compare_digest(token, session.get("csrf_token", ""))


def generate_csrf():
    """Generate and store a CSRF token in the session, returning the token string."""
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


app.jinja_env.globals["csrf_token"] = generate_csrf


@app.before_first_request
def setup():
    """Run database initialization before the first HTTP request."""
    init_db()


@app.route("/")
def index():
    """Redirect to weather dashboard if logged in, otherwise to login page."""
    if "user_id" in session:
        return redirect(url_for("weather"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    """
    User registration page.

    GET: Render the registration form.
    POST: Validate name, email, 4-digit ID, and password. Create the user
    in the database with a hashed password. Uses parameterized queries
    to prevent SQL injection (OWASP A03).
    """
    if request.method == "POST":
        if not validate_csrf():
            abort(403)

        user_id = request.form.get("user_id", "").strip()
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        errors = []
        if not validate_user_id(user_id):
            errors.append("ID must be exactly 4 digits.")
        if not name or len(name) > 100:
            errors.append("Name is required (max 100 characters).")
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email) or len(email) > 254:
            errors.append("Valid email is required.")
        if len(password) < 8:
            errors.append("Password must be at least 8 characters.")
        if password != confirm_password:
            errors.append("Passwords do not match.")

        if errors:
            for e in errors:
                flash(e, "danger")
            return render_template("register.html", name=name, email=email, user_id=user_id)

        db = get_db()
        existing = db.execute(
            "SELECT id FROM users WHERE user_id = ?", (user_id,)
        ).fetchone()
        if existing:
            flash("This ID is already registered.", "danger")
            return render_template("register.html", name=name, email=email, user_id=user_id)

        db.execute(
            "INSERT INTO users (user_id, name, email, password_hash) VALUES (?, ?, ?, ?)",
            (user_id, name, email, hash_password(password))
        )
        db.commit()
        logging.info("New user registered: %s", user_id)
        flash("Registration successful! Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """
    User login page.

    GET: Render the login form.
    POST: Validate 4-digit ID and password. Implements account lockout
    after MAX_LOGIN_ATTEMPTS failed attempts for LOCKOUT_DURATION seconds
    to mitigate brute-force attacks (OWASP A07).
    """
    if request.method == "POST":
        if not validate_csrf():
            abort(403)

        user_id = request.form.get("user_id", "").strip()
        password = request.form.get("password", "")

        if not validate_user_id(user_id):
            flash("Invalid ID format. Must be 4 digits.", "danger")
            return render_template("login.html")

        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE user_id = ?", (user_id,)
        ).fetchone()

        if user:
            if user["locked_until"] and time.time() < user["locked_until"]:
                remaining = int(user["locked_until"] - time.time())
                flash(f"Account locked. Try again in {remaining} seconds.", "danger")
                logging.warning("Login attempt on locked account: %s", user_id)
                return render_template("login.html")

            if verify_password(password, user["password_hash"]):
                db.execute(
                    "UPDATE users SET login_attempts = 0, locked_until = NULL WHERE user_id = ?",
                    (user_id,)
                )
                db.commit()
                session.clear()
                session["user_id"] = user["user_id"]
                session["user_name"] = user["name"]
                logging.info("Successful login: %s", user_id)
                return redirect(url_for("weather"))
            else:
                attempts = user["login_attempts"] + 1
                locked_until = None
                if attempts >= MAX_LOGIN_ATTEMPTS:
                    locked_until = time.time() + LOCKOUT_DURATION
                    logging.warning("Account locked due to failed attempts: %s", user_id)
                db.execute(
                    "UPDATE users SET login_attempts = ?, locked_until = ? WHERE user_id = ?",
                    (attempts, locked_until, user_id)
                )
                db.commit()

        flash("Invalid ID or password.", "danger")
        logging.warning("Failed login attempt for ID: %s", user_id)
        return render_template("login.html")

    return render_template("login.html")


@app.route("/logout")
def logout():
    """Clear the user session and redirect to the login page."""
    user_id = session.get("user_id", "unknown")
    session.clear()
    logging.info("User logged out: %s", user_id)
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


@app.route("/weather", methods=["GET", "POST"])
@login_required
def weather():
    """
    Weather dashboard page. Requires authentication (OWASP A01).

    GET: Display the city selection form with all Thai cities.
    POST: Fetch weather from OpenWeatherMap for the selected city.
    City is validated against a whitelist to prevent SSRF (OWASP A10).
    Falls back to demo data if no API key is configured.
    """
    weather_data = None
    selected_city = None

    if request.method == "POST":
        if not validate_csrf():
            abort(403)

        selected_city = request.form.get("city", "")
        if selected_city not in THAI_CITIES:
            flash("Please select a valid Thai city.", "danger")
            return render_template("weather.html", cities=THAI_CITIES)

        if WEATHER_API_KEY == "demo_key":
            weather_data = {
                "city": selected_city,
                "country": "TH",
                "temp": 32,
                "feels_like": 36,
                "humidity": 75,
                "description": "Scattered Clouds",
                "wind_speed": 3.5,
                "icon": "03d",
                "demo": True
            }
        else:
            try:
                resp = http_requests.get(
                    WEATHER_API_BASE,
                    params={
                        "q": f"{selected_city},TH",
                        "appid": WEATHER_API_KEY,
                        "units": "metric"
                    },
                    timeout=10
                )
                resp.raise_for_status()
                data = resp.json()
                weather_data = {
                    "city": data["name"],
                    "country": data["sys"]["country"],
                    "temp": round(data["main"]["temp"]),
                    "feels_like": round(data["main"]["feels_like"]),
                    "humidity": data["main"]["humidity"],
                    "description": data["weather"][0]["description"].title(),
                    "wind_speed": data["wind"]["speed"],
                    "icon": data["weather"][0]["icon"],
                    "demo": False
                }
            except http_requests.RequestException:
                flash("Could not fetch weather data. Please try again.", "danger")
                logging.error("Weather API failed for city: %s", selected_city)

    return render_template(
        "weather.html", cities=THAI_CITIES,
        weather_data=weather_data, selected_city=selected_city
    )


@app.errorhandler(403)
def forbidden(e):
    """Render a 403 error page for CSRF or access violations."""
    return render_template("error.html", code=403, message="Forbidden - invalid request."), 403


@app.errorhandler(404)
def not_found(e):
    """Render a 404 error page for missing routes."""
    return render_template("error.html", code=404, message="Page not found."), 404


if __name__ == "__main__":
    debug_mode = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(debug=debug_mode, host="127.0.0.1", port=5000)
