import os
from functools import wraps
import bcrypt
import mysql.connector
from mysql.connector import Error
from flask import Flask, flash, redirect, render_template, request, session, url_for

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "change-this-development-secret-key")

def get_db():
    return mysql.connector.connect(
        host=os.getenv("DB_HOST", "localhost"),
        port=int(os.getenv("DB_PORT", "3306")),
        user=os.getenv("DB_USER", "root"),
        password=os.getenv("DB_PASSWORD", ""),
        database=os.getenv("DB_NAME", "secure_login_db"),
    )

def init_db():
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("""CREATE TABLE IF NOT EXISTS app_users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(80) NOT NULL UNIQUE,
            email VARCHAR(150) NOT NULL UNIQUE,
            password_hash VARCHAR(255) NOT NULL,
            role VARCHAR(20) NOT NULL DEFAULT 'USER',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""")
        cur.execute("""CREATE TABLE IF NOT EXISTS login_events (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NULL,
            username VARCHAR(80) NOT NULL,
            event_type VARCHAR(30) NOT NULL,
            event_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            ip_address VARCHAR(45) NULL,
            CONSTRAINT fk_login_event_user FOREIGN KEY (user_id)
                REFERENCES app_users(id) ON DELETE SET NULL
        )""")
        conn.commit()
        cur.close()
    finally:
        conn.close()

def log_event(user_id, username, event_type):
    conn = None
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO login_events (user_id, username, event_type, ip_address) VALUES (%s,%s,%s,%s)",
            (user_id, username, event_type, request.remote_addr)
        )
        conn.commit()
        cur.close()
    except Error:
        app.logger.exception("Could not record login event")
    finally:
        if conn and conn.is_connected():
            conn.close()

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to continue.", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped

def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in first.", "warning")
            return redirect(url_for("login"))
        if session.get("role") != "ADMIN":
            flash("You do not have permission to open the admin page.", "danger")
            return redirect(url_for("dashboard"))
        return view(*args, **kwargs)
    return wrapped

@app.route("/")
def index():
    return redirect(url_for("dashboard" if "user_id" in session else "login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if not username or not email or not password:
            flash("Please fill in all fields.", "danger")
            return render_template("register.html")
        if len(password) < 8:
            flash("Password must be at least 8 characters long.", "danger")
            return render_template("register.html")
        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        conn = get_db()
        try:
            cur = conn.cursor()
            cur.execute("INSERT INTO app_users (username,email,password_hash,role) VALUES (%s,%s,%s,'USER')",
                        (username, email, hashed))
            conn.commit()
            flash("Registration successful. You can now log in.", "success")
            return redirect(url_for("login"))
        except mysql.connector.IntegrityError:
            flash("That username or email is already registered.", "danger")
        except Error:
            app.logger.exception("Registration failed")
            flash("Database error. Check your MySQL settings.", "danger")
        finally:
            conn.close()
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        conn = get_db()
        try:
            cur = conn.cursor(dictionary=True)
            cur.execute("SELECT id,username,email,password_hash,role FROM app_users WHERE username=%s", (username,))
            user = cur.fetchone()
            cur.close()
        except Error:
            app.logger.exception("Login database lookup failed")
            flash("Could not connect to the database. Check configuration.", "danger")
            return render_template("login.html")
        finally:
            conn.close()
        if user and bcrypt.checkpw(password.encode(), user["password_hash"].encode()):
            session.clear()
            session.update(user_id=user["id"], username=user["username"], email=user["email"], role=user["role"])
            log_event(user["id"], user["username"], "LOGIN_SUCCESS")
            flash("Welcome back!", "success")
            return redirect(url_for("dashboard"))
        log_event(user["id"] if user else None, username or "(empty)", "LOGIN_FAILED")
        flash("Invalid username or password.", "danger")
    return render_template("login.html")

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")

@app.route("/admin")
@admin_required
def admin():
    conn = get_db()
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT id,username,email,role,created_at FROM app_users ORDER BY id DESC")
        users = cur.fetchall()
        cur.execute("SELECT id,username,event_type,event_time,ip_address FROM login_events ORDER BY id DESC LIMIT 100")
        events = cur.fetchall()
        cur.close()
    finally:
        conn.close()
    return render_template("admin.html", users=users, events=events)

@app.route("/logout", methods=["POST"])
@login_required
def logout():
    log_event(session.get("user_id"), session.get("username", "unknown"), "LOGOUT")
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))

if __name__ == "__main__":
    try:
        init_db()
        print("SecureGate tables are ready.")
    except Error as exc:
        print("Could not initialize MySQL:", exc)
        print("Check MySQL is running and DB environment variables are set.")
    app.run(debug=os.getenv("FLASK_DEBUG", "false").lower() == "true")
