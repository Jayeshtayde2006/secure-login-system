# SecureGate — Python Version

A learning project built with Python, Flask, MySQL, and BCrypt.

## Features
- User registration and login
- BCrypt password hashing and checking
- Session-based authentication and protected dashboard
- Admin-only page listing users and recent login events
- Logs successful logins, failed logins, and logout events

## Requirements
Python 3.10+, MySQL Server, and MySQL Workbench.

## Setup (Windows PowerShell)
1. Extract this ZIP and open the extracted `SecureGate_Python` folder in VS Code.
2. Create a virtual environment:
   ```powershell
   py -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```
   If activation is blocked, use Command Prompt and `.venv\Scripts\activate.bat`.
3. Install packages:
   ```powershell
   python -m pip install --upgrade pip
   pip install -r requirements.txt
   ```
4. In MySQL Workbench, open `schema.sql` and execute it.
5. In the VS Code PowerShell terminal, set your own database password:
   ```powershell
   $env:DB_HOST="localhost"
   $env:DB_PORT="3306"
   $env:DB_USER="root"
   $env:DB_PASSWORD="YOUR_MYSQL_PASSWORD"
   $env:DB_NAME="secure_login_db"
   $env:SECRET_KEY="use-a-long-random-secret"
   $env:FLASK_DEBUG="true"
   ```
6. Start the app:
   ```powershell
   python app.py
   ```
7. Open http://127.0.0.1:5000 and register an account.

The app creates the tables on startup if the database connection works. `schema.sql` creates the database and tables too.

## Make one account an admin
Register an account first. Then run in MySQL Workbench:
```sql
USE secure_login_db;
UPDATE app_users SET role='ADMIN' WHERE username='your_username';
```
Log out and log in again.

## Display stored data
```sql
USE secure_login_db;
SELECT id, username, email, role, created_at FROM app_users;
SELECT id, username, event_type, event_time, ip_address FROM login_events ORDER BY id DESC;
```
Never store plain-text passwords or share password hashes.

## Security notes
This is a college/learning starter, not production-ready. For deployment, add CSRF protection, HTTPS, secure cookie settings, login rate limiting, a strong secret key, limited database permissions, and disable debug mode. Do not expose Flask's development server to the internet.
