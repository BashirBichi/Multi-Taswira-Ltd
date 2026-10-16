"""Multi Taswira secure admin and inquiry backend. Run behind HTTPS."""
import os
import secrets
import sqlite3
from datetime import timedelta
from functools import wraps
from pathlib import Path

from flask import Flask, abort, flash, redirect, render_template_string, request, session, url_for
from flask_login import LoginManager, UserMixin, current_user, login_required, login_user, logout_user
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
secret = os.environ.get("SECRET_KEY")
if not secret or len(secret) < 32:
    raise RuntimeError("Set a random SECRET_KEY environment variable (32+ characters).")
app.config.update(SECRET_KEY=secret, SESSION_COOKIE_HTTPONLY=True,
                  SESSION_COOKIE_SAMESITE="Lax",
                  SESSION_COOKIE_SECURE=os.getenv("COOKIE_SECURE", "true").lower() == "true",
                  PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
                  MAX_CONTENT_LENGTH=64 * 1024)
DB = os.getenv("DATABASE_PATH", "/var/data/responses.db")
login_manager = LoginManager(app)
login_manager.login_view = "login"


def db():
    Path(DB).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB, timeout=15)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with db() as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS responses
                     (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
                      email TEXT NOT NULL, subject TEXT NOT NULL, message TEXT NOT NULL,
                      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)""")
        conn.execute("""CREATE TABLE IF NOT EXISTS admins
                     (company_id TEXT PRIMARY KEY, password TEXT NOT NULL)""")
        admin_id = os.environ.get("ADMIN_ID")
        admin_password = os.environ.get("ADMIN_PASSWORD")
        if admin_id and admin_password:
            if len(admin_password) < 14:
                raise RuntimeError("ADMIN_PASSWORD must be at least 14 characters.")
            conn.execute("INSERT OR IGNORE INTO admins(company_id,password) VALUES(?,?)",
                         (admin_id, generate_password_hash(admin_password)))


class Admin(UserMixin):
    def __init__(self, company_id):
        self.id = company_id


@login_manager.user_loader
def load_user(company_id):
    with db() as conn:
        row = conn.execute("SELECT company_id FROM admins WHERE company_id=?", (company_id,)).fetchone()
    return Admin(row["company_id"]) if row else None


def csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


def require_csrf():
    token = request.form.get("csrf_token", "")
    if not secrets.compare_digest(token, session.get("csrf_token", "")) or not token:
        abort(400, "Invalid form token.")


BASE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{ title }} | Multi Taswira</title>
<style>
:root{font-family:system-ui,Arial,sans-serif;color:#17212a;background:#f4f6f8}
*{box-sizing:border-box}body{margin:0}header{background:#17212a;color:#fff;padding:20px}
header .bar{max-width:1120px;margin:auto;display:flex;justify-content:space-between;align-items:center;gap:15px;flex-wrap:wrap}
header a{color:white}main{max-width:1120px;margin:45px auto;padding:0 18px}
h1{font-size:clamp(1.6rem,4vw,2.5rem)}.panel{background:#fff;padding:28px;border:1px solid #e0e5e9;border-radius:14px;box-shadow:0 10px 28px #17212a0a}
label{display:block;font-weight:650;margin:16px 0 7px}input,textarea{width:100%;padding:13px;border:1px solid #b8c3cb;border-radius:8px;font:inherit}
button,.btn{display:inline-block;border:0;background:#cc2200;color:white;padding:12px 18px;border-radius:8px;font-weight:700;cursor:pointer;text-decoration:none}
button:hover,.btn:hover{background:#a61b00}.muted{color:#66747f}.alert{padding:12px;background:#eaf6f9;border-left:4px solid #00aadd;margin:15px 0}
.table-wrap{overflow-x:auto}table{width:100%;border-collapse:collapse;background:#fff}th,td{text-align:left;border-bottom:1px solid #e0e5e9;padding:14px;vertical-align:top;overflow-wrap:anywhere}th{background:#eaf0f3}
td.message{min-width:210px;max-width:380px;white-space:pre-wrap}.danger{background:#8e1a10}
.login{max-width:450px;margin:75px auto}a:focus-visible,button:focus-visible,input:focus-visible{outline:3px solid #00aadd;outline-offset:2px}
</style></head><body><header><div class="bar"><strong>MULTI TASWIRA · ADMIN</strong><nav>
{% if current_user.is_authenticated %}<a href="{{ url_for('admin') }}">Dashboard</a>
<form style="display:inline;margin-left:18px" method="post" action="{{ url_for('logout') }}"><input type="hidden" name="csrf_token" value="{{ csrf }}"><button type="submit">Log out</button></form>
{% else %}<a href="{{ url_for('login') }}">Sign in</a>{% endif %}
</nav></div></header><main>
{% for msg in get_flashed_messages() %}<div class="alert" role="status">{{ msg }}</div>{% endfor %}
{{ body|safe }}</main></body></html>"""


def render(body, title, **kwargs):
    from flask import render_template_string as r
    # Body is trusted, constant application template markup.
    inner = r(body, csrf=csrf_token(), **kwargs)
    return render_template_string(BASE, title=title, body=inner, csrf=csrf_token())


@app.after_request
def headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.route("/")
def home():
    return redirect(url_for("login"))


@app.route("/health")
def health():
    return {"status": "ok"}


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("admin"))
    if request.method == "POST":
        require_csrf()
        admin_id = request.form.get("company_id", "").strip()[:120]
        password = request.form.get("password", "")
        with db() as conn:
            row = conn.execute("SELECT company_id,password FROM admins WHERE company_id=?", (admin_id,)).fetchone()
        if row and check_password_hash(row["password"], password):
            session.clear()
            login_user(Admin(row["company_id"]), remember=False)
            session.permanent = True
            return redirect(url_for("admin"))
        flash("Invalid administrator credentials.")
    return render("""<div class="panel login"><h1>Administrator sign in</h1><p class="muted">Authorized personnel only.</p>
    <form method="post"><input type="hidden" name="csrf_token" value="{{ csrf }}">
    <label for="company_id">Administrator ID</label><input id="company_id" name="company_id" autocomplete="username" required>
    <label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password" required>
    <p><button type="submit">Sign in securely →</button></p></form></div>""", "Sign in")


@app.route("/admin", methods=["GET", "POST"])
@login_required
def admin():
    if request.method == "POST":
        require_csrf()
        try:
            response_id = int(request.form.get("id", ""))
        except ValueError:
            abort(400)
        with db() as conn:
            conn.execute("DELETE FROM responses WHERE id=?", (response_id,))
        flash("Inquiry deleted.")
        return redirect(url_for("admin"))
    with db() as conn:
        rows = conn.execute("SELECT id,name,email,subject,message,timestamp FROM responses ORDER BY id DESC LIMIT 500").fetchall()
        total = conn.execute("SELECT COUNT(*) FROM responses").fetchone()[0]
    return render("""<h1>Inquiry dashboard</h1><p class="muted">Welcome, {{ admin_id }}. Showing the latest {{ rows|length }} of {{ total }} inquiries.</p>
    <div class="panel"><div class="table-wrap"><table><thead><tr><th>Date</th><th>Name</th><th>Email</th><th>Subject</th><th>Message</th><th>Action</th></tr></thead><tbody>
    {% for row in rows %}<tr><td>{{ row['timestamp'] }}</td><td>{{ row['name'] }}</td>
    <td><a href="mailto:{{ row['email']|urlencode }}">{{ row['email'] }}</a></td>
    <td>{{ row['subject'] }}</td><td class="message">{{ row['message'] }}</td>
    <td><form method="post" onsubmit="return confirm('Delete this inquiry permanently?')">
    <input type="hidden" name="csrf_token" value="{{ csrf }}"><input type="hidden" name="id" value="{{ row['id'] }}">
    <button class="danger" type="submit">Delete</button></form></td></tr>
    {% else %}<tr><td colspan="6">No inquiries yet.</td></tr>{% endfor %}
    </tbody></table></div></div>""", "Dashboard", rows=rows, total=total, admin_id=current_user.id)


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    require_csrf()
    logout_user()
    session.clear()
    return redirect(url_for("login"))


@app.route("/contact", methods=["POST"])
def contact():
    # Contact API is intentionally not exposed cross-origin until a verified,
    # rate-limited submission integration is configured.
    abort(404)


@app.route("/reset_password")
def reset_password():
    abort(404)  # Never allow unauthenticated password resets.


init_db()

if __name__ == "__main__":
    app.run(debug=False)
