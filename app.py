from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

DATABASE = 'responses.db'


# Database Initialization
def init_db():
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        # Create responses table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS responses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL,
                subject TEXT NOT NULL,
                message TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        # Create admins table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS admins (
                company_id TEXT PRIMARY KEY,
                password TEXT NOT NULL
            )
        ''')
        # Insert default admin accounts
        default_password = generate_password_hash('default123')
        companies = [
            ('COMPANY001', default_password),
            ('COMPANY002', default_password),
            ('COMPANY003', default_password)
        ]
        for company_id, password in companies:
            try:
                cursor.execute(
                    "INSERT INTO admins (company_id, password) VALUES (?, ?)",
                    (company_id, password)
                )
            except sqlite3.IntegrityError:
                pass  # Skip if company ID exists


# Admin Class for Login
class Admin(UserMixin):
    def __init__(self, company_id):
        self.company_id = company_id

    def get_id(self):
        return self.company_id


@login_manager.user_loader
def load_user(company_id):
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM admins WHERE company_id=?", (company_id,))
        result = cursor.fetchone()
        if result:
            return Admin(company_id=result[0])
    return None


# Routes
@app.route('/')
def home():
    return redirect(url_for('contact'))


@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        subject = request.form['subject']
        message = request.form['message']

        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO responses (name, email, subject, message) VALUES (?, ?, ?, ?)",
                (name, email, subject, message)
            )
            conn.commit()

        return "Thank you for your message! We'll get back to you shortly."

    return render_template('contact_us.html')


@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    if request.method == 'POST':
        response_id = request.form.get('id')
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM responses WHERE id=?", (response_id,))
            conn.commit()

    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, name, email, subject, message, timestamp FROM responses")
        responses = cursor.fetchall()

    return render_template('admin.html', responses=responses)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        company_id = request.form['company_id']
        password = request.form['password']

        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM admins WHERE company_id=?", (company_id,))
            admin = cursor.fetchone()

            if admin and check_password_hash(admin[1], password):
                user = Admin(company_id=admin[0])
                login_user(user)
                return redirect(url_for('admin'))
            else:
                return "Invalid login credentials. Please try again."

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        company_id = request.form['company_id']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if new_password != confirm_password:
            return "Passwords do not match. Please try again."

        hashed_password = generate_password_hash(new_password)

        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE admins SET password=? WHERE company_id=?",
                (hashed_password, company_id)
            )
            conn.commit()

        return "Password successfully updated. Please log in with your new password."

    return render_template('reset_password.html')


if __name__ == '__main__':
    init_db()
    app.run(debug=True)
