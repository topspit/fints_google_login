import os
import flask
from flask import Flask, redirect, request, url_for, render_template
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user, logout_user
from google.auth.transport.requests import Request
from google.auth import jwt
import google.auth

# Flask-Setup
app = Flask(__name__)
app.config.from_object('config')
login_manager = LoginManager(app)
login_manager.login_view = "index"

# Dummy User Klasse
class User(UserMixin):
    def __init__(self, id):
        self.id = id

# Dummy-Datenbank, wo Benutzerinformationen gespeichert werden
users = {}

# Routen
@app.route('/')
def index():
    # Login-Seite mit Google
    return render_template("index.html")

@app.route('/login/callback')
def login_callback():
    # Google Token verifizieren und Benutzer authentifizieren
    token = request.args.get("token")
    try:
        credentials = google.auth.credentials.Credentials.from_authorized_user_info(token)
    except Exception as e:
        return f"Error during login: {str(e)}", 500

    user = User(id=token)
    users[token] = user
    login_user(user)
    return redirect(url_for('dashboard'))

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    # Einfache Addition von zwei Zahlen
    result = None
    if request.method == 'POST':
        try:
            num1 = float(request.form['num1'])
            num2 = float(request.form['num2'])
            result = num1 + num2
        except ValueError:
            result = "Ungültige Eingabe"
    return render_template('dashboard.html', result=result)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# User-Loader
@login_manager.user_loader
def load_user(user_id):
    return users.get(user_id)

if __name__ == '__main__':
    app.run(debug=True)