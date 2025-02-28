import os
import pathlib
import requests
from flask import Flask, session, redirect, request, render_template, abort, jsonify
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests
from functools import wraps
from decrypt_sub import decrypt_file

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Geheime Session-Key

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"  # Lokale HTTP-Entwicklung erlauben

encrypted_file = "client_secret.json.enc"
decrypted_file = "client_secret.json"
password = os.getenv('DECRYPTION_PASSWORD')
# Entschlüsselung der Datei direkt beim Start der Anwendung
decrypt_file(encrypted_file, decrypted_file, password)
print("Datei erfolgreich entschlüsselt")

# Google OAuth Konfiguration
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, decrypted_file)



# OAuth 2.0 Flow einrichten
flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri="http://localhost:5000/login/callback"
)

# Löschen der Datei nach erfolgreichem Einlesen
if os.path.exists(decrypted_file):
    os.remove(decrypted_file)
    print(f"{decrypted_file} wurde erfolgreich gelöscht.")
else:
    print(f"{decrypted_file} existiert nicht.")

# Login-Required Decorator
def login_required(f):
    @wraps(f)  # Bewahrt den Namen und die Metadaten der Originalfunktion
    def decorated_function(*args, **kwargs):
        if "google_id" not in session:
            return redirect("/")  # Falls nicht eingeloggt, zurück zur Startseite
        return f(*args, **kwargs)
    return decorated_function



@app.route("/")
def index():
    return render_template("index.html")

@app.route("/login")
def login():
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)

@app.route("/login/callback")
def callback():
    
    flow.fetch_token(authorization_response=request.url)

    if not session["state"] == request.args["state"]:
        abort(500)  # Falls State nicht passt

    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=flow.client_config["client_id"]
    )

    session["google_id"] = id_info.get("sub")
    session["name"] = id_info.get("name")
    return redirect("/dashboard")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", name=session["name"])

@app.route("/add", methods=["POST"])
@login_required
def add_numbers():
    data = request.get_json()
    result = data["num1"] + data["num2"]
    return jsonify({"result": result})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
