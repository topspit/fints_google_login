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
from fints.client import FinTS3PinTanClient, NeedTANResponse

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

#FINTSClient-Product-ID
product_id = "36792786FA12F235F04647689"


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

# Simulierter Google Key Store (später durch echten ersetzen)
mock_google_key_store = {}

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
    session["email"] = id_info.get("email") # speicherung eMail
    print(session["email"])
    return redirect("/dashboard")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

# Simulierter Google Key Store (nur für den Test)
mock_google_key_store = {}

@app.route("/dashboard")
@login_required
def dashboard():
    email = session.get("email")
    if not email:
        return redirect("/")

    # Simulierte Abfrage im Google Key Store
    if email in mock_google_key_store:
       # fints_data = mock_google_key_store[email]  # Falls Daten existieren
       # fints_client = FinTSClient(fints_data["bank_identifier"], fints_data["user_id"], fints_data["pin"])
       # accounts = fints_client.get_accounts()
       # balances = {acc.iban: fints_client.get_balance(acc) for acc in accounts}
        print(f"email ist in mock?")
        return render_template("dashboard.html", name=session["name"])
    
    # Falls keine Daten existieren -> FINTS Login Maske anzeigen
    print(f"email ist NICHT in mock?")
    return redirect("/fints_login")

@app.route("/fints_login", methods=["GET", "POST"])
@login_required
def fints_login():
    if request.method == "POST":
        print(f"sind wohl im fint_login_post")
        bank_identifier = request.form["bank_identifier"]
        user_id = request.form["user_id"]
        pin = request.form["pin"]
        server = request.form["server"]

        # FINTS Login testen
        f = FinTS3PinTanClient(
            bank_identifier=bank_identifier,
            user_id=user_id,
            pin=pin,
            server=server,
            product_id=product_id
        )
        with f:
            # Falls eine TAN nötig ist
            if f.init_tan_response:
                return render_template("tan.html", challenge=f.init_tan_response.challenge)

            # Konten abrufen
            accounts = f.get_sepa_accounts()
            if not accounts:
                return "Keine Konten gefunden.", 400
            
            # Ersten Kontosaldo abrufen
            saldo = f.get_balance(accounts[0])
            print(saldo.amount)
            print(accounts[0].iban)
            print(f"sind wohl im fint_login_post")

        print(f"sind vor return dashboard.html") 
        return render_template("dashboard.html", konto=accounts[0].iban, saldo=saldo.amount)

        

    return render_template("fints_login.html")



if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
