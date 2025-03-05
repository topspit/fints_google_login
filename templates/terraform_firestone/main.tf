# Google Cloud Provider
provider "google" {
  credentials = file("your-service-account-file.json")  # Dein Service-Account
  project     = "fints-web"
  region      = "europe-west3"
}

# Firestore API aktivieren
resource "google_project_service" "firestore" {
  project = "fints-web"
  service = "firestore.googleapis.com"
}

# Firestore-Datenbank erstellen (Native Mode)
resource "google_firestore_database" "default" {
  project     = "fints-web"
  name        = "(default)"  # "(default)" ist Pflicht für Firestore
  location_id = "europe-west3"  # Setze deine Region
  type        = "FIRESTORE_NATIVE"
}

# Firestore Sicherheitsregeln setzen (optional)
resource "google_firestore_ruleset" "firestore_rules" {
  project = "fints-web"

  source {
    files {
      name    = "firestore.rules"
      content = <<EOT
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    
    // Authentifizierte Nutzer können auf ihre eigenen Daten zugreifen
    match /fints_logins/{email} {
      allow read, write: if request.auth.token.email == email;
    }
  }
}
EOT
    }
  }
}
