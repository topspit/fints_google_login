# Aktiviert die Cloud Resource Manager API
resource "google_project_service" "cloudresourcemanager" {
  project = "fints-web"
  service = "cloudresourcemanager.googleapis.com"
}

# Aktiviert Firestore API (falls nicht schon aktiviert)
resource "google_project_service" "firestore" {
  project = "fints-web"
  service = "firestore.googleapis.com"
}

resource "google_service_account" "firestore_sa" {
  account_id   = "firestore-service-account"
  display_name = "Firestore Service Account"
}

# Rollen zuweisen (Firestore + IAM Rechte)
resource "google_project_iam_member" "firestore_sa_roles" {
  for_each = toset([
    "roles/datastore.user",          # Zugriff auf Firestore
    "roles/iam.serviceAccountUser"   # Erlaubt Nutzung des Service-Accounts
  ])
  project = "fints-web"
  role    = each.value
  member  = "serviceAccount:${google_service_account.firestore_sa.email}"
}

# Service-Account-Schlüssel als JSON generieren
resource "google_service_account_key" "firestore_sa_key" {
  service_account_id = google_service_account.firestore_sa.name
}

# JSON Key in eine Datei speichern
resource "local_file" "service_account_key_file" {
  filename = "${path.module}/service-account.json"
  content  = base64decode(google_service_account_key.firestore_sa_key.private_key)
}

resource "google_firestore_database" "firestore" {
  project     = "fints-web"
  name        = "(default)"  # Standard-Datenbankname
  location_id = "europe-west3"  # Ändere dies nach Bedarf
  type        = "FIRESTORE_NATIVE"
  deletion_protection = false
}
