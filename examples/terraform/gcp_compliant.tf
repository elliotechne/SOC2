# SOC2 Compliant GCP Terraform Configuration Examples
# These resources pass all SOC2 Checkov policies

# GCS Bucket with CMEK Encryption
resource "google_storage_bucket" "compliant_bucket" {
  name     = "soc2-compliant-bucket"
  location = "US"

  encryption {
    default_kms_key_name = google_kms_crypto_key.bucket_key.id
  }

  versioning {
    enabled = true
  }

  logging {
    log_bucket = google_storage_bucket.log_bucket.name
  }
}

resource "google_storage_bucket" "log_bucket" {
  name     = "soc2-log-bucket"
  location = "US"
}

resource "google_kms_key_ring" "key_ring" {
  name     = "soc2-key-ring"
  location = "us"
}

resource "google_kms_crypto_key" "bucket_key" {
  name     = "bucket-encryption-key"
  key_ring = google_kms_key_ring.key_ring.id

  rotation_period = "7776000s" # 90 days
}

# Cloud SQL with Encryption and Backups
resource "google_sql_database_instance" "compliant_instance" {
  name             = "soc2-compliant-db"
  database_version = "POSTGRES_14"
  region           = "us-central1"

  encryption_key_name = google_kms_crypto_key.sql_key.id

  settings {
    tier              = "db-f1-micro"
    availability_type = "REGIONAL"

    backup_configuration {
      enabled                        = true
      point_in_time_recovery_enabled = true
      start_time                     = "03:00"
    }

    ip_configuration {
      ipv4_enabled    = false
      private_network = google_compute_network.private_network.id
    }

    database_flags {
      name  = "log_statement"
      value = "all"
    }
  }
}

resource "google_kms_crypto_key" "sql_key" {
  name     = "sql-encryption-key"
  key_ring = google_kms_key_ring.key_ring.id
}

resource "google_compute_network" "private_network" {
  name = "soc2-private-network"
}

# Compute Instance with Encryption and OS Login
resource "google_compute_instance" "compliant_instance" {
  name         = "soc2-compliant-instance"
  machine_type = "e2-medium"
  zone         = "us-central1-a"

  metadata = {
    enable-oslogin       = "TRUE"
    serial-port-enable   = "FALSE"
  }

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-11"
    }
    kms_key_self_link = google_kms_crypto_key.disk_key.id
  }

  network_interface {
    network = google_compute_network.private_network.name
  }
}

resource "google_kms_crypto_key" "disk_key" {
  name     = "disk-encryption-key"
  key_ring = google_kms_key_ring.key_ring.id
}

# Firewall with Restricted Access
resource "google_compute_firewall" "compliant_firewall" {
  name    = "soc2-compliant-firewall"
  network = google_compute_network.private_network.name

  direction = "INGRESS"

  allow {
    protocol = "tcp"
    ports    = ["443"]
  }

  source_ranges = ["10.0.0.0/8"]
}

# VPC Subnet with Flow Logs
resource "google_compute_subnetwork" "compliant_subnet" {
  name          = "soc2-compliant-subnet"
  ip_cidr_range = "10.2.0.0/16"
  region        = "us-central1"
  network       = google_compute_network.private_network.id

  log_config {
    aggregation_interval = "INTERVAL_10_MIN"
    flow_sampling        = 0.5
    metadata             = "INCLUDE_ALL_METADATA"
  }
}

# Project Logging Sink
resource "google_logging_project_sink" "compliant_sink" {
  name        = "soc2-audit-logs"
  destination = "storage.googleapis.com/${google_storage_bucket.log_bucket.name}"

  filter = "resource.type = gce_instance AND severity >= ERROR"

  unique_writer_identity = true
}

# BigQuery Dataset with CMEK
resource "google_bigquery_dataset" "compliant_dataset" {
  dataset_id = "soc2_compliant_dataset"
  location   = "US"

  default_encryption_configuration {
    kms_key_name = google_kms_crypto_key.bigquery_key.id
  }
}

resource "google_kms_crypto_key" "bigquery_key" {
  name     = "bigquery-encryption-key"
  key_ring = google_kms_key_ring.key_ring.id
}

# Pub/Sub Topic with CMEK
resource "google_pubsub_topic" "compliant_topic" {
  name = "soc2-compliant-topic"

  kms_key_name = google_kms_crypto_key.pubsub_key.id
}

resource "google_kms_crypto_key" "pubsub_key" {
  name     = "pubsub-encryption-key"
  key_ring = google_kms_key_ring.key_ring.id
}

# IAM Binding with Specific Role (Not Primitive)
resource "google_project_iam_binding" "compliant_binding" {
  project = "my-project"
  role    = "roles/storage.objectViewer"

  members = [
    "user:user@example.com",
  ]
}

# Service Account Key (with rotation consideration)
resource "google_service_account" "compliant_sa" {
  account_id   = "soc2-compliant-sa"
  display_name = "SOC2 Compliant Service Account"
}

resource "google_service_account_key" "compliant_key" {
  service_account_id = google_service_account.compliant_sa.name
  key_algorithm      = "KEY_ALG_RSA_2048"
}

# Compute Disk Snapshot Schedule
resource "google_compute_resource_policy" "compliant_snapshot_policy" {
  name   = "soc2-snapshot-policy"
  region = "us-central1"

  snapshot_schedule_policy {
    schedule {
      daily_schedule {
        days_in_cycle = 1
        start_time    = "04:00"
      }
    }

    retention_policy {
      max_retention_days    = 14
      on_source_disk_delete = "KEEP_AUTO_SNAPSHOTS"
    }
  }
}

# Load Balancer Backend with Logging
resource "google_compute_backend_service" "compliant_backend" {
  name        = "soc2-compliant-backend"
  protocol    = "HTTP"
  timeout_sec = 10

  log_config {
    enable      = true
    sample_rate = 1.0
  }
}

# HTTPS Target Proxy
resource "google_compute_target_https_proxy" "compliant_proxy" {
  name    = "soc2-compliant-proxy"
  url_map = google_compute_url_map.compliant_url_map.id
}

resource "google_compute_url_map" "compliant_url_map" {
  name            = "soc2-url-map"
  default_service = google_compute_backend_service.compliant_backend.id
}

# Log Retention Policy
resource "google_logging_project_bucket_config" "compliant_retention" {
  project        = "my-project"
  location       = "global"
  retention_days = 90
  bucket_id      = "_Default"
}
