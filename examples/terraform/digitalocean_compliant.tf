# SOC2 Compliant DigitalOcean Terraform Configuration Examples
# These resources pass all SOC2 Checkov policies

# Droplet with SSH Keys and Backups
resource "digitalocean_droplet" "compliant_droplet" {
  image              = "ubuntu-22-04-x64"
  name               = "soc2-compliant-droplet"
  region             = "nyc3"
  size               = "s-1vcpu-1gb"
  backups            = true
  private_networking = true
  vpc_uuid           = digitalocean_vpc.compliant_vpc.id

  ssh_keys = [
    digitalocean_ssh_key.compliant_key.id
  ]
}

resource "digitalocean_ssh_key" "compliant_key" {
  name       = "SOC2 SSH Key"
  public_key = file("~/.ssh/id_rsa.pub")
}

# VPC Configuration
resource "digitalocean_vpc" "compliant_vpc" {
  name     = "soc2-compliant-vpc"
  region   = "nyc3"
  ip_range = "10.10.10.0/24"
}

# Firewall with Restricted Rules
resource "digitalocean_firewall" "compliant_firewall" {
  name = "soc2-compliant-firewall"

  droplet_ids = [digitalocean_droplet.compliant_droplet.id]

  inbound_rule {
    protocol         = "tcp"
    port_range       = "443"
    source_addresses = ["10.0.0.0/8"]
  }

  inbound_rule {
    protocol         = "tcp"
    port_range       = "22"
    source_addresses = ["192.168.1.0/24"]
  }

  outbound_rule {
    protocol              = "tcp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }
}

# Database Cluster with High Availability
resource "digitalocean_database_cluster" "compliant_db" {
  name       = "soc2-compliant-database"
  engine     = "pg"
  version    = "14"
  size       = "db-s-1vcpu-1gb"
  region     = "nyc3"
  node_count = 2

  private_network_uuid = digitalocean_vpc.compliant_vpc.id
}

# Database Firewall
resource "digitalocean_database_firewall" "compliant_db_fw" {
  cluster_id = digitalocean_database_cluster.compliant_db.id

  rule {
    type  = "droplet"
    value = digitalocean_droplet.compliant_droplet.id
  }

  rule {
    type  = "ip_addr"
    value = "10.10.10.0/24"
  }
}

# Load Balancer with HTTPS
resource "digitalocean_loadbalancer" "compliant_lb" {
  name   = "soc2-compliant-lb"
  region = "nyc3"

  forwarding_rule {
    entry_port     = 443
    entry_protocol = "https"

    target_port     = 80
    target_protocol = "http"

    certificate_name = digitalocean_certificate.cert.name
  }

  healthcheck {
    port     = 80
    protocol = "http"
    path     = "/health"
  }

  droplet_ids = [digitalocean_droplet.compliant_droplet.id]
}

resource "digitalocean_certificate" "cert" {
  name    = "soc2-cert"
  type    = "lets_encrypt"
  domains = ["example.com"]
}

# Spaces Bucket with Private ACL
resource "digitalocean_spaces_bucket" "compliant_bucket" {
  name   = "soc2-compliant-bucket"
  region = "nyc3"
  acl    = "private"

  lifecycle_rule {
    id      = "expire-old-files"
    enabled = true

    expiration {
      days = 90
    }
  }
}

# Volume with Snapshot
resource "digitalocean_volume" "compliant_volume" {
  region                  = "nyc3"
  name                    = "soc2-compliant-volume"
  size                    = 100
  initial_filesystem_type = "ext4"
  description             = "SOC2 compliant storage volume"
}

resource "digitalocean_volume_snapshot" "compliant_snapshot" {
  name      = "soc2-volume-snapshot"
  volume_id = digitalocean_volume.compliant_volume.id
}

# Kubernetes Cluster with VPC
resource "digitalocean_kubernetes_cluster" "compliant_cluster" {
  name    = "soc2-compliant-k8s"
  region  = "nyc3"
  version = "1.27.4-do.0"

  vpc_uuid = digitalocean_vpc.compliant_vpc.id

  node_pool {
    name       = "worker-pool"
    size       = "s-2vcpu-2gb"
    node_count = 3
  }
}

# Monitoring Alert
resource "digitalocean_monitor_alert" "compliant_alert" {
  alerts {
    email = ["admin@example.com"]
  }

  window      = "5m"
  type        = "v1/insights/droplet/cpu"
  compare     = "GreaterThan"
  value       = 80
  enabled     = true
  entities    = [digitalocean_droplet.compliant_droplet.id]
  description = "CPU usage alert for SOC2 compliance"
}

# Project Organization
resource "digitalocean_project" "compliant_project" {
  name        = "SOC2 Compliant Infrastructure"
  description = "Infrastructure meeting SOC2 compliance requirements"
  purpose     = "Web Application"
  environment = "Production"

  resources = [
    digitalocean_droplet.compliant_droplet.urn,
    digitalocean_database_cluster.compliant_db.urn,
    digitalocean_loadbalancer.compliant_lb.urn
  ]
}
