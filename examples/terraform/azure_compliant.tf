# SOC2 Compliant Azure Terraform Configuration Examples
# These resources pass all SOC2 Checkov policies for Azure

# Resource Group
resource "azurerm_resource_group" "soc2_rg" {
  name     = "soc2-compliant-rg"
  location = "East US"

  tags = {
    Environment = "Production"
    Compliance  = "SOC2"
  }
}

# Virtual Network
resource "azurerm_virtual_network" "soc2_vnet" {
  name                = "soc2-compliant-vnet"
  location            = azurerm_resource_group.soc2_rg.location
  resource_group_name = azurerm_resource_group.soc2_rg.name
  address_space       = ["10.0.0.0/16"]

  tags = {
    Environment = "Production"
    Compliance  = "SOC2"
  }
}

# Subnet with Service Endpoints
resource "azurerm_subnet" "soc2_subnet" {
  name                 = "soc2-compliant-subnet"
  resource_group_name  = azurerm_resource_group.soc2_rg.name
  virtual_network_name = azurerm_virtual_network.soc2_vnet.name
  address_prefixes     = ["10.0.1.0/24"]
  service_endpoints    = ["Microsoft.Storage", "Microsoft.KeyVault", "Microsoft.Sql"]
}

# Network Security Group with Restricted SSH/RDP
resource "azurerm_network_security_group" "soc2_nsg" {
  name                = "soc2-compliant-nsg"
  location            = azurerm_resource_group.soc2_rg.location
  resource_group_name = azurerm_resource_group.soc2_rg.name

  security_rule {
    name                       = "AllowHTTPS"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "10.0.0.0/8"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "AllowSSHRestricted"
    priority                   = 200
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "10.0.0.0/24"
    destination_address_prefix = "*"
  }

  tags = {
    Environment = "Production"
    Compliance  = "SOC2"
  }
}

# Storage Account with Encryption and Restricted Access
resource "azurerm_storage_account" "soc2_storage" {
  name                      = "soc2compliantstorage"
  resource_group_name       = azurerm_resource_group.soc2_rg.name
  location                  = azurerm_resource_group.soc2_rg.location
  account_tier              = "Standard"
  account_replication_type  = "GRS"
  enable_https_traffic_only = true
  min_tls_version           = "TLS1_2"
  allow_blob_public_access  = false
  public_network_access_enabled = false

  network_rules {
    default_action             = "Deny"
    ip_rules                   = []
    virtual_network_subnet_ids = [azurerm_subnet.soc2_subnet.id]
    bypass                     = ["AzureServices"]
  }

  tags = {
    Environment     = "Production"
    Compliance      = "SOC2"
    LoggingEnabled  = "true"
  }
}

# Log Analytics Workspace
resource "azurerm_log_analytics_workspace" "soc2_workspace" {
  name                = "soc2-log-analytics"
  location            = azurerm_resource_group.soc2_rg.location
  resource_group_name = azurerm_resource_group.soc2_rg.name
  sku                 = "PerGB2018"
  retention_in_days   = 90

  tags = {
    Environment = "Production"
    Compliance  = "SOC2"
  }
}

# Key Vault with Network Restrictions
resource "azurerm_key_vault" "soc2_kv" {
  name                        = "soc2-compliant-kv"
  location                    = azurerm_resource_group.soc2_rg.location
  resource_group_name         = azurerm_resource_group.soc2_rg.name
  tenant_id                   = data.azurerm_client_config.current.tenant_id
  sku_name                    = "premium"
  soft_delete_retention_days  = 90
  purge_protection_enabled    = true
  enable_rbac_authorization   = true
  public_network_access_enabled = false

  network_acls {
    default_action             = "Deny"
    bypass                     = "AzureServices"
    virtual_network_subnet_ids = [azurerm_subnet.soc2_subnet.id]
  }

  tags = {
    Environment         = "Production"
    Compliance          = "SOC2"
    DiagnosticsEnabled  = "true"
  }
}

data "azurerm_client_config" "current" {}

# Disk Encryption Set
resource "azurerm_disk_encryption_set" "soc2_des" {
  name                = "soc2-disk-encryption-set"
  resource_group_name = azurerm_resource_group.soc2_rg.name
  location            = azurerm_resource_group.soc2_rg.location
  key_vault_key_id    = azurerm_key_vault_key.soc2_key.id

  identity {
    type = "SystemAssigned"
  }

  tags = {
    Environment = "Production"
    Compliance  = "SOC2"
  }
}

resource "azurerm_key_vault_key" "soc2_key" {
  name         = "soc2-encryption-key"
  key_vault_id = azurerm_key_vault.soc2_kv.id
  key_type     = "RSA"
  key_size     = 2048

  key_opts = [
    "decrypt",
    "encrypt",
    "sign",
    "unwrapKey",
    "verify",
    "wrapKey",
  ]
}

# Linux Virtual Machine with Encryption and SSH Key Authentication
resource "azurerm_linux_virtual_machine" "soc2_vm" {
  name                            = "soc2-compliant-vm"
  location                        = azurerm_resource_group.soc2_rg.location
  resource_group_name             = azurerm_resource_group.soc2_rg.name
  size                            = "Standard_DS1_v2"
  admin_username                  = "azureuser"
  disable_password_authentication = true
  encryption_at_host_enabled      = true

  network_interface_ids = [
    azurerm_network_interface.soc2_nic.id,
  ]

  admin_ssh_key {
    username   = "azureuser"
    public_key = file("~/.ssh/id_rsa.pub")
  }

  os_disk {
    name                 = "soc2-vm-osdisk"
    caching              = "ReadWrite"
    storage_account_type = "Premium_LRS"
    disk_encryption_set_id = azurerm_disk_encryption_set.soc2_des.id
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "UbuntuServer"
    sku       = "18.04-LTS"
    version   = "latest"
  }

  identity {
    type = "SystemAssigned"
  }

  tags = {
    Environment   = "Production"
    Compliance    = "SOC2"
    BackupEnabled = "true"
  }
}

resource "azurerm_network_interface" "soc2_nic" {
  name                = "soc2-nic"
  location            = azurerm_resource_group.soc2_rg.location
  resource_group_name = azurerm_resource_group.soc2_rg.name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.soc2_subnet.id
    private_ip_address_allocation = "Dynamic"
  }

  tags = {
    Environment = "Production"
    Compliance  = "SOC2"
  }
}

# SQL Server with Azure AD Admin and Auditing
resource "azurerm_mssql_server" "soc2_sql" {
  name                         = "soc2-compliant-sqlserver"
  resource_group_name          = azurerm_resource_group.soc2_rg.name
  location                     = azurerm_resource_group.soc2_rg.location
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = "ComplexP@ssw0rd123!"
  minimum_tls_version          = "1.2"
  public_network_access_enabled = false

  azuread_administrator {
    login_username = "AzureAD Admin"
    object_id      = data.azurerm_client_config.current.object_id
  }

  tags = {
    Environment      = "Production"
    Compliance       = "SOC2"
    AuditingEnabled  = "true"
  }
}

# SQL Database with Encryption and Backup
resource "azurerm_mssql_database" "soc2_db" {
  name           = "soc2-compliant-db"
  server_id      = azurerm_mssql_server.soc2_sql.id
  collation      = "SQL_Latin1_General_CP1_CI_AS"
  license_type   = "LicenseIncluded"
  sku_name       = "S0"
  zone_redundant = true
  geo_backup_enabled = true

  short_term_retention_policy {
    retention_days = 7
  }

  long_term_retention_policy {
    weekly_retention  = "P1W"
    monthly_retention = "P1M"
    yearly_retention  = "P1Y"
    week_of_year      = 1
  }

  tags = {
    Environment = "Production"
    Compliance  = "SOC2"
  }
}

# SQL Firewall Rule (Restricted)
resource "azurerm_mssql_firewall_rule" "soc2_sql_fw" {
  name             = "AllowSpecificIP"
  server_id        = azurerm_mssql_server.soc2_sql.id
  start_ip_address = "10.0.0.1"
  end_ip_address   = "10.0.0.254"
}

# PostgreSQL Flexible Server with SSL and Backup
resource "azurerm_postgresql_flexible_server" "soc2_postgres" {
  name                   = "soc2-compliant-postgres"
  resource_group_name    = azurerm_resource_group.soc2_rg.name
  location               = azurerm_resource_group.soc2_rg.location
  version                = "13"
  administrator_login    = "psqladmin"
  administrator_password = "ComplexP@ssw0rd123!"
  storage_mb             = 32768
  sku_name               = "GP_Standard_D2s_v3"
  zone                   = "1"
  backup_retention_days  = 7
  geo_redundant_backup_enabled = true

  tags = {
    Environment = "Production"
    Compliance  = "SOC2"
  }
}

# PostgreSQL Configuration for Logging
resource "azurerm_postgresql_configuration" "log_connections" {
  name                = "log_connections"
  resource_group_name = azurerm_resource_group.soc2_rg.name
  server_name         = azurerm_postgresql_flexible_server.soc2_postgres.name
  value               = "on"
}

resource "azurerm_postgresql_configuration" "log_checkpoints" {
  name                = "log_checkpoints"
  resource_group_name = azurerm_resource_group.soc2_rg.name
  server_name         = azurerm_postgresql_flexible_server.soc2_postgres.name
  value               = "on"
}

# MySQL Flexible Server with SSL and Backup
resource "azurerm_mysql_flexible_server" "soc2_mysql" {
  name                   = "soc2-compliant-mysql"
  resource_group_name    = azurerm_resource_group.soc2_rg.name
  location               = azurerm_resource_group.soc2_rg.location
  administrator_login    = "mysqladmin"
  administrator_password = "ComplexP@ssw0rd123!"
  sku_name               = "GP_Standard_D2ds_v4"
  version                = "8.0.21"
  backup_retention_days  = 7
  geo_redundant_backup_enabled = true

  tags = {
    Environment = "Production"
    Compliance  = "SOC2"
  }
}

# CosmosDB Account with Backup
resource "azurerm_cosmosdb_account" "soc2_cosmos" {
  name                = "soc2-compliant-cosmos"
  location            = azurerm_resource_group.soc2_rg.location
  resource_group_name = azurerm_resource_group.soc2_rg.name
  offer_type          = "Standard"
  kind                = "GlobalDocumentDB"
  public_network_access_enabled = false
  is_virtual_network_filter_enabled = true

  consistency_policy {
    consistency_level = "Session"
  }

  geo_location {
    location          = azurerm_resource_group.soc2_rg.location
    failover_priority = 0
  }

  backup {
    type                = "Continuous"
  }

  virtual_network_rule {
    id = azurerm_subnet.soc2_subnet.id
  }

  tags = {
    Environment = "Production"
    Compliance  = "SOC2"
  }
}

# Container Registry without Admin Account
resource "azurerm_container_registry" "soc2_acr" {
  name                = "soc2compliantacr"
  resource_group_name = azurerm_resource_group.soc2_rg.name
  location            = azurerm_resource_group.soc2_rg.location
  sku                 = "Premium"
  admin_enabled       = false
  public_network_access_enabled = false

  network_rule_set {
    default_action = "Deny"
    virtual_network {
      action    = "Allow"
      subnet_id = azurerm_subnet.soc2_subnet.id
    }
  }

  tags = {
    Environment = "Production"
    Compliance  = "SOC2"
  }
}

# AKS Cluster with RBAC and Monitoring
resource "azurerm_kubernetes_cluster" "soc2_aks" {
  name                = "soc2-compliant-aks"
  location            = azurerm_resource_group.soc2_rg.location
  resource_group_name = azurerm_resource_group.soc2_rg.name
  dns_prefix          = "soc2aks"
  role_based_access_control_enabled = true
  local_account_disabled = true
  private_cluster_enabled = true

  default_node_pool {
    name                = "default"
    node_count          = 3
    vm_size             = "Standard_DS2_v2"
    zones               = ["1", "2", "3"]
    enable_host_encryption = true
    vnet_subnet_id      = azurerm_subnet.soc2_subnet.id
  }

  identity {
    type = "SystemAssigned"
  }

  azure_active_directory_role_based_access_control {
    managed                = true
    azure_rbac_enabled     = true
  }

  network_profile {
    network_plugin    = "azure"
    network_policy    = "azure"
    service_cidr      = "10.1.0.0/16"
    dns_service_ip    = "10.1.0.10"
    docker_bridge_cidr = "172.17.0.1/16"
  }

  oms_agent {
    log_analytics_workspace_id = azurerm_log_analytics_workspace.soc2_workspace.id
  }

  azure_policy_enabled = true

  tags = {
    Environment = "Production"
    Compliance  = "SOC2"
  }
}

# Recovery Services Vault
resource "azurerm_recovery_services_vault" "soc2_vault" {
  name                = "soc2-recovery-vault"
  location            = azurerm_resource_group.soc2_rg.location
  resource_group_name = azurerm_resource_group.soc2_rg.name
  sku                 = "Standard"
  soft_delete_enabled = true

  tags = {
    Environment = "Production"
    Compliance  = "SOC2"
  }
}

# Backup Policy for VMs
resource "azurerm_backup_policy_vm" "soc2_backup_policy" {
  name                = "soc2-vm-backup-policy"
  resource_group_name = azurerm_resource_group.soc2_rg.name
  recovery_vault_name = azurerm_recovery_services_vault.soc2_vault.name

  backup {
    frequency = "Daily"
    time      = "23:00"
  }

  retention_daily {
    count = 30
  }

  retention_weekly {
    count    = 12
    weekdays = ["Sunday"]
  }

  retention_monthly {
    count    = 12
    weekdays = ["Sunday"]
    weeks    = ["First"]
  }

  retention_yearly {
    count    = 7
    weekdays = ["Sunday"]
    weeks    = ["First"]
    months   = ["January"]
  }
}

# App Service Plan
resource "azurerm_service_plan" "soc2_plan" {
  name                = "soc2-app-service-plan"
  location            = azurerm_resource_group.soc2_rg.location
  resource_group_name = azurerm_resource_group.soc2_rg.name
  os_type             = "Linux"
  sku_name            = "P1v2"

  tags = {
    Environment = "Production"
    Compliance  = "SOC2"
  }
}

# Linux Web App with Managed Identity and VNet Integration
resource "azurerm_linux_web_app" "soc2_app" {
  name                = "soc2-compliant-webapp"
  location            = azurerm_resource_group.soc2_rg.location
  resource_group_name = azurerm_resource_group.soc2_rg.name
  service_plan_id     = azurerm_service_plan.soc2_plan.id
  https_only          = true
  virtual_network_subnet_id = azurerm_subnet.soc2_subnet.id

  site_config {
    minimum_tls_version = "1.2"
    http2_enabled       = true
    ftps_state          = "FtpsOnly"
    http_logging_enabled = true
    detailed_error_logging_enabled = true
    vnet_route_all_enabled = true
  }

  identity {
    type = "SystemAssigned"
  }

  logs {
    application_logs {
      file_system_level = "Information"
    }

    http_logs {
      file_system {
        retention_in_days = 7
        retention_in_mb   = 35
      }
    }
  }

  tags = {
    Environment = "Production"
    Compliance  = "SOC2"
  }
}

# Network Watcher (required for flow logs)
resource "azurerm_network_watcher" "soc2_watcher" {
  name                = "soc2-network-watcher"
  location            = azurerm_resource_group.soc2_rg.location
  resource_group_name = azurerm_resource_group.soc2_rg.name

  tags = {
    Environment = "Production"
    Compliance  = "SOC2"
  }
}

# Network Watcher Flow Log
resource "azurerm_network_watcher_flow_log" "soc2_flow_log" {
  network_watcher_name = azurerm_network_watcher.soc2_watcher.name
  resource_group_name  = azurerm_resource_group.soc2_rg.name
  name                 = "soc2-nsg-flow-log"

  network_security_group_id = azurerm_network_security_group.soc2_nsg.id
  storage_account_id        = azurerm_storage_account.soc2_storage.id
  enabled                   = true

  retention_policy {
    enabled = true
    days    = 90
  }

  traffic_analytics {
    enabled               = true
    workspace_id          = azurerm_log_analytics_workspace.soc2_workspace.workspace_id
    workspace_region      = azurerm_log_analytics_workspace.soc2_workspace.location
    workspace_resource_id = azurerm_log_analytics_workspace.soc2_workspace.id
  }

  tags = {
    Environment = "Production"
    Compliance  = "SOC2"
  }
}
