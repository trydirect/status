# ─────────────────────────────────────────────────────────────────────────────
# Input variables for the Kata host module
# ─────────────────────────────────────────────────────────────────────────────

variable "hcloud_token" {
  description = "Hetzner Cloud API token"
  type        = string
  sensitive   = true
}

variable "ssh_key_name" {
  description = "Name of an existing Hetzner SSH key to inject into the server"
  type        = string
}

variable "server_name" {
  description = "Hostname for the provisioned server"
  type        = string
  default     = "kata-host-01"
}

variable "server_type" {
  description = <<-EOT
    Hetzner server type. Use dedicated-vCPU types for reliable KVM support:
      - cx23  (2 vCPU / 8 GB)   — smallest dedicated, good for testing
      - ccx23  (4 vCPU / 16 GB)  — light production
      - ccx33  (8 vCPU / 32 GB)  — production
    Shared-vCPU types (cx*) may work but KVM is not guaranteed.
  EOT
  type        = string
  default     = "cx23"
}

variable "location" {
  description = "Hetzner datacenter location (nbg1, fsn1, hel1, ash, hil)"
  type        = string
  default     = "nbg1"
}

variable "labels" {
  description = "Labels to attach to the server resource"
  type        = map(string)
  default = {
    managed-by = "terraform"
    role       = "kata-host"
    project    = "stacker"
  }
}
