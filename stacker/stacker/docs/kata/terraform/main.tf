# ─────────────────────────────────────────────────────────────────────────────
# Terraform module: Provision a KVM-capable Hetzner server with Docker + Kata
# ─────────────────────────────────────────────────────────────────────────────
#
# Usage:
#   terraform init
#   terraform plan -var="hcloud_token=YOUR_TOKEN" -var="ssh_key_name=my-key"
#   terraform apply
#
# The server is provisioned with a cloud-init script that installs Docker CE
# and Kata Containers on first boot. After boot completes, run the Ansible
# playbook for idempotent configuration or simply SSH in — everything is ready.

terraform {
  required_version = ">= 1.5"

  required_providers {
    hcloud = {
      source  = "hetznercloud/hcloud"
      version = "~> 1.45"
    }
  }
}

provider "hcloud" {
  token = var.hcloud_token
}

# ── SSH key reference ───────────────────────────────────────────────────────
data "hcloud_ssh_key" "default" {
  name = var.ssh_key_name
}

# ── Dedicated server ───────────────────────────────────────────────────────
resource "hcloud_server" "kata_host" {
  name        = var.server_name
  image       = "ubuntu-22.04"
  server_type = var.server_type  # must support KVM — dedicated vCPU types (ccx*, cx*)
  location    = var.location
  ssh_keys    = [data.hcloud_ssh_key.default.id]
  labels      = var.labels

  # cloud-init installs Docker + Kata on first boot
  user_data = <<-CLOUDINIT
    #cloud-config
    package_update: true
    package_upgrade: true

    packages:
      - apt-transport-https
      - ca-certificates
      - curl
      - gnupg
      - lsb-release

    write_files:
      # Docker daemon config with kata runtime pre-registered
      - path: /etc/docker/daemon.json
        permissions: "0644"
        content: |
          {
            "runtimes": {
              "kata": {
                "path": "/usr/bin/kata-runtime"
              }
            }
          }

    runcmd:
      # ── Docker CE ──────────────────────────────────────────────────
      - install -m 0755 -d /etc/apt/keyrings
      - curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
      - chmod a+r /etc/apt/keyrings/docker.asc
      - |
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
        https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
        > /etc/apt/sources.list.d/docker.list
      - apt-get update -y
      - apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
      - systemctl enable --now docker

      # ── Kata Containers ────────────────────────────────────────────
      - curl -fsSL https://packages.kata-containers.io/kata-containers.key -o /etc/apt/keyrings/kata-containers.asc
      - |
        echo "deb [signed-by=/etc/apt/keyrings/kata-containers.asc] \
        https://packages.kata-containers.io/stable/ubuntu/$(lsb_release -cs)/ stable main" \
        > /etc/apt/sources.list.d/kata-containers.list
      - apt-get update -y
      - apt-get install -y kata-containers

      # ── Restart Docker to pick up kata runtime ─────────────────────
      - systemctl restart docker

      # ── Quick smoke test ───────────────────────────────────────────
      - docker run --rm --runtime kata hello-world
  CLOUDINIT

  # Dedicated servers can take a few minutes to provision
  timeouts {
    create = "15m"
  }
}
