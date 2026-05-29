# ─────────────────────────────────────────────────────────────────────────────
# Outputs for the Kata host module
# ─────────────────────────────────────────────────────────────────────────────

output "server_ip" {
  description = "Public IPv4 address of the Kata host"
  value       = hcloud_server.kata_host.ipv4_address
}

output "server_ipv6" {
  description = "Public IPv6 network of the Kata host"
  value       = hcloud_server.kata_host.ipv6_network
}

output "server_status" {
  description = "Current status of the server (running, off, etc.)"
  value       = hcloud_server.kata_host.status
}

output "server_id" {
  description = "Hetzner server ID"
  value       = hcloud_server.kata_host.id
}

output "ssh_command" {
  description = "SSH command to connect to the server"
  value       = "ssh root@${hcloud_server.kata_host.ipv4_address}"
}
