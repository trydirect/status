# Hetzner Bare-Metal KVM Guide for Kata Containers

## What Actually Works on Hetzner

Kata Containers require direct access to `/dev/kvm`. On Hetzner, that means
**bare metal only**.

| Platform | Example types | `/dev/kvm` available | Kata Ready |
|---|---|---|---|
| Hetzner Cloud | CCX, CX, CPX, CAX | ❌ | ❌ |
| Hetzner Robot | Dedicated bare-metal servers | ✅ | ✅ |

> **Important:** Dedicated CPU is **not** enough on Hetzner Cloud. Even the
> CCX family runs inside a VM, and the guest OS does not get direct `/dev/kvm`
> access. For Kata on Hetzner, use **Robot bare metal**.

## Why Hetzner Cloud Does Not Work

All Hetzner Cloud instances run on a hypervisor that does **not** expose
`/dev/kvm` to the guest. Without KVM, the Kata hypervisor cannot create
hardware-isolated VMs, and `kata-runtime` will fail with:

```
kata-runtime: arch requires KVM to run, but /dev/kvm is not accessible
```

There is no practical workaround on Hetzner Cloud — Kata needs real KVM access.

## Verifying KVM Access

After provisioning your **Hetzner Robot bare-metal** server, verify KVM is
available:

```bash
# Check /dev/kvm exists
ls -la /dev/kvm
# Expected: crw-rw---- 1 root kvm 10, 232 ... /dev/kvm

# Check KVM module is loaded
lsmod | grep kvm
# Expected: kvm_intel (or kvm_amd) and kvm modules

# After installing Kata, run Kata's own validation
kata-runtime check
# Expected: all checks pass once the runtime is installed
```

## Provisioning a Kata-Ready Bare-Metal Server

### Option 1: Hetzner Robot + Ansible (recommended)

```bash
# Order and install a dedicated server in Hetzner Robot first.
# Then configure Kata on the running host:
git clone https://github.com/trydirect/stacker.git
cd stacker/docs/kata/ansible

ansible-playbook -i <server-ip>, kata-setup.yml \
  --private-key ~/.ssh/id_rsa \
  --user root
```

Before you run the playbook:

1. Order an x86_64 dedicated server in the
   [Hetzner Robot portal](https://robot.hetzner.com/).
2. Install **Ubuntu 22.04 LTS**.
3. Add your SSH key and boot the host.
4. Verify `/dev/kvm` exists on the server.

The `kata-setup.yml` playbook then:

- Validates KVM access
- Installs Kata Containers from the official APT repository
- Configures Docker with the `kata` runtime
- Restarts Docker and runs a smoke test

### Option 2: Manual Setup on an Existing Robot Server

```bash
# SSH into your bare-metal server
ssh root@<server-ip>

# Verify KVM
ls -la /dev/kvm

# Install Kata (Ubuntu 22.04+)
install -d /etc/apt/keyrings
curl -fsSL https://packages.kata-containers.io/kata-containers.key \
  | gpg --dearmor -o /etc/apt/keyrings/kata-containers.gpg
echo "deb [signed-by=/etc/apt/keyrings/kata-containers.gpg] \
  https://packages.kata-containers.io/stable/ubuntu/$(lsb_release -cs)/ \
  stable main" > /etc/apt/sources.list.d/kata-containers.list
apt-get update && apt-get install -y kata-containers

# Configure Docker
python3 - <<'PY'
import json
from pathlib import Path

path = Path('/etc/docker/daemon.json')
text = path.read_text() if path.exists() else ''
data = json.loads(text) if text.strip() else {}
data.setdefault('runtimes', {})['kata'] = {'path': '/usr/bin/kata-runtime'}
path.write_text(json.dumps(data, indent=2) + '\n')
PY
systemctl restart docker

# Test
kata-runtime check
docker run --rm --runtime kata hello-world
```

## Do Not Use the Hetzner Cloud Terraform Module for Kata

The `hcloud` provider provisions **Hetzner Cloud** VMs only. Those VMs do not
expose `/dev/kvm`, so they are not valid Kata targets. On Hetzner, the correct
flow is:

1. Provision a **Robot bare-metal** server outside Terraform
2. Verify `/dev/kvm`
3. Run the Kata Ansible playbook or the manual install steps above

## Network Considerations

See [NETWORK_CONSTRAINTS.md](NETWORK_CONSTRAINTS.md) for important networking
limitations when running Kata containers, particularly around `network_mode: host`.

## Performance Notes

Running containers inside Kata VMs adds overhead compared to `runc`:

| Aspect | Overhead |
|---|---|
| Container start time | +0.5–2s (VM boot) |
| Memory | +~30 MB per container (VM overhead) |
| Network latency | +50–150 µs per packet |
| Disk I/O | ~5–10% throughput reduction |
| CPU | Negligible for compute; slight overhead for syscall-heavy workloads |

For web services, APIs, and databases, the overhead is typically negligible.
For latency-critical workloads, benchmark before committing to Kata.

## Troubleshooting

### `/dev/kvm` not found
- Ensure you're on a **Hetzner Robot bare-metal** server, not any Hetzner Cloud VM
- Verify virtualisation support is enabled for the host CPU
- Reboot after OS installation if `/dev/kvm` is still missing
- Check `dmesg | grep -i kvm` for kernel-level errors

### `kata-runtime check` fails
- Run `kata-runtime check --verbose` for detailed diagnostics
- Verify kernel modules: `lsmod | grep kvm`
- Check CPU flags: `grep -c vmx /proc/cpuinfo` (Intel) or `grep -c svm /proc/cpuinfo` (AMD)

### Container fails to start with Kata
- Check Docker logs: `journalctl -u docker -f`
- Check for `network_mode: host` conflicts (not supported)
- Ensure enough memory for VM overhead (~30 MB per container)
