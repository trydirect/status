# Network Constraints with Kata Containers

Kata Containers run each container inside a lightweight virtual machine. This VM
boundary changes how networking behaves compared to standard `runc` containers.

## `network_mode: host` Is Not Supported

With `runc`, `network_mode: host` shares the host's network namespace directly.
Under Kata, the container runs in a **guest VM** with its own kernel and network
stack, so there is no host namespace to share. Setting `network_mode: host` on a
Kata container will either fail or silently fall back to bridge mode (depending
on the Kata/Docker version), producing unexpected behaviour.

**Rule of thumb:** never use `network_mode: host` with `runtime: kata`.

## Recommended Network Modes

| Mode | Works with Kata | Notes |
|---|---|---|
| `bridge` (default) | ✅ | Standard Docker bridge. Port mapping (`-p`) works normally. |
| `macvlan` | ✅ | Assigns a real MAC address on the host NIC; useful for L2 access. |
| `overlay` | ✅ | Swarm/multi-host overlay networks work as expected. |
| `none` | ✅ | No networking — useful for batch/compute workloads. |
| `host` | ❌ | Not supported — VM boundary prevents host namespace sharing. |

### Port Mapping

Standard port mapping (`ports: ["8080:80"]`) works normally in bridge mode.
Traffic crosses the VM boundary via a `virtio-net` device and a TAP interface on
the host — no extra configuration needed.

## Performance Considerations

Network traffic crosses the VM boundary through a virtual NIC (`virtio-net`),
which adds a small amount of latency and CPU overhead compared to `runc`.

| Metric | Typical Overhead |
|---|---|
| Latency | ~50–150 µs additional per packet |
| Throughput | ~5–10% reduction at line rate |
| CPU | Slightly higher due to vhost processing |

For most web services, databases, and APIs the overhead is negligible. For
latency-critical workloads (sub-millisecond SLAs, high-frequency trading), test
under load before committing to Kata.

## Workarounds for Services That Traditionally Use Host Networking

### 1. Use Bridge Mode with Explicit Port Mapping

Most services use `network_mode: host` only for convenience — they work fine in
bridge mode once ports are mapped explicitly:

```yaml
services:
  my-service:
    image: my-app:latest
    runtime: kata
    ports:
      - "8080:8080"
      - "9090:9090"
```

### 2. Use macvlan for L2 Access

If a service needs to appear as a physical device on the LAN (e.g., for mDNS,
DHCP, or cluster discovery):

```yaml
networks:
  lan:
    driver: macvlan
    driver_opts:
      parent: eth0
    ipam:
      config:
        - subnet: 192.168.1.0/24

services:
  my-service:
    image: my-app:latest
    runtime: kata
    networks:
      lan:
        ipv4_address: 192.168.1.50
```

### 3. Run Specific Services with runc

Not every service needs hardware isolation. In a mixed stack, run
security-critical containers with Kata and leave performance-critical networking
services on `runc`:

```yaml
services:
  # Isolated workload — use Kata
  untrusted-processor:
    image: processor:latest
    runtime: kata

  # Needs host networking — keep on runc
  metrics-exporter:
    image: prom/node-exporter:latest
    network_mode: host
    # runtime defaults to runc
```

## How Stacker Handles This

When a deployment specifies `runtime: kata`, the Stacker agent performs
pre-deploy validation on the generated `docker-compose.yml`:

1. **Scans** each service block for `network_mode: host`.
2. **Emits a warning** in the deployment log if host networking is detected on a
   Kata service.
3. **Does not block** the deployment — Docker/Kata will reject the incompatible
   configuration at container start, and the error is surfaced in the deploy
   status.

This lets operators catch misconfigurations early without requiring Stacker to
enforce hard failures on compose content it doesn't own.

## References

- [Kata networking architecture](https://github.com/kata-containers/kata-containers/blob/main/docs/design/architecture/networking.md)
- [Kata limitations](https://github.com/kata-containers/kata-containers/blob/main/docs/Limitations.md)
