# Known Bugs

## GLIBC version mismatch inside container
- **Summary**: The `status` binary inside the container requires `GLIBC_2.39`, but the deployed base image ships an older glibc, causing startup failure.
- **Error**: `/usr/local/bin/status: /lib/x86_64-linux-gnu/libc.so.6: version 'GLIBC_2.39' not found (required by /usr/local/bin/status)`
- **Impact**: Status agent fails to start in the deployed container; health endpoints and status panel remain unavailable.
- **Environment**: Remote server container image (likely Debian/Ubuntu with glibc < 2.39). Local build environment used a newer glibc when compiling.
- **Repro Steps**:
  1) Build the image with the current toolchain.
  2) Run the container on a host/base image with glibc < 2.39.
  3) Execute `/usr/local/bin/status` → startup fails with the glibc error above.
- **Suspected Cause**: Binary compiled against glibc 2.39 on host/build image; deployed runtime provides an older glibc. No compatibility shim present.
- **Suggested Fixes/Workarounds**:
  - Rebuild `status` using the same base image as runtime (e.g., align Dockerfile build stage to target glibc version) so it links against the older glibc available in container.
  - Alternatively, build a statically linked binary using musl (`musl-gcc`/`cargo build --target x86_64-unknown-linux-musl`) to remove glibc dependency.
  - Ensure CI uses the production base image for builds, or pin toolchain to match deployed distro glibc.
