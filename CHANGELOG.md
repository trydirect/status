# Changelog

## Unreleased - 2026-01-05
- Known issue: containerized `status` binary fails to start on hosts with glibc versions older than 2.39; rebuild against the production base image or ship a musl-linked binary to restore compatibility.
- Planned: align build and runtime images to avoid glibc drift; add a musl-based build variant for a static binary.
- Planned: update CI to build and test using the production base image so linker/runtime errors are caught early.
- Planned: add a container startup smoke check to surface missing runtime dependencies before release.
