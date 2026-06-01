# Release build (GitHub Actions)

This repository uses GitHub Actions to build release artifacts:

- `release.yml` builds `stacker-cli` binaries on release publish.
- `docker.yml` builds and pushes `trydirect/stacker:<tag>` on release publish.

## Release via GitHub CLI

### 1) Ensure you are on `main`

```bash
git checkout main

git pull
```

### 2) Create and publish the release

```bash
gh release create v0.2.8 --generate-notes
```

This creates the `v0.2.8` tag and publishes the release, which triggers:

- CLI binary builds (linux + macOS) and uploads to the release.
- Docker image build and push tagged as `trydirect/stacker:v0.2.8`.

### 3) Verify artifacts

```bash
gh release view v0.2.8 --json assets --jq '.assets[].name'
```

### 4) Check workflows

```bash
gh run list -L 10
```

## Optional: Re-run workflows

```bash
gh run rerun <run-id>
```
