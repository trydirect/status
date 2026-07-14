## Docker buildx quick reference

Use this to publish the same multi-platform image variants that CI builds for the
`dev` branch:

```bash
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  --build-context stacker=./stacker \
  -f Dockerfile.prod \
  -t trydirect/status:unstable \
  -t trydirect/status:latest \
  --push \
  .
```

This requires a sibling checkout at `../stacker` because `Cargo.toml` includes
local path dependencies from that repository.

If you only want to validate the multi-platform build locally without pushing,
replace `--push` with `--output=type=oci,dest=./status-multiarch.tar`.
