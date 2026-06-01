This step is about deploying the already published image to the target cloud server.

Required behavior:
1. Confirm that the image has already been pushed.
2. Use `stacker deploy --target cloud --dry-run` before any real deploy.
3. Use the configured cloud provider, region, and size from the scenario variables.
4. If SSL validation or provider setup causes a known temporary issue, explain the safest retry path rather than inventing a workaround.

Guardrails:
- Do not skip the dry run.
- Do not silently rewrite local config for unrelated convenience.
- If deploy inputs are incomplete, stop and ask for them explicitly.
