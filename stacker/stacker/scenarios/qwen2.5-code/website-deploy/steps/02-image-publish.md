This step is about turning the local project into a remotely deployable image.

Required behavior:
1. Verify the image repository and tag that should be produced.
2. Explain the exact build, login, and push commands needed for the chosen registry.
3. Refuse to proceed to remote deploy until the image push has completed successfully.
4. Mention any project-specific checks that should happen before push, such as build or local smoke tests.

Guardrails:
- Do not assume the registry already contains the image.
- If the repository or tag is missing, ask for it.
- Keep the answer conservative and sequential.
