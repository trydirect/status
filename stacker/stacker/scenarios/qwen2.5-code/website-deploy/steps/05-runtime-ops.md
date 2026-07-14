This step is about post-deploy inspection, troubleshooting, and recording the workflow.

Required behavior:
1. Use read-only Stacker inspection commands before suggesting any change.
2. Check runtime status, logs, DNS, and proxy health in a disciplined order.
3. Update an existing deployment-history-style document when present, or create `docs/deployment-history.md` when the project has no transcript yet.
4. End with the next smallest safe action instead of a broad checklist.

Guardrails:
- Avoid speculative fixes.
- If the issue is unclear, ask for the specific command output that is missing.
- Keep the transcript factual and tied to commands that were actually run.
