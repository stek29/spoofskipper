# Agent instructions

- Discussion and review do not authorize edits. Commit, push, and deploy only within the user's authorized scope; existing authorization remains valid.
- For changes packaged in an image: test → bump the affected VERSION_* in .env → commit/push → wait for tests and image publication → deploy the published image → verify. Use another production build source only if explicitly requested.
- For private configuration changes: back up → validate → activate → verify the actual traffic path.
- Keep ignored private configuration and runtime data out of Git, and credentials out of tool output.
