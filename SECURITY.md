# Security Policy

ARC-Emulator treats emulator inputs as untrusted data.

- Never execute guest-provided data as host code.
- Never fetch ROMs, BIOS files, ISOs, or firmware automatically.
- Never store raw payloads inside authority receipts.
- Store large data as binary objects with hashes and manifests.
- Keep receipts small, deterministic, and verifiable.
- Treat imported save states as untrusted binary containers.
