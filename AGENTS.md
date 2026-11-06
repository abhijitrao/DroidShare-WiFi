# AGENTS.md

## Project purpose
DroidShare-WiFi is a local-network file transfer and media-sharing product for Android and Windows. It must work without cloud services or internet access once the devices are on a mutually reachable local network.

## Repository layout
- `android/`: Android application (Kotlin; Jetpack Compose for UI).
- `windows/`: Windows desktop application (C#/.NET; WPF).
- `shared/protocol/`: transport and message protocol specifications shared by both clients.
- `docs/`: architecture, security, testing, and release documentation.
- `PROJECT_PLAN.md`: product scope, decisions, milestones, and acceptance criteria.

## Non-negotiable product decisions
1. Android and Windows live in this single monorepo.
2. The app transfers files in both directions and supports multiple files, nested folders, progress, pause/resume, and integrity verification.
3. Network setup must be automatic. Do not ask users to enter IP addresses, ports, or network parameters. Discover peers automatically on a reachable local network. Use QR pairing when discovery or first-time trust needs user action.
4. Support both ordinary Wi-Fi router networks (prefer 5 GHz when available) and a phone/PC hotspot when the devices can reach each other. Do not promise that the app can silently enable/join hotspots: OS permissions and user confirmation may be required.
5. Only folders explicitly selected by the Windows user may be exposed to Android. Enforce per-share read, write, delete, and stream permissions on the Windows side.
6. Keep file transfer, remote folder browsing, and media streaming as separate capabilities over shared, reusable networking/security components.
7. Planned later features: UPnP AV / DLNA discovery and streaming, plus Android remote browsing/upload/download/streaming of Windows-selected folders.

## Engineering rules
- Inspect the existing repository before changing files. Preserve user changes and existing conventions.
- Keep Android and Windows protocol behavior compatible. Update `shared/protocol/` documentation whenever wire behavior changes.
- Prefer small, reviewable changes. Do not claim a build or test passed unless it was actually run and its result is known.
- Never commit credentials, pairing secrets, private keys, personal paths, or real device/network identifiers.
- Treat all network input and remote file paths as untrusted. Canonicalize paths and enforce that resolved paths remain inside the selected shared root.
- Use TLS for authenticated sessions. QR payloads must contain only short-lived pairing material and connection hints, never a permanent secret.
- Stream files; do not load whole files into memory. Use bounded buffers, explicit framing, cancellation, timeouts, and backpressure.
- Resume only from acknowledged/persisted offsets. Verify completed files with SHA-256.
- Use safe temporary files and atomic finalization where possible. Never overwrite or delete user data silently.
- Keep default share permissions read + stream; write and delete require explicit opt-in.
- Add tests for protocol framing, path traversal prevention, resume boundaries, and reconnect behavior.
- Avoid introducing SMB/Windows Network Sharing as a dependency for the app-managed sharing feature.

## Phase 1 implementation order
1. Define protocol framing and discovery contract.
2. Create Windows TCP listener and a minimal diagnostic UI/status surface.
3. Create Android connection screen and TCP client.
4. Add automatic local-network discovery and QR pairing after the basic connection is reliable.
5. Add repeatable connection tests and throughput benchmarks before file-transfer implementation.

## Definition of done
- Relevant projects compile with documented SDK/tool versions.
- Tests are run where available and their results are reported honestly.
- Documentation and setup instructions match the actual implementation.
- No secrets or user data are included in commits.
