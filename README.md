# DroidShare-WiFi

Fast, secure local file sharing between Android and Windows over Wi-Fi.

## Project structure
- `android/` — Kotlin / Jetpack Compose application.
- `windows/` — C# / .NET 10 / WPF application.
- `shared/protocol/` — shared protocol specifications.
- `docs/` — architecture, security, and testing documentation.

## Product principles
- Bidirectional file transfer over local Wi-Fi.
- Automatic device discovery; no manual IP or port entry.
- QR-assisted pairing when needed.
- Router Wi-Fi and hotspot connectivity where devices can reach each other.
- User-selected Windows shared folders only.
- Planned UPnP AV / DLNA media streaming.

See [AGENTS.md](AGENTS.md) for repository engineering instructions and [PROJECT_PLAN.md](PROJECT_PLAN.md) for the complete roadmap and acceptance criteria.

## Status
Phase 1 connection diagnostics are implemented: Windows UDP discovery/TCP host and Android UDP discovery/TCP client, including HELLO/WELCOME and PING/PONG round-trip measurement. GitHub Actions run 10 passed for both platform builds. QR pairing, TLS authentication, file transfer, resume, DLNA, remote folder access, and physical-device testing are still pending.
