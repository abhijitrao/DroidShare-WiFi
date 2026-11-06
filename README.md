# DroidShare-WiFi

Fast, secure local file sharing between Android and Windows over Wi-Fi.

## Project structure
- android/ — Kotlin / Jetpack Compose application.
- windows/ — C# / .NET 10 / WPF application.
- shared/protocol/ — shared protocol specifications.
- docs/ — architecture, security, and testing documentation.

## Product principles
- Bidirectional file transfer over local Wi-Fi.
- Automatic device discovery; no manual IP or port entry.
- QR-assisted pairing when needed.
- Router Wi-Fi and hotspot connectivity where devices can reach each other.
- User-selected Windows shared folders only.
- Planned UPnP AV / DLNA media streaming.

See AGENTS.md for repository engineering instructions and PROJECT_PLAN.md for the roadmap and acceptance criteria.

## Current implementation status
- Windows WPF: UDP discovery responder and TCP diagnostic listener.
- Android: UDP discovery client, TCP HELLO/WELCOME handshake, and PING/PONG round-trip display.
- CI: Android and Windows build jobs are configured.
- Not implemented: QR display/scanning, TLS, authenticated pairing, trust/revocation, file transfer, resume, DLNA, remote folder access, and physical-device interoperability testing.

The current connection diagnostic is plaintext and unauthenticated. It is not suitable for file access or user-file transfer. See docs/SECURITY.md before extending the network protocol.
