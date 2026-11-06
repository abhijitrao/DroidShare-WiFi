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
- Windows: creates/loads a self-signed TLS certificate in the current user's certificate store and displays its SHA-256 fingerprint.
- Windows: generates a 120-second QR payload preview with a cryptographically random nonce and local IPv4 endpoint hint.
- Android: UDP discovery client, TCP HELLO/WELCOME handshake, and PING/PONG round-trip display.
- CI: Android and Windows build jobs are configured.

**Still not implemented:** Android QR scanning, TLS listener and certificate pin validation, server-side nonce validation/consumption, authenticated pairing approval/proof, trust storage/revocation, file transfer, resume, DLNA, remote folder access, and physical-device interoperability testing.

The Windows QR is explicitly labelled as a preview and must not be scanned as a working pairing flow yet. The current connection diagnostic is plaintext and unauthenticated; it is not suitable for file access or user-file transfer. See docs/SECURITY.md.
