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
- Windows: runs a dedicated TLS diagnostic listener on port 45822 and generates a 120-second QR with a cryptographically random nonce and TLS endpoint hint.
- Android: scans and validates the QR, then can explicitly connect over TLS and verify the exact certificate SHA-256 pin.
- Android: UDP discovery client, TCP HELLO/WELCOME handshake, and PING/PONG round-trip display.
- CI: Android and Windows build jobs are configured.

**Still not implemented:** server-side nonce validation/consumption, authenticated pairing approval/proof, trust storage/revocation, file transfer, resume, DLNA, remote folder access, and physical-device interoperability testing.

The TLS probe confirms that the endpoint presents the certificate encoded in the scanned QR. It does not pair devices or authorize file access. The separate TCP diagnostic on port 45821 remains plaintext and unauthenticated; neither diagnostic endpoint is suitable for file access or user-file transfer. See docs/SECURITY.md.
