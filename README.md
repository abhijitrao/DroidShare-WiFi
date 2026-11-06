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
- Android: scans and validates the QR, pins the Windows certificate, and pairs using an Android Keystore P-256 key.
- Windows: validates the one-time QR nonce, asks for explicit approval, verifies Android challenge proof, and persists the trusted public-key identity.
- Android: UDP discovery client, TCP HELLO/WELCOME handshake, and PING/PONG round-trip display.
- CI: Android and Windows build jobs are configured.

**Still not implemented:** trusted-device revocation UI, file transfer, resume, DLNA, remote folder access, and physical-device interoperability testing.

Secure pairing now verifies the Windows certificate pin, one-time in-memory QR nonce, Windows user approval, and Android private-key proof. Windows stores Android public-key identities under LocalAppData; Android stores the Windows certificate pin after the final approval response. Pairing does not yet authorize file access. The separate TCP diagnostic on port 45821 remains plaintext and unauthenticated; neither diagnostic endpoint is suitable for file access or user-file transfer. See docs/SECURITY.md.
