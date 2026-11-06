# Architecture

## Platform applications
- Android: Kotlin + Jetpack Compose.
- Windows: C# + .NET 10 + WPF.
- Both applications implement the wire contract in shared/protocol/PROTOCOL.md.

## Current Phase 1 diagnostic path
1. Windows starts a TCP diagnostic listener on port 45821 and a UDP discovery listener on port 45820.
2. Android broadcasts a discovery request on the local IPv4 network.
3. Windows replies with its device name and TCP port.
4. Android opens TCP to the response source address.
5. Android sends HELLO; Windows returns WELCOME.
6. Android sends PING; Windows returns PONG and Android displays round-trip time.
7. This exchange is plaintext and unauthenticated. It is not a secure session and does not permit file access.

## Next: QR pairing and authenticated session
1. Windows creates or loads a stable TLS certificate and displays a QR code containing device identity, endpoint hint, certificate SHA-256 fingerprint, and a short-lived one-time nonce.
2. Android scans the QR code, validates schema and expiry, connects, and pins the TLS certificate fingerprint.
3. Android presents its public-key identity over TLS.
4. Windows asks the user to approve the Android device; Android confirms the Windows identity.
5. Both sides complete a challenge/proof exchange and persist trust only after successful confirmation.
6. Trusted devices can be revoked. No filesystem API is enabled until this milestone is complete.

The pairing message sequence, expiry, replay rules, and QR schema are specified in shared/protocol/PROTOCOL.md. Security requirements are in docs/SECURITY.md.

## Later architecture
- Transfer: bounded streaming, file manifests, acknowledgements, resume, SHA-256.
- Sharing: Windows-selected roots with per-share read/write/delete/stream authorization.
- Media: separate UPnP AV / DLNA discovery and HTTP byte-range streaming service.

## Network caveats
UDP broadcast can be blocked by guest Wi-Fi, client isolation, VPNs, host firewalls, or hotspot implementations. QR pairing does not bypass network isolation; the devices still need a reachable local route.
