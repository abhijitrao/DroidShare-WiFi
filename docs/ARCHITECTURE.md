# Architecture

## Platform applications
- Android: Kotlin + Jetpack Compose.
- Windows: C# + .NET 10 + WPF.
- Both applications implement the wire contract in `shared/protocol/PROTOCOL.md`.

## Phase 1 connection path
1. Windows starts a TCP diagnostic listener on port 45821 and a UDP discovery listener on port 45820.
2. Android broadcasts a discovery request on the local IPv4 network.
3. Windows replies to the sender with its device name and TCP port.
4. Android opens a TCP connection to the response source address.
5. Android sends a protocol-versioned HELLO line; Windows returns WELCOME.
6. Both UIs show connection status. This initial diagnostic handshake is not a secure file-transfer session.

## Later architecture
- Pairing/security: QR-assisted first trust, short-lived pairing nonce, TLS, device revocation.
- Transfer: bounded streaming, file manifests, acknowledgements, resume, SHA-256.
- Sharing: Windows-selected roots with per-share read/write/delete/stream authorization.
- Media: separate UPnP AV / DLNA discovery and HTTP byte-range streaming service.

## Network caveats
UDP broadcast can be blocked by guest Wi-Fi, client isolation, VPNs, host firewalls, or hotspot implementations. Discovery should eventually support additional mechanisms (such as mDNS and QR endpoint hints). QR pairing does not bypass network isolation; the devices still need a reachable local route.
