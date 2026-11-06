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

## TLS pairing and authenticated sessions (implemented)
1. Windows creates or loads a stable TLS certificate and displays a QR code containing device identity, endpoint hint, certificate SHA-256 fingerprint, and a short-lived nonce.
2. Android scans the QR code, validates schema and expiry, and waits for the user to tap **Connect securely**.
3. Android pins the exact certificate fingerprint, presents its Android Keystore P-256 public key, and proves possession after explicit Windows approval.
4. Windows stores the trusted Android identity; Android persists the Windows certificate pin only after validating the final approval response.
5. On reconnect, Android and Windows perform a fresh challenge/proof exchange. Windows checks revocation before the session and before every directory listing.

The pairing message sequence, expiry, replay rules, and QR schema are specified in shared/protocol/PROTOCOL.md. Security requirements are in docs/SECURITY.md.

## Windows shared-folder configuration foundation
- The Windows app now provides a dedicated shared-folder manager with explicit folder selection, removal, and per-share Read, Write, Delete, and Stream toggles.
- New shares default to Read + Stream; Write and Delete are opt-in. Removing a share never deletes its contents.
- Share definitions are persisted under the current user's LocalAppData application directory.
- `SharedFolderStore.ResolveAuthorizedPath` is the authorization/path-containment primitive for future file APIs. It rejects rooted paths, traversal segments, paths outside the selected root, and existing reparse points in the root ancestry or requested path.
- The authenticated network API exposes only Read-enabled shares and bounded directory metadata. Android supports root and nested folder browsing with clickable breadcrumbs and back navigation. No file content is read or transferred yet; upload, download, delete, and stream APIs remain disabled. Filesystem operations must revalidate authorization and path safety immediately before use; handle-based/reparse-safe operations are required before content operations to address filesystem races.

## Authenticated sessions and remote folder metadata browsing
- UDP discovery advertises the stable Windows certificate-derived device ID and TLS port as untrusted connection hints.
- Android reconnects to a previously paired Windows host using the saved certificate pin and Android Keystore P-256 identity. Windows issues a fresh challenge and verifies proof of possession for each TLS session.
- Windows checks the active trusted-device record before and after proof verification and before each directory listing request, so revocation prevents further browsing.
- `SESSION_READY` exposes only shares with Read permission and never exposes absolute Windows paths.
- `LIST_DIRECTORY` accepts a validated relative path beneath the selected share and returns a bounded metadata listing (maximum 500 entries); reparse-point entries are skipped. Android navigates nested directories and supports root/ancestor breadcrumbs and back navigation. Each navigation currently opens a fresh authenticated TLS session.
- Android shows shared folder names, permissions, and root entry metadata in a modern card-based UI. This is metadata browsing only; no file bytes are read or sent.

## Later architecture
- Nested directory navigation and breadcrumb/back navigation.
- Transfer: bounded streaming, file manifests, acknowledgements, resume, SHA-256.
- Sharing: enforce per-share read/write/delete/stream authorization for every future operation.
## Network caveats
UDP broadcast can be blocked by guest Wi-Fi, client isolation, VPNs, host firewalls, or hotspot implementations. QR pairing does not bypass network isolation; the devices still need a reachable local route.
