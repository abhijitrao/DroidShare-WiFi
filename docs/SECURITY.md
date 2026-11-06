# Security Design

## Current security posture
The implementation has a plaintext TCP diagnostic on port 45821 and a TLS endpoint on port 45822. UDP discovery and the plaintext HELLO/WELCOME/PING/PONG exchange do not authenticate either device. TLS supports first-time pairing and fresh challenge-proof authentication for already trusted Android identities. Windows checks revocation before session establishment and before each folder listing or file-download request. Android can browse explicitly shared Windows folders and download one file at a time over authenticated TLS. Windows checks Read permission and resolves each requested relative path beneath the configured share root; file bytes are sent in bounded 8 KiB chunks. Android writes to a user-selected document destination and verifies the transmitted byte count and SHA-256. Upload, write, delete, streaming, multi-file queue, pause/resume, cancellation UI, and Android-side trust management are not implemented.
## Security boundaries
- UDP discovery is untrusted input and provides connection hints only.
- A QR code is a short-lived pairing bootstrap, not a permanent credential.
- TLS certificate pinning authenticates the Windows endpoint against the fingerprint scanned by Android.
- Pairing approval is explicit on both devices.
- A trusted device identity is represented by a public key; private keys remain in platform-protected storage.
- Pairing alone does not grant access to arbitrary Windows paths.

## Pairing requirements
1. Use a cryptographically secure 256-bit random nonce.
2. Expire a QR pairing window after approximately 120 seconds.
3. Keep pending nonce state in memory only; invalidate on expiry, use, cancel, or restart.
4. Bind the exchange to a TLS session whose server certificate fingerprint matches the QR.
5. Require Windows approval and Android confirmation.
6. Verify proof of possession of the Android private key before storing trust.
7. Consume a nonce atomically and reject subsequent attempts.
8. Rate-limit failed attempts and cap pending requests.
9. Store trusted public-key identities and support explicit revocation.
10. Never log QR payloads, nonces, private keys, or proof material.

## TLS identity
- Windows uses a stable self-signed server certificate; protect its private key using the current-user certificate store.
- QR carries only the SHA-256 fingerprint of the DER certificate.
- Android pins the scanned fingerprint during first pairing and persists the pin only after successful approval.
- A changed fingerprint requires explicit re-pairing.

## File access gate
No file listing, upload, download, write, delete, or media-stream request may be served before TLS is established, the peer identity is authenticated for the current session, the peer is trusted and not revoked, the requested operation is authorized by an explicitly configured Windows share, and the resolved path is verified to remain within the selected share root.

## Windows share configuration foundation
- Share definitions are local configuration only and are stored in the current user's LocalAppData directory.
- New shares default to Read + Stream. Write and Delete require explicit opt-in; Write/Delete cannot be enabled unless Read is also enabled.
- Removing a share only removes its configuration; it never deletes files.
- The current path guard rejects rooted client paths, `..` traversal, canonical paths outside the share root, and existing reparse points in the root ancestry/requested path.
- The guard is wired to authenticated directory listing and single-file download. Download rechecks trust, Read permission, canonical path containment, and reparse-point attributes before opening the file. The current check/open sequence is not a complete defense against filesystem races; use handle-based/reparse-safe access before production use. Upload/write/delete/stream operations are not exposed.

## Threats to test
- Forged UDP discovery response.
- QR payload tampering or malformed data.
- Expired and replayed pairing nonce.
- TLS certificate fingerprint mismatch.
- Unauthorized or revoked device.
- Two clients racing to consume one nonce.
- Repeated invalid pairing attempts.
- App restart while a QR code is active.
- Path traversal and Windows reparse-point/symlink escape before file sharing is enabled.


## Windows identity, QR, and authenticated pairing implementation
The Windows app creates or loads a self-signed server-authentication certificate in the CurrentUser personal certificate store. Its private key is not included in the QR. The UI displays the SHA-256 fingerprint and generates a QR containing a random 256-bit nonce, a 120-second expiry, device identity, and the TLS endpoint hint on port 45822.

The Windows TLS listener presents this certificate. Android connects only after explicit user action and pins the exact SHA-256 fingerprint from the QR. Android sends a P-256 public key generated in Android Keystore. Windows reserves the current 256-bit nonce, asks the user to approve the device, sends a fresh challenge, and verifies the ECDSA signature. On success, Windows consumes the nonce and persists the Android public key; Android stores the Windows certificate pin only after receiving a matching final approval response. The pending nonce is memory-only and invalidated on refresh, expiry, or app shutdown. The separate TCP diagnostic listener on port 45821 remains plaintext. Windows provides explicit trusted-device revocation. Android-side trust management and file-share authorization are still pending; no file access is enabled. A repeated pairing attempt for an already trusted device is accepted only when the public key is byte-for-byte identical and Windows user approval plus a fresh challenge proof succeed.
