# Security Design

## Current security posture
The implementation has a plaintext TCP diagnostic on port 45821 and a TLS endpoint on port 45822. UDP discovery and the plaintext HELLO/WELCOME/PING/PONG exchange do not authenticate either device. TLS supports first-time pairing and fresh challenge-proof authentication for already trusted Android identities. Windows checks revocation before session establishment and before each folder listing, download, or upload request. Android can browse explicitly shared Windows folders, download one file, and upload one file to a Write-enabled share over authenticated TLS. Downloads and uploads use fixed-length raw binary TLS bodies with bounded 256 KiB buffers and SHA-256 verification. Uploads are written to a unique temporary file in the target folder, flushed, rechecked against current trust and Write permission, and moved into place without overwriting an existing file. Android uses a user-selected SAF source and destination. Delete, streaming, multi-file queue, pause/resume, cancellation UI, and Android management of multiple Windows trust records are not implemented. Android can explicitly revoke its own paired identity using an authenticated `REVOKE_SELF` request; Windows persists the revocation and Android removes its local Windows pin only after receiving the matching acknowledgement.
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
- The guard is wired to authenticated directory listing, download, and upload. Upload rechecks trust and Write permission, validates path containment and reparse points, stages a uniquely named temporary file under the destination folder, verifies size and SHA-256, rechecks authorization, and finalizes without overwrite. The current check/open sequence is not a complete defense against filesystem races; use handle-based/reparse-safe access before production use. Delete/stream operations are not exposed.

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

The Windows TLS listener presents this certificate. Android connects only after explicit user action and pins the exact SHA-256 fingerprint from the QR. Android sends a P-256 public key generated in Android Keystore. Windows reserves the current 256-bit nonce, asks the user to approve the device, sends a fresh challenge, and verifies the ECDSA signature. On success, Windows consumes the nonce and persists the Android public key; Android stores the Windows certificate pin only after receiving a matching final approval response. The pending nonce is memory-only and invalidated on refresh, expiry, or app shutdown. The separate TCP diagnostic listener on port 45821 remains plaintext. Windows provides explicit trusted-device revocation. Android also exposes a confirmed Disconnect & Forget action: it authenticates with the saved pin and Android Keystore key, asks Windows to revoke that exact identity, validates the acknowledgement, and only then removes the local Windows pin. If Windows is unreachable, the action fails without silently clearing local trust. Android management of multiple Windows trust records and file-share authorization controls are still pending. A repeated pairing attempt for an already trusted device is accepted only when the public key is byte-for-byte identical and Windows user approval plus a fresh challenge proof succeed.
