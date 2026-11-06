# Security Design

## Current security posture
The current Phase 1 implementation is a plaintext, unauthenticated LAN diagnostic only. UDP discovery and the HELLO/WELCOME/PING/PONG exchange do not authenticate either device. Do not use this build to expose folders or transfer files.

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
No file listing, upload, download, write, delete, or media-stream request may be served before TLS is established, the peer identity is authenticated, the peer is trusted, the requested operation is authorized by an explicitly configured Windows share, and the resolved path is verified to remain within the selected share root.

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


## Windows identity and QR preview implementation
The Windows app now creates or loads a self-signed server-authentication certificate in the CurrentUser personal certificate store. Its private key is not included in the QR. The UI displays the SHA-256 fingerprint and generates a QR preview containing a random 256-bit nonce, a 120-second expiry, device identity, and the selected local IPv4 endpoint hint.

This is preview-only. The existing TCP listener is still plaintext; it does not validate or consume the QR nonce and does not perform TLS certificate presentation. The UI explicitly warns users not to scan the preview. Do not treat QR generation as completed pairing or enable file access until the TLS and pairing protocol is implemented and tested.
