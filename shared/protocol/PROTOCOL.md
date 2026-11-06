# DroidShare-WiFi Local Protocol (v1 draft)

## Status
The current implementation supports UDP discovery, certificate-pinned TLS, first-time pairing, authenticated trusted-session re-establishment, Windows shared-folder listing, and nested directory metadata browsing on Android. Android supports clickable breadcrumbs and back navigation. File upload/download and Android trust management are not implemented. No file content read/write/delete/stream operation is exposed.

## Existing diagnostic transport
- Discovery: IPv4 UDP broadcast on port 45820.
- Diagnostic TCP session: port 45821 (plaintext; connectivity testing only).
- TLS session: port 45822 (certificate-pinned pairing, trusted-session authentication, and read-only folder metadata browsing).
- Control messages: UTF-8 JSON, one object per line, maximum 16 KiB.
- Protocol version: integer 1.

### Discovery
Android broadcasts the exact UTF-8 payload:

    DROIDSHARE_DISCOVER_V1

Windows replies by unicast with JSON containing type DROIDSHARE_DEVICE, protocolVersion 1, deviceName, deviceId (first 32 lowercase hex characters of its certificate fingerprint), tlsPort 45822, and tcpPort 45821. All response fields remain untrusted discovery hints; Android must pin the TLS certificate before using the identity. UDP discovery is untrusted metadata only. It is never proof of identity and must not authorize pairing or file access.

### Diagnostic handshake
Android sends HELLO and Windows returns WELCOME. Android then sends PING and Windows returns PONG. This exchange is plaintext and unauthenticated. The measured round-trip time is a connectivity diagnostic, not a throughput benchmark. The server applies a five-second idle timeout.

## TLS transport and pairing (implemented; file access not active)

- Windows listens on TCP port 45822 using its persisted self-signed server certificate.
- The pairing QR advertises this TLS endpoint and the SHA-256 fingerprint of the DER certificate.
- Android connects only after the user taps **Connect securely** and validates the exact certificate SHA-256 fingerprint from the QR.
- The TLS stream uses TLS 1.2 or 1.3; no global trust-all handler is used.
- Android sends `PAIR_HELLO` with its UUID, device name, QR nonce, and P-256 public key from Android Keystore.
- Windows atomically reserves the current QR nonce, rejects expired/replayed/replaced nonces, and asks the Windows user for explicit approval.
- Windows sends a fresh 256-bit challenge. Android signs it using its Keystore private key with SHA256withECDSA and sends the ASN.1 DER-encoded ECDSA signature. Windows verifies it against the supplied P-256 public key using the RFC 3279 DER sequence format (not the .NET P1363 default).
- On successful proof, Windows consumes the nonce and stores the Android public key. It returns `PAIR_APPROVED`; Android persists the Windows certificate pin only after validating that final response.
- The nonce registry is memory-only; refresh/restart invalidates pending QR state. The nonce can be reserved by only one concurrent pairing attempt.
- The old plaintext diagnostic endpoint remains separate on port 45821.

## Secure pairing design and current limits

### Roles and trust model
- Windows is the pairing host and displays a QR code.
- Android scans the QR code and initiates the connection.
- Windows explicitly approves the Android device. Android also confirms the Windows identity.
- QR pairing is for first-time trust and endpoint hints. It does not bypass Wi-Fi client isolation, firewall rules, or routing restrictions.
- No filesystem operation is available until the authenticated session and trust record are established.

### Windows identity and TLS
1. Windows creates a stable device identifier and self-signed TLS server certificate on first launch.
2. The certificate private key is stored in the Windows current-user certificate store and is never exported into the QR payload.
3. The certificate SHA-256 fingerprint is calculated from the DER-encoded certificate.
4. Windows presents this certificate on the TLS listener. Android compares its SHA-256 fingerprint with the fingerprint scanned from the QR code.
5. A certificate change is a trust change and requires explicit re-pairing. Never silently accept a new fingerprint for an already trusted device.

### QR payload
The QR payload is UTF-8 JSON with a versioned envelope. Example:

    {
      "type": "DROIDSHARE_PAIR",
      "protocolVersion": 1,
      "deviceId": "stable-windows-device-id",
      "deviceName": "DESKTOP",
      "host": "192.168.1.20",
      "port": 45822,
      "certificateSha256": "lowercase-hex-sha256-of-certificate-der",
      "nonce": "base64url-encoded-256-bit-random-value",
      "expiresAt": "2026-11-06T12:02:00Z"
    }

- Generate the nonce using a cryptographically secure random number generator.
- Pairing window target: 120 seconds.
- Keep nonce state in memory only. It is single-use and invalidated on expiry, successful consumption, cancellation, or app shutdown.
- QR contains no private key, permanent password, reusable device secret, or filesystem path.
- The host address is only a connection hint; trust it only after TLS pin verification.
- Users never type an address or port.

### Pairing exchange
After scanning, Android validates the QR schema and expiry, connects using TLS, and verifies the certificate fingerprint before sending pairing messages.

1. Android sends PAIR_HELLO with protocol version, QR nonce, Android device ID, public-key algorithm, and Android public key.
2. Windows validates nonce, expiry, pending state, and request schema; invalid attempts are rate-limited.
3. Windows displays the Android device identity and public-key fingerprint and asks the user to approve.
4. Windows sends a fresh random challenge. Android signs it with its device private key and returns PAIR_PROOF.
5. Windows verifies proof of possession. On approval, it atomically consumes the nonce and stores the Android public key as a trusted device.
6. Android stores the Windows device ID and pinned certificate fingerprint only after receiving the final successful pairing response.
7. Both sides show an explicit paired state. Failed, rejected, expired, or interrupted flows leave no trusted-device record.

The Android implementation uses an Android Keystore P-256 signing key. Windows stores the public key and metadata in a LocalAppData JSON file and provides a paired-device manager with explicit revocation. Android stores the Windows device ID and certificate pin in app-private preferences. Android-side trusted-device management is still required. If Windows already has the same device ID and identical public key, it allows a new explicit approval and challenge proof to recover Android's missed final response; a different key under the same active device ID is rejected. Never log QR contents, nonce values, private keys, or proof payloads.

### Replay, abuse, and lifecycle
- Nonces are random, expire, and are consumed atomically once.
- Reject expired, malformed, replayed, and unknown nonces.
- Limit concurrent pending requests and throttle invalid attempts.
- Restart invalidates all pending QR codes.
- Windows supports explicit trusted-device revocation. Revocation blocks future authenticated sessions.
- Re-pairing is explicit; never silently replace an existing trusted identity.

## Authenticated trusted sessions and folder browsing
- UDP discovery now includes the stable Windows device ID and TLS port 45822; these fields are untrusted hints only.
- After first-time pairing, Android stores the Windows certificate fingerprint and its own Keystore identity.
- For reconnect, Android pins the stored certificate, sends `SESSION_HELLO` with its device ID and public key, receives a fresh 256-bit `SESSION_CHALLENGE`, and signs it using the Android Keystore key in `SESSION_PROOF`.
- Windows checks the active trusted-device record and exact public key before issuing the challenge, verifies the proof, then re-checks trust before returning `SESSION_READY`.
- `SESSION_READY` returns only shares with Read permission. It includes opaque share IDs, display names, and permission flags; absolute Windows paths are never sent.
- Android requests a directory listing with `LIST_DIRECTORY` (`shareId`, relative `path`). Windows re-checks trust and Read permission, resolves the path beneath the configured share root, skips reparse points, and returns up to 500 entry names/types/sizes/timestamps, with the serialized response capped at 12 KiB in `DIRECTORY_LIST`. Android validates the relative path, supports nested folder navigation, and displays clickable root/ancestor breadcrumbs plus back navigation. Each navigation currently establishes a fresh authenticated TLS session.
- Trust is checked again before each listing request so a revoked device cannot continue browsing on an existing session. Session connections have a 45-second server-side lifetime.
- This is metadata browsing only. No file contents are transferred, and upload/download/write/delete/stream APIs remain disabled.
- The Windows path guard remains a lexical and reparse-point defense; before file content operations are enabled, use handle-based/reparse-safe operations to mitigate TOCTOU races.

## Compatibility and future transfer protocol
Any breaking wire-format change requires a protocol version change and updates to both platforms.

Before file transfer is enabled:
- Add Android-side trust management and physical-device tests for reconnect and revocation.
- Define length-prefixed control/data framing and transfer IDs.
- Add manifests, bounded chunks, durable acknowledgements, pause/resume, and SHA-256 verification.
- Enforce selected-share authorization and canonical path containment on Windows.
- Test framing limits, malformed messages, nonce expiry/replay, certificate pin mismatch, and revocation/reconnect behavior.
