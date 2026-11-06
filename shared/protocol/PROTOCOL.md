# DroidShare-WiFi Local Protocol (v1 draft)

## Status
The current implementation supports plaintext discovery/diagnostics plus a certificate-pinned TLS diagnostic probe. Secure pairing is still not implemented. No filesystem operation or file transfer may be exposed.

## Existing diagnostic transport
- Discovery: IPv4 UDP broadcast on port 45820.
- Diagnostic TCP session: port 45821 (plaintext; connectivity testing only).
- TLS diagnostic session: port 45822 (certificate pinning; no pairing or file access).
- Control messages: UTF-8 JSON, one object per line, maximum 16 KiB.
- Protocol version: integer 1.

### Discovery
Android broadcasts the exact UTF-8 payload:

    DROIDSHARE_DISCOVER_V1

Windows replies by unicast with JSON containing type DROIDSHARE_DEVICE, protocolVersion 1, deviceName, and tcpPort 45821. UDP discovery is untrusted metadata only. It is never proof of identity and must not authorize pairing or file access.

### Diagnostic handshake
Android sends HELLO and Windows returns WELCOME. Android then sends PING and Windows returns PONG. This exchange is plaintext and unauthenticated. The measured round-trip time is a connectivity diagnostic, not a throughput benchmark. The server applies a five-second idle timeout.

## TLS diagnostic probe (implemented; pairing not active)

- Windows listens on TCP port 45822 using its persisted self-signed server certificate.
- The pairing QR advertises this TLS endpoint and the SHA-256 fingerprint of the DER certificate.
- Android connects only after the user taps **Connect securely**.
- Android validates the certificate validity period and compares the exact SHA-256 fingerprint before sending `SECURE_HELLO`. It does not use a global trust-all certificate handler.
- Windows replies `TLS_READY` over the encrypted stream.
- This proves that the endpoint presented the certificate encoded in the scanned QR. It does not prove Android identity, consume the QR nonce, establish a paired-device record, or authorize filesystem access.
- The old plaintext diagnostic endpoint remains separate on port 45821.

## Secure pairing design (partially scaffolded; no active pairing yet)

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

The exact key algorithm and platform key-storage APIs must be validated against supported OS versions before implementation. Prefer platform-protected private-key storage. Never log QR contents, nonce values, private keys, or proof payloads.

### Replay, abuse, and lifecycle
- Nonces are random, expire, and are consumed atomically once.
- Reject expired, malformed, replayed, and unknown nonces.
- Limit concurrent pending requests and throttle invalid attempts.
- Restart invalidates all pending QR codes.
- Windows supports explicit trusted-device revocation. Revocation blocks future authenticated sessions.
- Re-pairing is explicit; never silently replace an existing trusted identity.

## Compatibility and future transfer protocol
Any breaking wire-format change requires a protocol version change and updates to both platforms.

Before file transfer is enabled:
- Complete TLS, QR pairing, device identity, trust storage, and revocation.
- Define length-prefixed control/data framing and transfer IDs.
- Add manifests, bounded chunks, durable acknowledgements, pause/resume, and SHA-256 verification.
- Enforce selected-share authorization and canonical path containment on Windows.
- Test framing limits, malformed messages, nonce expiry/replay, certificate pin mismatch, and revocation/reconnect behavior.
