# DroidShare-WiFi Local Protocol (v1 draft)

## Status
Draft for Phase 1 connection diagnostics. This protocol is not yet the production file-transfer protocol. Phase 1 must not expose filesystem operations or transfer user files.

## Transport
- Discovery: IPv4 UDP broadcast, destination port **45820**.
- Session: TCP, destination port **45821**.
- TCP control messages: UTF-8 JSON, one JSON object per line (newline-delimited).
- Maximum control line: 16 KiB. Implementations must reject oversized messages.
- Protocol version: integer `1`.

## Discovery
Android broadcasts the exact UTF-8 payload:

```text
DROIDSHARE_DISCOVER_V1
```

Windows replies by unicast to the sender with one JSON object:

```json
{
  "type": "DROIDSHARE_DEVICE",
  "protocolVersion": 1,
  "deviceName": "DESKTOP",
  "tcpPort": 45821
}
```

The UDP response is discovery metadata only. It is not proof of identity and must never authorize file access.

## Phase 1 TCP diagnostic handshake
Android opens TCP to the UDP response source address and advertised port, then sends:

```json
{"type":"HELLO","protocolVersion":1,"client":"Android"}
```

Windows replies:

```json
{"type":"WELCOME","protocolVersion":1,"server":"DroidShare-WiFi"}
```

Any unsupported message type or protocol version must be rejected. Close idle diagnostic connections after a short timeout.

## Production protocol requirements (later phase)
Before file transfer or remote folder access is enabled:
- Add authenticated pairing and TLS-protected sessions.
- Use short-lived QR pairing tokens with expiry and replay protection.
- Add message IDs / transfer IDs and bounded payload framing.
- Add file manifests, chunk offsets, durable acknowledgements, pause/resume, and SHA-256 verification.
- Enforce selected-share authorization and canonical path containment on Windows.
- Never trust a UDP discovery packet as authentication.

## Compatibility
Any breaking wire-format change requires a protocol version change and updates to both platform implementations.
