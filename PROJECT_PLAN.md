# DroidShare-WiFi — Project Plan

## 1. Product vision
Build a fast, secure, easy-to-use local-network sharing platform for Android and Windows. The product should transfer files in both directions, expose only user-selected Windows folders to the Android app, and later support UPnP AV / DLNA media discovery and streaming.

The core experience is automatic: users should not type IP addresses, ports, subnet masks, or other network settings. When automatic discovery is insufficient or a device needs to be trusted, QR pairing is the user-facing fallback.

## 2. Confirmed scope and decisions

### Platforms
- Android application: Kotlin, Jetpack Compose.
- Windows application: C#/.NET 10, WPF.
- One GitHub monorepo: `abhijitrao/DroidShare-WiFi`.
- Android minimum OS version: **to be confirmed before setting minSdk**. Android 10+ was proposed, but is not yet a locked decision.

### Connectivity
- Support devices connected to the same Wi-Fi router, preferring 5 GHz when available.
- Also support a local hotspot topology when the devices can communicate over it.
- Detect available network interfaces and discover peers automatically.
- Do not require manual IP or port configuration.
- Use QR pairing for first-time trust and as a fallback containing short-lived connection hints.
- Do not assume Android or Windows can silently turn on or join a hotspot. OS-level user action/permission may be necessary.
- Internet access is not required for local transfer. Router client isolation, guest-network isolation, firewall policy, and hotspot restrictions can prevent peer-to-peer communication; explain these conditions clearly.

### Version 1.0 — File transfer
- Android → Windows and Windows → Android.
- Single files, multiple files, and nested folders.
- Transfer queue and progress, current/average speed, remaining bytes/time.
- Pause, cancel, and resume interrupted transfers.
- Streaming I/O with bounded buffers; never read an entire large file into RAM.
- SHA-256 verification after completion.
- Duplicate-name choices: ask, rename, skip, or replace with explicit confirmation.
- QR-based pairing and authenticated encrypted sessions.
- Connection and transfer history.

### Version 1.1 — Media streaming
- UPnP AV / DLNA support (not merely generic UPnP).
- SSDP discovery and UPnP AV ContentDirectory integration as applicable.
- Stream media over HTTP(S) with byte-range support for seeking.
- Browse media libraries and play supported media on the receiving device.
- Keep DLNA media discovery/streaming separate from the high-speed transfer engine.
- Evaluate renderer/player options on each platform; do not promise universal codec support.

### Version 1.2 — Windows shared folders / remote file access
- Windows user explicitly chooses which directories to share.
- Android can browse only those selected roots.
- Per-share permissions: Read, Write, Delete, Stream.
- Default to Read + Stream; Write and Delete are opt-in.
- Android can download files, upload files, create folders where permitted, and stream media directly.
- Enforce path containment on the Windows server; reject traversal, symlink/reparse-point escapes, and unauthorized operations.
- App-managed sharing is primary. Optional access to existing SMB2/SMB3 shares can be evaluated separately; it is not a dependency.

### Later enhancements
- Wi-Fi Direct only after validating platform/device compatibility and user experience.
- More advanced throughput tuning based on measured results.
- Optional simultaneous transfer tuning, only if benchmarks show a benefit.

## 3. Architecture

### Monorepo layout
```text
DroidShare-WiFi/
├── AGENTS.md
├── PROJECT_PLAN.md
├── README.md
├── android/
│   └── app/
├── windows/
│   ├── WiFiTransfer.App/
│   ├── WiFiTransfer.Core/
│   ├── WiFiTransfer.Network/
│   └── WiFiTransfer.Tests/
├── shared/
│   └── protocol/
│       ├── PROTOCOL.md
│       └── discovery.md
└── docs/
    ├── ARCHITECTURE.md
    ├── SECURITY.md
    └── TESTING.md
```

### Logical components
1. **Discovery** — local-network UDP discovery; interface-aware and resilient to network changes.
2. **Pairing and identity** — QR-assisted first trust, short-lived pairing tokens, device identity, revocation.
3. **Session transport** — authenticated TLS session over TCP, bounded framing, cancellation and backpressure.
4. **Transfer engine** — file manifests, chunk streaming, acknowledgements, pause/resume, SHA-256.
5. **Storage adapters** — Android Storage Access Framework and Windows filesystem access.
6. **Share manager** — explicitly selected Windows roots and per-share authorization.
7. **Media service** — later UPnP AV / DLNA discovery and media streaming.
8. **UI** — Compose on Android and WPF on Windows.

### Network design notes
- A TCP session can be full-duplex, but protocol framing and independent transfer IDs are required to avoid interleaving ambiguity.
- UDP discovery is a convenience, not a security boundary. Every connection must authenticate before exposing files or accepting commands.
- QR payload should carry a device identifier, endpoint candidates, protocol version, expiry, and one-time pairing nonce; never a long-lived private key or reusable bearer secret.
- The Windows listener should bind only to appropriate active interfaces and use a narrowly scoped Windows Firewall rule. Do not expose it to public networks by default.
- Hotspot support depends on the hotspot host's routing/isolation behavior and OS APIs. If automatic discovery fails, QR can provide endpoint hints only when the network route is actually reachable.

## 4. Protocol principles
- Version every handshake and message envelope.
- Use explicit message framing (length prefix + message type/version/transfer ID).
- Separate control messages from file payload frames logically.
- Use bounded chunks and buffers; benchmark 256 KiB, 1 MiB, and 4 MiB rather than assuming one is optimal.
- Acknowledge durable chunk offsets; resume from the last acknowledged offset, not merely bytes written to a transient buffer.
- Store transfer metadata safely and expire abandoned sessions.
- Verify final file size and SHA-256 before marking complete.
- Treat filenames, metadata, and all remote paths as untrusted input.

## 5. Development phases and acceptance criteria

### Phase 0 — Repository foundation
- Add repository instructions, project plan, architecture/security/protocol docs.
- Create Android and Windows project scaffolds.
- Document build prerequisites and local run steps.
**Exit:** a clean, understandable monorepo with documented build commands.

### Phase 1 — Connection foundation
- [x] Windows TCP listener and status UI.
- [x] Android TCP client and connection status UI.
- Protocol version handshake and ping/pong diagnostic.
- Automatic local-network discovery.
- QR pairing for first trust/fallback.
- Test on same router and hotspot topology.
**Exit:** both apps establish an authenticated local session without manual IP/port entry; network limitations are surfaced clearly.

### Phase 2 — Bidirectional file transfer
- Single/multiple file streaming in both directions.
- Progress, speed, cancellation, and transfer queue.
- Large-file and memory-pressure tests.
**Exit:** repeatable transfers in both directions with bounded memory use.

### Phase 3 — Folder transfer
- Recursive manifest, directory creation, conflict policy.
- Safe path validation and partial-failure reporting.
**Exit:** nested folder trees transfer without path escape or silent data loss.

### Phase 4 — Resume and integrity
- Durable acknowledgements and persisted offsets.
- Reconnect and resume after app/network interruption.
- SHA-256 verification and safe finalization.
**Exit:** interrupted large files resume correctly and completed files verify.

### Phase 5 — Security and release hardening
- QR pairing expiry/replay protection, device trust/revocation.
- TLS certificate identity/pinning strategy.
- Windows Firewall UX, Android background transfer handling.
- Logging, diagnostics, installer/APK packaging.
**Exit:** documented security review and reproducible release builds.

### Phase 6 — Performance optimization
- Benchmark same-router 5 GHz and hotspot scenarios.
- Test different buffer sizes, chunk sizes, file counts, and device combinations.
- Compare sequential vs bounded parallel transfers.
- Record throughput, CPU, memory, battery, and failure rates.
**Exit:** published reproducible benchmark results; optimizations justified by measurements.

### Phase 7 — UPnP AV / DLNA
- SSDP discovery, device/media-server discovery.
- ContentDirectory browsing.
- HTTP byte-range streaming and player integration.
**Exit:** supported media can be browsed and streamed locally with seek support.

### Phase 8 — Remote shared folders
- Windows share selection UI and permission management.
- Android remote browser, upload, download, folder creation, streaming.
- Path containment and authorization tests.
**Exit:** Android can access only explicitly shared folders and only permitted operations.

## 6. Performance and test matrix
Use the same devices and Wi-Fi environment when comparing:
- Same 5 GHz router (primary target).
- Laptop hotspot.
- Android hotspot.
- Different Wi-Fi signal strengths and channel conditions.
- Guest/client-isolated Wi-Fi (expected to fail gracefully).

Test payloads:
- 100 MB, 1 GB, 5 GB, and 10 GB files.
- 1,000 small files and deeply nested folders.
- Multiple queued files.
- Disconnect/reconnect during transfer.
- Low storage, permission denial, duplicate names, app restart, and device sleep.

Report measured MB/s; do not advertise theoretical Wi-Fi link rates as file-transfer throughput. Internet bandwidth is irrelevant to local transfer speed.

## 7. Security and privacy requirements
- No cloud upload or telemetry by default.
- Pairing required before file access.
- TLS for authenticated sessions.
- Short-lived QR pairing material and replay protection.
- Explicit Windows share roots and per-operation permissions.
- Path traversal and symlink/reparse-point protections.
- No silent overwrite/delete.
- Keep secrets out of logs and repository.
- Provide a clear disconnect and device-revoke action.

## 8. Current status
- Product name and repository: DroidShare-WiFi — https://github.com/abhijitrao/DroidShare-WiFi
- Monorepo: confirmed.
- Platform stack: Kotlin/Compose and C#/.NET 10/WPF.
- Connectivity UX: automatic discovery; QR pairing when needed; no manual IP/port configuration.
- Shared folders: user-selected roots only, with permissions.
- Router/hotspot: both supported where local peer connectivity is available.
- UPnP AV / DLNA and remote shared-folder access are planned after the transfer foundation.
- Phase 1 implementation now includes Windows WPF UDP discovery/TCP diagnostic host, Android Compose discovery/TCP client, HELLO/WELCOME handshake, PING/PONG round-trip diagnostic, protocol documentation, and CI. GitHub Actions run 10 passed for both Android and Windows builds. Physical-device interoperability and QR pairing remain pending. This is not yet a secure production session or file transfer.

## 9. Decision log
- Prefer 5 GHz router as the primary performance test environment, but do not hard-code or require 5 GHz.
- Support hotspot connectivity as an alternative.
- Do not require users to choose IP/port or configure network parameters.
- QR is for pairing/trust and connection hints, not a workaround for network isolation.
- Windows sharing is app-managed and limited to explicitly selected folders.
- DLNA is a media feature; the custom transfer protocol remains responsible for file transfer.
