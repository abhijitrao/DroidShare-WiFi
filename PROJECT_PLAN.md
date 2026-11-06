# DroidShare-WiFi — Project Plan

## 1. Product vision
Build a secure local-network sharing platform for Android and Windows. Transfer files in both directions, expose only user-selected Windows folders, and later support UPnP AV / DLNA media discovery and streaming. Users should not type IP addresses, ports, subnet masks, or network parameters.

## 2. Confirmed scope

### Platforms
- Android: Kotlin + Jetpack Compose.
- Windows: C#/.NET 10 + WPF.
- Monorepo: abhijitrao/DroidShare-WiFi.
- Current Android minSdk 26 is provisional; confirm before release.

### Connectivity
- Same Wi-Fi router, preferring 5 GHz where available.
- Local hotspot where peer-to-peer communication is permitted.
- Automatic discovery and QR pairing for first-time trust or fallback endpoint hints.
- No promise of silently enabling/joining hotspots.
- No internet required after devices are on a mutually reachable LAN. Client isolation, guest networks, firewalls, and hotspot policy can block peer traffic.

### Version 1.0 — File transfer
- Android ↔ Windows; single files, multiple files, and nested folders.
- Queue, progress, speed, remaining bytes/time, cancellation, pause, and resume.
- Bounded streaming I/O; SHA-256 verification.
- Explicit duplicate-name choices; no silent overwrite/delete.
- QR pairing and authenticated encrypted sessions.
- Connection and transfer history.

### Version 1.1 — Media streaming
- UPnP AV / DLNA discovery and ContentDirectory browsing.
- HTTP(S) byte-range streaming for seeking.
- Keep media streaming separate from the transfer engine.

### Version 1.2 — Windows shared folders
- User-selected Windows roots only.
- Per-share Read, Write, Delete, Stream permissions.
- Default Read + Stream; Write and Delete are opt-in.
- Enforce path containment; reject traversal and reparse-point escapes.
- App-managed sharing is primary; SMB is not a dependency.

## 3. Architecture
1. Discovery — local UDP discovery, interface-aware and resilient to network changes.
2. Pairing and identity — QR-assisted first trust, short-lived nonce, identity, revocation.
3. Session transport — authenticated TLS over TCP, bounded framing, cancellation, backpressure.
4. Transfer engine — manifests, chunk streaming, acknowledgements, pause/resume, SHA-256.
5. Storage adapters — Android Storage Access Framework and Windows filesystem.
6. Share manager — explicitly selected Windows roots and per-share authorization.
7. Media service — later UPnP AV / DLNA.
8. UI — Compose and WPF.

See docs/ARCHITECTURE.md, docs/SECURITY.md, and shared/protocol/PROTOCOL.md.

## 4. Protocol principles
- Version every message envelope.
- UDP discovery is untrusted metadata, never authentication.
- QR carries device ID, endpoint hint, protocol version, certificate fingerprint, expiry, and one-time nonce; never a private key or permanent secret.
- Verify TLS certificate pin before accepting pairing messages.
- Require explicit approval, proof of key possession, replay protection, and revocation.
- Use bounded framing/chunks, durable acknowledgements, resume offsets, and SHA-256.
- Treat filenames, metadata, and remote paths as untrusted.

## 5. Development phases

### Phase 0 — Repository foundation
- [x] Repository instructions, plan, architecture/protocol documentation.
- [x] Android and Windows scaffolds.
- [x] CI build workflow.
**Exit:** clean monorepo and documented build commands.

### Phase 1 — Connection foundation
- [x] Windows TCP diagnostic listener and status UI.
- [x] Android TCP client and status UI.
- [x] HELLO/WELCOME and PING/PONG diagnostic.
- [x] Automatic local-network UDP discovery.
- [ ] Windows QR display and one-time pairing window.
- [ ] Android QR scanning and payload validation.
- [ ] TLS certificate identity and Android fingerprint pinning.
- [ ] One-time pairing nonce, explicit approval, and proof of possession.
- [ ] Trust storage and device revocation.
- [ ] Physical-device tests on router and supported hotspot topology.
**Exit:** authenticated local session without manual IP/port entry. No file API before exit.

### Phase 2 — Bidirectional file transfer
- Stream single/multiple files both directions; queue, progress, speed, cancellation.
**Exit:** repeatable transfers with bounded memory.

### Phase 3 — Folder transfer
- Recursive manifest, directory creation, conflict policy, path validation.
**Exit:** nested trees transfer without path escape or silent data loss.

### Phase 4 — Resume and integrity
- Durable acknowledgements, persisted offsets, reconnect/resume, SHA-256, safe finalization.
**Exit:** interrupted large files resume and verify correctly.

### Phase 5 — Security and release hardening
- Review pairing, TLS, trust/revocation, share authorization.
- Firewall UX, Android background transfers, diagnostics, installers/APK.
**Exit:** security review and reproducible release builds.

### Phase 6 — Performance
- Benchmark router 5 GHz, laptop/Android hotspots, weak signal, guest/client-isolated Wi-Fi.
- Test 100 MB, 1 GB, 5 GB, 10 GB, 1,000 small files, nested folders, interrupted transfers.
- Record measured throughput, CPU, memory, battery, and failures.
**Exit:** reproducible benchmarks; optimizations based on evidence.

### Phase 7 — UPnP AV / DLNA
- SSDP discovery, ContentDirectory, HTTP byte-range streaming, player integration.
**Exit:** supported media browses and streams with seeking.

### Phase 8 — Remote shared folders
- Windows share selection and permissions; Android remote browser/upload/download/folder creation/streaming.
- Path containment and authorization tests.
**Exit:** only selected folders and permitted operations are accessible.

## 6. Security requirements
- No cloud upload or telemetry by default.
- Pairing required before file access; TLS for authenticated sessions.
- Short-lived QR material and replay protection.
- Explicit share roots and operation authorization.
- Path traversal/reparse-point protections.
- No silent overwrite/delete; secrets excluded from logs.
- Disconnect and revoke controls.

## 7. Current status
Phase 1 currently provides diagnostic-only Windows UDP discovery/TCP host and Android UDP discovery/TCP client, HELLO/WELCOME, and PING/PONG. CI build jobs are configured. QR, TLS, authenticated trust, file transfer, physical-device interoperability, DLNA, and remote folder access are not implemented. The current TCP diagnostic is plaintext and unauthenticated.

## 8. Decision log
- Prefer 5 GHz for primary performance tests; do not require it.
- Support hotspot connectivity where peer routing is available.
- No manual IP/port entry.
- QR is for pairing/trust and endpoint hints, not bypassing network isolation.
- Windows sharing is limited to explicitly selected roots.
- DLNA remains separate from file transfer.
