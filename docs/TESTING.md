# Build and test guide

## Prerequisites
- Windows build: Windows 10/11, .NET 10 SDK, Visual Studio 2026 or a compatible .NET IDE.
- Android build: Android Studio with JDK 17, Android SDK Platform 35, and Gradle 8.11.1.
- A physical Android device and Windows PC connected to the same reachable local Wi-Fi for device testing.

## Windows
From the repository root:

```powershell
dotnet build .\windows\WiFiTransfer.App\WiFiTransfer.App.csproj
dotnet run --project .\windows\WiFiTransfer.App\WiFiTransfer.App.csproj
```

The desktop app starts a TCP diagnostic listener on port 45821, TLS diagnostic listener on port 45822, and UDP discovery responder on port 45820. It creates or loads a self-signed TLS certificate in the Current User certificate store and shows a QR containing the TLS endpoint, certificate fingerprint, and 120-second nonce. The QR starts the first-time pairing flow; Windows asks for explicit approval before storing trust. Windows Defender Firewall may prompt for network access; allow private-network access only when testing on a trusted network.

## Android
Open the `android/` directory in Android Studio, sync Gradle, and run the `app` configuration on a device. Or, with Gradle 8.11.1 installed:

```powershell
gradle -p .\android :app:assembleDebug
```

The Android app supports:
- **Find Windows device** — IPv4 UDP discovery and plaintext TCP HELLO/WELCOME/PING/PONG diagnostic.
- **Scan Windows pairing QR** — opens the bundled ZXing camera scanner, validates the QR envelope, device identity, IPv4 endpoint, port, certificate fingerprint, 256-bit nonce, and expiry, then displays the parsed details. **Connect securely** pins the presented certificate, submits the one-time nonce and Android Keystore public key, waits for Windows approval, signs a fresh challenge, and stores the Windows pin only after final approval.

The scanner is bundled and works offline; camera permission is requested by the scanner when needed.

## Phase 1 manual test
1. Connect Windows and Android to the same non-isolated Wi-Fi network.
2. Start the Windows app and allow its private-network firewall prompt if shown.
3. Start the Android app and tap **Find Windows device** to test the existing diagnostic path.
4. Tap **Scan Windows pairing QR** and scan the active Windows pairing QR.
5. Confirm Android shows the Windows name, TLS endpoint, fingerprint, and expiry.
6. Tap **Connect securely**. Confirm Windows shows an approval dialog with Android device name, ID, and public-key fingerprint.
7. Reject the request and confirm Android reports rejection and no paired state is shown. Refresh the QR and try again.
8. Approve the request and confirm Android reports pairing success. Verify a trusted-devices JSON record appears under `%LOCALAPPDATA%\\DroidShare-WiFi\\trusted-devices.json`.
9. Reuse the same QR and confirm it is rejected because the nonce was consumed. Refresh QR and retry with a new nonce.
10. Alter one certificate fingerprint character in a test QR and confirm TLS is rejected before any pairing message is sent.
11. Refresh the QR while a pairing approval dialog is open; after approval, confirm the replaced nonce cannot complete pairing.
12. Repeat with a hotspot topology where the hotspot host permits client-to-client communication.

## Multi-file download queue test
1. Pair Android with Windows and configure a Windows share with Read permission.
2. Open a folder containing at least three files of different sizes on Android.
3. Select two or more file checkboxes and tap **Download selected**.
4. Choose a destination folder through the Android system folder picker.
5. Confirm files download sequentially, per-file status advances, aggregate progress/speed updates, and each file reports SHA-256 verification.
6. Repeat with one destination filename already present; confirm that file is skipped and never overwritten while the remaining files complete.
7. Interrupt network connectivity during a file; confirm the queue stops, the incomplete destination document is removed when the provider permits deletion, and completed earlier files remain intact.

## Transfer controls and history test
1. Start a large download (for example, a file of at least 500 MB) or a multi-file queue.
2. Tap **Pause** while bytes are transferring. Confirm the progress stops advancing after the current bounded I/O chunk.
3. Tap **Resume** and confirm the same file continues on the same authenticated TLS session and completes with SHA-256 verification.
4. Start another large transfer and tap **Cancel**. Confirm the operation stops at the next I/O checkpoint, the incomplete Android destination is removed when the storage provider permits it, and the Windows upload staging file is not finalized.
5. Repeat cancellation during a multi-file queue. Confirm files completed before cancellation remain, the current partial file is cleaned up, and later queue items do not start.
6. Verify completed, cancelled, and failed jobs appear in **Transfer History** with direction, name, byte counts, and timestamp.
7. Force-close Android while a transfer is active, reopen it, and confirm the stale history item is marked **Interrupted**. Do not expect automatic byte-offset resume after process death or network loss in this version.
8. Clear history and confirm the list is removed without affecting transferred files.

## Current limitations and safety
- Pairing stores public identity material. Verify the Windows paired-device manager lists the new Android device and can revoke it. Android-side trust management, transfer authorization, and file transfer are not implemented. To test recovery, simulate a lost final `PAIR_APPROVED` response after Windows persists the trust record, then retry with the same Android installation/key and approve again; Windows must accept the identical key and reject a changed key. No file access is enabled.
- The existing TCP diagnostic is plaintext and unauthenticated. It does not send files.
- Discovery currently uses IPv4 limited broadcast; some routers/hotspots block client broadcast or client-to-client traffic.
- Durable resume after process death or network loss, delete, and DLNA remain pending. Pause/resume is in-session only and requires the TLS session to remain alive; Windows currently applies a 30-minute session timeout. Multi-file queues and transfer controls require physical-device validation.
- Do not expose the diagnostic listener to an untrusted/public network.
