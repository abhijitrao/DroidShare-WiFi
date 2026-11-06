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
4. Tap **Scan Windows pairing QR** and scan the Windows preview QR.
5. Confirm Android shows the Windows name, TLS endpoint, fingerprint, and expiry.
6. Tap **Connect securely**. Confirm Windows shows an approval dialog with Android device name, ID, and public-key fingerprint.
7. Reject the request and confirm Android reports rejection and no paired state is shown. Refresh the QR and try again.
8. Approve the request and confirm Android reports pairing success. Verify a trusted-devices JSON record appears under `%LOCALAPPDATA%\\DroidShare-WiFi\\trusted-devices.json`.
9. Reuse the same QR and confirm it is rejected because the nonce was consumed. Refresh QR and retry with a new nonce.
10. Alter one certificate fingerprint character in a test QR and confirm TLS is rejected before any pairing message is sent.
11. Refresh the QR while a pairing approval dialog is open; after approval, confirm the replaced nonce cannot complete pairing.
12. Repeat with a hotspot topology where the hotspot host permits client-to-client communication.

## Current limitations and safety
- Pairing stores public identity material, but trusted-device revocation UI, recovery from a lost final response, transfer authorization, and file transfer are not implemented. No file access is enabled.
- The existing TCP diagnostic is plaintext and unauthenticated. It does not send files.
- Discovery currently uses IPv4 limited broadcast; some routers/hotspots block client broadcast or client-to-client traffic.
- Nonce validation and replay prevention, explicit approval/proof, trust storage/revocation, transfer, resume, and DLNA remain pending.
- Do not expose the diagnostic listener to an untrusted/public network.
