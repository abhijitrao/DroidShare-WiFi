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

The desktop app starts a TCP diagnostic listener on port 45821 and UDP discovery responder on port 45820. It creates or loads a self-signed TLS certificate in the Current User certificate store and shows a QR payload preview with a 120-second expiry. The QR is not an active pairing credential yet. Windows Defender Firewall may prompt for network access; allow private-network access only when testing on a trusted network.

## Android
Open the `android/` directory in Android Studio, sync Gradle, and run the `app` configuration on a device. Or, with Gradle 8.11.1 installed:

```powershell
gradle -p .\android :app:assembleDebug
```

The Android app supports:
- **Find Windows device** — IPv4 UDP discovery and plaintext TCP HELLO/WELCOME/PING/PONG diagnostic.
- **Scan Windows pairing QR** — opens the bundled ZXing camera scanner, validates the QR envelope, device identity, IPv4 endpoint, port, certificate fingerprint, 256-bit nonce, and expiry, then displays the parsed details.

The scanner is bundled and works offline; camera permission is requested by the scanner when needed.

## Phase 1 manual test
1. Connect Windows and Android to the same non-isolated Wi-Fi network.
2. Start the Windows app and allow its private-network firewall prompt if shown.
3. Start the Android app and tap **Find Windows device** to test the existing diagnostic path.
4. Tap **Scan Windows pairing QR** and scan the Windows preview QR.
5. Confirm Android shows the Windows name, endpoint, fingerprint, and expiry.
6. Try scanning an unrelated QR and confirm it is rejected. Wait for a Windows QR to expire, refresh it, and scan the new one.
7. Repeat with a hotspot topology where the hotspot host permits client-to-client communication.

## Current limitations and safety
- QR scanning currently validates and previews payload data only. It does not connect to the QR endpoint, consume the nonce, establish TLS, or create a trusted-device record.
- The Windows QR is marked preview-only. Do not treat a successful scan as pairing.
- The existing TCP diagnostic is plaintext and unauthenticated. It does not send files.
- Discovery currently uses IPv4 limited broadcast; some routers/hotspots block client broadcast or client-to-client traffic.
- TLS listener/pinning, nonce validation and replay prevention, explicit approval/proof, trust storage/revocation, transfer, resume, and DLNA remain pending.
- Do not expose the diagnostic listener to an untrusted/public network.
