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

The desktop app starts a TCP diagnostic listener on port 45821, TLS diagnostic listener on port 45822, and UDP discovery responder on port 45820. It creates or loads a self-signed TLS certificate in the Current User certificate store and shows a QR containing the TLS endpoint, certificate fingerprint, and 120-second nonce. The QR is not an active pairing credential yet. Windows Defender Firewall may prompt for network access; allow private-network access only when testing on a trusted network.

## Android
Open the `android/` directory in Android Studio, sync Gradle, and run the `app` configuration on a device. Or, with Gradle 8.11.1 installed:

```powershell
gradle -p .\android :app:assembleDebug
```

The Android app supports:
- **Find Windows device** — IPv4 UDP discovery and plaintext TCP HELLO/WELCOME/PING/PONG diagnostic.
- **Scan Windows pairing QR** — opens the bundled ZXing camera scanner, validates the QR envelope, device identity, IPv4 endpoint, port, certificate fingerprint, 256-bit nonce, and expiry, then displays the parsed details. **Connect securely** opens the QR endpoint, pins the presented certificate fingerprint, and verifies the TLS diagnostic response.

The scanner is bundled and works offline; camera permission is requested by the scanner when needed.

## Phase 1 manual test
1. Connect Windows and Android to the same non-isolated Wi-Fi network.
2. Start the Windows app and allow its private-network firewall prompt if shown.
3. Start the Android app and tap **Find Windows device** to test the existing diagnostic path.
4. Tap **Scan Windows pairing QR** and scan the Windows preview QR.
5. Confirm Android shows the Windows name, TLS endpoint, fingerprint, and expiry.
6. Tap **Connect securely** and confirm TLS is established only when the server certificate matches the QR fingerprint.
7. Alter one fingerprint character in a test QR and confirm the TLS connection is rejected. Restore the valid QR and confirm the connection succeeds.
8. Try scanning an unrelated QR and confirm it is rejected. Wait for a Windows QR to expire, refresh it, and scan the new one.
9. Repeat with a hotspot topology where the hotspot host permits client-to-client communication.

## Current limitations and safety
- QR scanning validates the payload. The explicit TLS probe connects and pins the certificate, but it does not consume the nonce or create a trusted-device record. Do not treat a successful TLS probe as pairing.
- The existing TCP diagnostic is plaintext and unauthenticated. It does not send files.
- Discovery currently uses IPv4 limited broadcast; some routers/hotspots block client broadcast or client-to-client traffic.
- Nonce validation and replay prevention, explicit approval/proof, trust storage/revocation, transfer, resume, and DLNA remain pending.
- Do not expose the diagnostic listener to an untrusted/public network.
