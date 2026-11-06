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

The Phase 1 desktop app starts a TCP diagnostic listener on port 45821 and UDP discovery responder on port 45820. Windows Defender Firewall may prompt for network access. Allow private-network access only when testing on a trusted network.

## Android
Open the `android/` directory in Android Studio, sync Gradle, and run the `app` configuration on a device. Or, with Gradle 8.11.1 installed:

```powershell
gradle -p .\android :app:assembleDebug
```

The app's **Find Windows device** action broadcasts a UDP discovery packet and performs a small TCP HELLO/WELCOME diagnostic handshake.

## Phase 1 manual test
1. Connect Windows and Android to the same non-isolated Wi-Fi network.
2. Start the Windows app.
3. Allow its private-network firewall prompt if shown.
4. Start the Android app and tap **Find Windows device**.
5. Confirm Android reports a successful connection and Windows shows the remote endpoint.
6. Repeat with a hotspot topology where the hotspot host permits client-to-client communication.

## Current limitations
- Phase 1 is only a connectivity diagnostic. It does not send files.
- Discovery currently uses IPv4 limited broadcast; some routers/hotspots block client broadcast or client-to-client traffic.
- QR pairing, TLS authentication, retrying discovery, mDNS fallback, transfer, resume, and DLNA are not implemented yet.
- Do not expose the diagnostic listener to an untrusted/public network.
