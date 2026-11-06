package com.droidshare.wifi

import android.os.Bundle
import android.os.SystemClock
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.charset.StandardCharsets
import java.time.ZoneId
import java.time.format.DateTimeFormatter

class MainActivity : ComponentActivity() {
    private val scannedQr = mutableStateOf<PairingQrPayload?>(null)
    private val scanMessage = mutableStateOf("No pairing QR scanned yet.")
    private val scannerLauncher = registerForActivityResult(ScanContract()) { result ->
        val contents = result.contents
        if (contents.isNullOrBlank()) {
            scanMessage.value = "QR scan cancelled."
        } else {
            try {
                scannedQr.value = PairingQrPayload.parse(contents)
                scanMessage.value = "QR payload validated. Connect to verify the Windows certificate."
            } catch (error: Exception) {
                scannedQr.value = null
                scanMessage.value = error.message ?: "Invalid pairing QR code."
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                var status by remember { mutableStateOf("Ready to discover a Windows device") }
                var busy by remember { mutableStateOf(false) }
                var tlsStatus by remember { mutableStateOf("TLS connection has not been tested.") }
                val scope = rememberCoroutineScope()
                Surface(modifier = Modifier.fillMaxSize()) {
                    Column(Modifier.fillMaxSize().padding(24.dp), verticalArrangement = Arrangement.Center) {
                        Text("DroidShare-WiFi", style = MaterialTheme.typography.headlineMedium)
                        Spacer(Modifier.height(8.dp))
                        Text("Phase 1 · Local and secure connection test")
                        Spacer(Modifier.height(20.dp))
                        Text(status, style = MaterialTheme.typography.bodyLarge)
                        Spacer(Modifier.height(16.dp))
                        Button(
                            modifier = Modifier.fillMaxWidth(),
                            enabled = !busy,
                            onClick = {
                                scope.launch {
                                    busy = true
                                    status = "Searching local Wi-Fi network…"
                                    status = withContext(Dispatchers.IO) { discoverAndHandshake() }
                                    busy = false
                                }
                            }
                        ) { Text(if (busy) "Searching…" else "Find Windows device") }

                        Spacer(Modifier.height(12.dp))
                        OutlinedButton(
                            modifier = Modifier.fillMaxWidth(),
                            onClick = {
                                val options = ScanOptions()
                                    .setDesiredBarcodeFormats(ScanOptions.QR_CODE)
                                    .setPrompt("Scan the QR displayed by DroidShare-WiFi on Windows")
                                    .setBeepEnabled(false)
                                    .setOrientationLocked(false)
                                scannerLauncher.launch(options)
                            }
                        ) { Text("Scan Windows pairing QR") }

                        Spacer(Modifier.height(12.dp))
                        Text(scanMessage.value, style = MaterialTheme.typography.bodyMedium)
                        scannedQr.value?.let { pairing ->
                            Spacer(Modifier.height(8.dp))
                            Card(modifier = Modifier.fillMaxWidth()) {
                                Column(Modifier.padding(12.dp)) {
                                    Text(pairing.deviceName, style = MaterialTheme.typography.titleMedium)
                                    Text("${pairing.host}:${pairing.port}")
                                    Text(
                                        "Certificate SHA-256: ${pairing.certificateSha256}",
                                        style = MaterialTheme.typography.bodySmall
                                    )
                                    Text(
                                        "Expires: ${DateTimeFormatter.ofPattern("HH:mm:ss")
                                            .withZone(ZoneId.systemDefault()).format(pairing.expiresAt)}",
                                        style = MaterialTheme.typography.bodySmall
                                    )
                                    Text(
                                        "TLS probe verifies the exact certificate fingerprint. It does not pair devices or grant file access.",
                                        color = MaterialTheme.colorScheme.error,
                                        style = MaterialTheme.typography.bodySmall
                                    )
                                    Spacer(Modifier.height(10.dp))
                                    Button(
                                        modifier = Modifier.fillMaxWidth(),
                                        enabled = !busy && pairing.expiresAt.isAfter(java.time.Instant.now()),
                                        onClick = {
                                            scope.launch {
                                                busy = true
                                                tlsStatus = "Connecting and validating Windows certificate…"
                                                tlsStatus = withContext(Dispatchers.IO) {
                                                    try {
                                                        SecureTlsProbe.connect(pairing)
                                                    } catch (error: Exception) {
                                                        "TLS connection failed: " + (error.localizedMessage ?: error.javaClass.simpleName)
                                                    }
                                                }
                                                busy = false
                                            }
                                        }
                                    ) { Text(if (busy) "Connecting…" else "Connect securely") }
                                    Text(tlsStatus, style = MaterialTheme.typography.bodySmall)
                                }
                            }
                        }

                        Spacer(Modifier.height(20.dp))
                        Text(
                            "Both devices must be connected to a network that allows local device communication. " +
                                "The TLS test verifies the scanned Windows certificate. Device pairing and file transfer are not enabled.",
                            style = MaterialTheme.typography.bodySmall
                        )
                    }
                }
            }
        }
    }

    private fun discoverAndHandshake(): String {
        val request = "DROIDSHARE_DISCOVER_V1".toByteArray(StandardCharsets.UTF_8)
        return try {
            DatagramSocket().use { udp ->
                udp.broadcast = true
                udp.soTimeout = 2500
                val broadcast = InetAddress.getByName("255.255.255.255")
                udp.send(DatagramPacket(request, request.size, broadcast, 45820))
                val buffer = ByteArray(2048)
                val response = DatagramPacket(buffer, buffer.size)
                udp.receive(response)

                val device = JSONObject(String(response.data, 0, response.length, StandardCharsets.UTF_8))
                if (device.optString("type") != "DROIDSHARE_DEVICE" || device.optInt("protocolVersion") != 1) {
                    return "Received an unsupported discovery response."
                }
                val port = device.optInt("tcpPort", 0)
                if (port !in 1..65535) return "Windows device returned an invalid port."

                Socket().use { tcp ->
                    tcp.connect(InetSocketAddress(response.address, port), 3000)
                    tcp.soTimeout = 3000
                    val output = tcp.getOutputStream()
                    val input = tcp.getInputStream()
                    output.write("{\"type\":\"HELLO\",\"protocolVersion\":1,\"client\":\"Android\"}\n".toByteArray(StandardCharsets.UTF_8))
                    output.flush()

                    val welcome = JSONObject(readLine(input))
                    if (welcome.optString("type") != "WELCOME" || welcome.optInt("protocolVersion") != 1) {
                        return "Windows device responded, but the handshake was rejected."
                    }

                    val startedAt = SystemClock.elapsedRealtime()
                    output.write("{\"type\":\"PING\",\"protocolVersion\":1}\n".toByteArray(StandardCharsets.UTF_8))
                    output.flush()
                    val pong = JSONObject(readLine(input))
                    val roundTripMs = SystemClock.elapsedRealtime() - startedAt
                    if (pong.optString("type") != "PONG" || pong.optInt("protocolVersion") != 1) {
                        return "Connected, but the diagnostic ping was rejected."
                    }
                    "Connected to ${device.optString("deviceName")} successfully · ${roundTripMs} ms"
                }
            }
        } catch (error: Exception) {
            "Connection not established: ${error.localizedMessage ?: error.javaClass.simpleName}. " +
                "Check that both devices are on the same reachable Wi-Fi and Windows firewall allows DroidShare-WiFi."
        }
    }

    private fun readLine(input: java.io.InputStream): String {
        val bytes = java.io.ByteArrayOutputStream()
        while (bytes.size() < 16 * 1024) {
            val next = input.read()
            if (next == -1 || next == 10) break
            bytes.write(next)
        }
        check(bytes.size() < 16 * 1024) { "Protocol message exceeded 16 KiB." }
        return bytes.toString(StandardCharsets.UTF_8.name())
    }
}
