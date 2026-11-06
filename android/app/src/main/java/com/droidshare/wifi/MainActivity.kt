package com.droidshare.wifi

import android.os.Bundle
import android.os.SystemClock
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.graphics.Color
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.background
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

data class DiscoveryResult(val message: String, val shares: List<RemoteShare> = emptyList())

class MainActivity : ComponentActivity() {
    private val discoveredShares = mutableStateOf<List<RemoteShare>>(emptyList())
    private val scannedQr = mutableStateOf<PairingQrPayload?>(null)
    private val scanMessage = mutableStateOf("No pairing QR scanned yet.")
    private val scannerLauncher = registerForActivityResult(ScanContract()) { result ->
        val contents = result.contents
        if (contents.isNullOrBlank()) {
            scanMessage.value = "QR scan cancelled."
        } else {
            try {
                scannedQr.value = PairingQrPayload.parse(contents)
                scanMessage.value = "QR payload validated. Connect to request secure pairing."
            } catch (error: Exception) {
                scannedQr.value = null
                scanMessage.value = error.message ?: "Invalid pairing QR code."
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            val ink = androidx.compose.ui.graphics.Color(0xFF182033)
            val muted = androidx.compose.ui.graphics.Color(0xFF6B7890)
            val canvas = androidx.compose.ui.graphics.Color(0xFFF5F6FB)
            val violet = androidx.compose.ui.graphics.Color(0xFF6554C0)
            val green = androidx.compose.ui.graphics.Color(0xFF16865B)
            var status by remember { mutableStateOf("Ready to discover a Windows device") }
            var busy by remember { mutableStateOf(false) }
            var tlsStatus by remember { mutableStateOf("Pairing has not been attempted.") }
            val scope = rememberCoroutineScope()

            MaterialTheme(
                colorScheme = lightColorScheme(
                    primary = violet,
                    onPrimary = androidx.compose.ui.graphics.Color.White,
                    background = canvas,
                    surface = androidx.compose.ui.graphics.Color.White,
                    onSurface = ink
                )
            ) {
                Surface(modifier = Modifier.fillMaxSize(), color = canvas) {
                    Column(
                        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 22.dp, vertical = 28.dp)
                    ) {
                        Row(verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
                            Surface(
                                color = violet,
                                shape = androidx.compose.foundation.shape.RoundedCornerShape(14.dp),
                                modifier = Modifier.size(48.dp)
                            ) {
                                Box(contentAlignment = androidx.compose.ui.Alignment.Center) {
                                    Text("D", color = androidx.compose.ui.graphics.Color.White,
                                        style = MaterialTheme.typography.headlineSmall,
                                        fontWeight = androidx.compose.ui.text.font.FontWeight.Bold)
                                }
                            }
                            Spacer(Modifier.width(12.dp))
                            Column {
                                Text("DroidShare", style = MaterialTheme.typography.titleLarge,
                                    fontWeight = androidx.compose.ui.text.font.FontWeight.Bold, color = ink)
                                Text("PRIVATE • LOCAL • SECURE", style = MaterialTheme.typography.labelSmall,
                                    color = muted)
                            }
                        }

                        Spacer(Modifier.height(28.dp))
                        Text("Your devices,", style = MaterialTheme.typography.headlineMedium,
                            fontWeight = androidx.compose.ui.text.font.FontWeight.Bold, color = ink)
                        Text("connected privately.", style = MaterialTheme.typography.headlineMedium,
                            fontWeight = androidx.compose.ui.text.font.FontWeight.Bold, color = violet)
                        Spacer(Modifier.height(8.dp))
                        Text("Share files over your local Wi-Fi. No cloud account or internet required.",
                            style = MaterialTheme.typography.bodyMedium, color = muted)

                        Spacer(Modifier.height(22.dp))
                        Card(
                            modifier = Modifier.fillMaxWidth(),
                            shape = androidx.compose.foundation.shape.RoundedCornerShape(20.dp),
                            colors = CardDefaults.cardColors(containerColor = androidx.compose.ui.graphics.Color.White),
                            elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
                        ) {
                            Column(Modifier.padding(18.dp)) {
                                Row(verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
                                    Text("LOCAL NETWORK", style = MaterialTheme.typography.labelMedium,
                                        color = muted, fontWeight = androidx.compose.ui.text.font.FontWeight.Bold)
                                    Spacer(Modifier.weight(1f))
                                    Surface(color = androidx.compose.ui.graphics.Color(0xFFE9F7F0),
                                        shape = androidx.compose.foundation.shape.RoundedCornerShape(30.dp)) {
                                        Text("●  READY", modifier = Modifier.padding(horizontal = 10.dp, vertical = 5.dp),
                                            color = green, style = MaterialTheme.typography.labelSmall,
                                            fontWeight = androidx.compose.ui.text.font.FontWeight.Bold)
                                    }
                                }
                                Spacer(Modifier.height(10.dp))
                                Text(status, color = ink, style = MaterialTheme.typography.bodyLarge)
                                Spacer(Modifier.height(14.dp))
                                Button(
                                    modifier = Modifier.fillMaxWidth().height(52.dp),
                                    enabled = !busy,
                                    shape = androidx.compose.foundation.shape.RoundedCornerShape(14.dp),
                                    onClick = {
                                        scope.launch {
                                            busy = true
                                            status = "Searching local Wi-Fi network…"
                                            val result = withContext(Dispatchers.IO) { discoverAndHandshake() }
                                            status = result.message
                                            discoveredShares.value = result.shares
                                            busy = false
                                        }
                                    }
                                ) {
                                    if (busy) CircularProgressIndicator(
                                        modifier = Modifier.size(18.dp), strokeWidth = 2.dp,
                                        color = androidx.compose.ui.graphics.Color.White
                                    ) else Text("Find Windows device")
                                }
                                Spacer(Modifier.height(10.dp))
                                OutlinedButton(
                                    modifier = Modifier.fillMaxWidth().height(52.dp),
                                    enabled = !busy,
                                    shape = androidx.compose.foundation.shape.RoundedCornerShape(14.dp),
                                    onClick = {
                                        val options = ScanOptions()
                                            .setDesiredBarcodeFormats(ScanOptions.QR_CODE)
                                            .setPrompt("Scan the QR displayed by DroidShare-WiFi on Windows")
                                            .setBeepEnabled(false)
                                            .setOrientationLocked(false)
                                        scannerLauncher.launch(options)
                                    }
                                ) { Text("Scan Windows pairing QR") }
                            }
                        }

                        Spacer(Modifier.height(18.dp))
                        Text("SECURE PAIRING", style = MaterialTheme.typography.labelMedium,
                            color = muted, fontWeight = androidx.compose.ui.text.font.FontWeight.Bold)
                        Spacer(Modifier.height(8.dp))
                        Text(scanMessage.value, style = MaterialTheme.typography.bodyMedium, color = ink)
                        scannedQr.value?.let { pairing ->
                            val expiresLabel = DateTimeFormatter.ofPattern("HH:mm:ss")
                                .withZone(ZoneId.systemDefault()).format(pairing.expiresAt)
                            Spacer(Modifier.height(10.dp))
                            Card(
                                modifier = Modifier.fillMaxWidth(),
                                shape = androidx.compose.foundation.shape.RoundedCornerShape(20.dp),
                                colors = CardDefaults.cardColors(containerColor = androidx.compose.ui.graphics.Color.White),
                                elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
                            ) {
                                Column(Modifier.padding(18.dp)) {
                                    Row(verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
                                        Column(Modifier.weight(1f)) {
                                            Text(pairing.deviceName, style = MaterialTheme.typography.titleLarge,
                                                fontWeight = androidx.compose.ui.text.font.FontWeight.Bold, color = ink)
                                            Text("Windows device", style = MaterialTheme.typography.bodySmall, color = muted)
                                        }
                                        Surface(color = androidx.compose.ui.graphics.Color(0xFFE9F7F0),
                                            shape = androidx.compose.foundation.shape.RoundedCornerShape(30.dp)) {
                                            Text("QR VERIFIED", modifier = Modifier.padding(horizontal = 10.dp, vertical = 6.dp),
                                                color = green, style = MaterialTheme.typography.labelSmall,
                                                fontWeight = androidx.compose.ui.text.font.FontWeight.Bold)
                                        }
                                    }
                                    Spacer(Modifier.height(12.dp))
                                    Text("${pairing.host}:${pairing.port}", color = ink,
                                        style = MaterialTheme.typography.bodyMedium)
                                    Text("Certificate SHA-256", color = muted, style = MaterialTheme.typography.labelSmall)
                                    Text(pairing.certificateSha256, color = muted, style = MaterialTheme.typography.bodySmall)
                                    Text("QR expires $expiresLabel", color = muted,
                                        style = MaterialTheme.typography.labelSmall)
                                    Spacer(Modifier.height(14.dp))
                                    Button(
                                        modifier = Modifier.fillMaxWidth().height(52.dp),
                                        enabled = !busy && pairing.expiresAt.isAfter(java.time.Instant.now()),
                                        shape = androidx.compose.foundation.shape.RoundedCornerShape(14.dp),
                                        onClick = {
                                            scope.launch {
                                                busy = true
                                                tlsStatus = "Connecting and validating Windows certificate…"
                                                tlsStatus = withContext(Dispatchers.IO) {
                                                    try {
                                                        SecureTlsProbe.connect(this@MainActivity, pairing)
                                                    } catch (error: Exception) {
                                                        "Connection failed: " + (error.localizedMessage ?: error.javaClass.simpleName)
                                                    }
                                                }
                                                busy = false
                                            }
                                        }
                                    ) { Text(if (busy) "Connecting…" else "Connect securely") }
                                    Spacer(Modifier.height(10.dp))
                                    Surface(
                                        color = if (tlsStatus.startsWith("Paired")) androidx.compose.ui.graphics.Color(0xFFE9F7F0)
                                            else androidx.compose.ui.graphics.Color(0xFFF1F2F7),
                                        shape = androidx.compose.foundation.shape.RoundedCornerShape(12.dp)
                                    ) {
                                        Text(tlsStatus, modifier = Modifier.padding(12.dp),
                                            color = if (tlsStatus.startsWith("Paired")) green else ink,
                                            style = MaterialTheme.typography.bodySmall)
                                    }
                                }
                            }
                        }

                        if (discoveredShares.value.isNotEmpty()) {
                            Spacer(Modifier.height(22.dp))
                            Text("SHARED WITH YOU", style = MaterialTheme.typography.labelMedium,
                                color = muted, fontWeight = androidx.compose.ui.text.font.FontWeight.Bold)
                            Spacer(Modifier.height(10.dp))
                            discoveredShares.value.forEach { share ->
                                Card(
                                    modifier = Modifier.fillMaxWidth().padding(bottom = 10.dp),
                                    shape = androidx.compose.foundation.shape.RoundedCornerShape(18.dp),
                                    colors = CardDefaults.cardColors(containerColor = androidx.compose.ui.graphics.Color.White),
                                    elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
                                ) {
                                    Column(Modifier.padding(16.dp)) {
                                        Row(verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
                                            Text("▰", color = violet, style = MaterialTheme.typography.headlineSmall)
                                            Spacer(Modifier.width(10.dp))
                                            Column(Modifier.weight(1f)) {
                                                Text(share.name, color = ink, fontWeight = androidx.compose.ui.text.font.FontWeight.SemiBold)
                                                Text("${share.entries.size} items in this folder", color = muted,
                                                    style = MaterialTheme.typography.labelSmall)
                                            }
                                            Text("READ", color = green, style = MaterialTheme.typography.labelSmall,
                                                fontWeight = androidx.compose.ui.text.font.FontWeight.Bold)
                                        }
                                        Spacer(Modifier.height(10.dp))
                                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                            if (share.canWrite) PermissionTag("WRITE", violet)
                                            if (share.canDelete) PermissionTag("DELETE", androidx.compose.ui.graphics.Color(0xFFB45353))
                                            if (share.canStream) PermissionTag("STREAM", green)
                                        }
                                        if (share.entries.isEmpty()) {
                                            Text("This folder is empty.", color = muted,
                                                style = MaterialTheme.typography.bodySmall,
                                                modifier = Modifier.padding(top = 12.dp))
                                        } else {
                                            Spacer(Modifier.height(12.dp))
                                            share.entries.take(12).forEach { entry ->
                                                Row(
                                                    modifier = Modifier.fillMaxWidth().padding(vertical = 5.dp),
                                                    verticalAlignment = androidx.compose.ui.Alignment.CenterVertically
                                                ) {
                                                    Text(if (entry.isDirectory) "📁" else "📄")
                                                    Spacer(Modifier.width(9.dp))
                                                    Text(entry.name, color = ink, style = MaterialTheme.typography.bodySmall,
                                                        modifier = Modifier.weight(1f), maxLines = 1)
                                                    if (!entry.isDirectory) Text(formatFileSize(entry.size), color = muted,
                                                        style = MaterialTheme.typography.labelSmall)
                                                }
                                            }
                                            if (share.entries.size > 12 || share.truncated)
                                                Text("Showing the first 12 items from the shared folder root.",
                                                    color = muted, style = MaterialTheme.typography.labelSmall,
                                                    modifier = Modifier.padding(top = 6.dp))
                                        }
                                    }
                                }
                            }
                        }

                        Spacer(Modifier.height(22.dp))
                        Card(
                            modifier = Modifier.fillMaxWidth(),
                            shape = androidx.compose.foundation.shape.RoundedCornerShape(16.dp),
                            colors = CardDefaults.cardColors(containerColor = androidx.compose.ui.graphics.Color(0xFFECEBFA))
                        ) {
                            Column(Modifier.padding(16.dp)) {
                                Text("Coming next", color = violet, fontWeight = androidx.compose.ui.text.font.FontWeight.Bold)
                                Spacer(Modifier.height(4.dp))
                                Text("Your paired Windows folders are now available here. Secure file upload and download are the next milestone.",
                                    color = ink, style = MaterialTheme.typography.bodySmall)
                            }
                        }
                        Spacer(Modifier.height(18.dp))
                        Text("Both devices must allow local device communication. QR pairing does not bypass Wi-Fi client isolation or firewall rules.",
                            style = MaterialTheme.typography.bodySmall, color = muted)
                    }
                }
            }
        }
    }

    private fun discoverAndHandshake(): DiscoveryResult {
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
                    return DiscoveryResult("Received an unsupported discovery response.")
                }
                val port = device.optInt("tcpPort", 0)
                if (port !in 1..65535) return DiscoveryResult("Windows device returned an invalid port.")

                val windowsDeviceId = device.optString("deviceId")
                val tlsPort = device.optInt("tlsPort", 0)
                if (windowsDeviceId.matches(Regex("^[a-f0-9]{32}$")) && tlsPort in 1..65535) {
                    val prefs = getSharedPreferences("droidshare_trust_v1", MODE_PRIVATE)
                    if (prefs.contains("trusted_windows_" + windowsDeviceId)) {
                        val shares = SecureTlsProbe.connectTrusted(
                            this, response.address.hostAddress ?: return DiscoveryResult("Windows address is unavailable."),
                            tlsPort, windowsDeviceId
                        )
                        return DiscoveryResult(
                            "Securely connected to ${device.optString("deviceName")} · ${shares.size} shared folder(s) found.",
                            shares
                        )
                    }
                }

                Socket().use { tcp ->
                    tcp.connect(InetSocketAddress(response.address, port), 3000)
                    tcp.soTimeout = 3000
                    val output = tcp.getOutputStream()
                    val input = tcp.getInputStream()
                    output.write("{\"type\":\"HELLO\",\"protocolVersion\":1,\"client\":\"Android\"}\n".toByteArray(StandardCharsets.UTF_8))
                    output.flush()

                    val welcome = JSONObject(readLine(input))
                    if (welcome.optString("type") != "WELCOME" || welcome.optInt("protocolVersion") != 1) {
                        return DiscoveryResult("Windows device responded, but the diagnostic handshake was rejected. Scan its QR to pair securely.")
                    }

                    val startedAt = SystemClock.elapsedRealtime()
                    output.write("{\"type\":\"PING\",\"protocolVersion\":1}\n".toByteArray(StandardCharsets.UTF_8))
                    output.flush()
                    val pong = JSONObject(readLine(input))
                    val roundTripMs = SystemClock.elapsedRealtime() - startedAt
                    if (pong.optString("type") != "PONG" || pong.optInt("protocolVersion") != 1) {
                        return DiscoveryResult("Connected, but the diagnostic ping was rejected.")
                    }
                    DiscoveryResult("Found ${device.optString("deviceName")} · ${roundTripMs} ms. Scan its Windows QR to pair securely.")
                }
            }
        } catch (error: Exception) {
            DiscoveryResult("Connection not established: ${error.localizedMessage ?: error.javaClass.simpleName}. " +
                "Check that both devices are on the same reachable Wi-Fi and Windows firewall allows DroidShare-WiFi.", emptyList())
        }
    }

    @Composable
    private fun PermissionTag(label: String, color: androidx.compose.ui.graphics.Color) {
        Surface(color = color.copy(alpha = 0.10f),
            shape = androidx.compose.foundation.shape.RoundedCornerShape(30.dp)) {
            Text(label, modifier = Modifier.padding(horizontal = 9.dp, vertical = 5.dp),
                color = color, style = MaterialTheme.typography.labelSmall,
                fontWeight = androidx.compose.ui.text.font.FontWeight.Bold)
        }
    }

    private fun formatFileSize(bytes: Long): String = when {
        bytes < 1024 -> "${bytes} B"
        bytes < 1024 * 1024 -> "${bytes / 1024} KB"
        bytes < 1024L * 1024 * 1024 -> "${bytes / (1024 * 1024)} MB"
        else -> String.format("%.1f GB", bytes / (1024.0 * 1024 * 1024))
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
