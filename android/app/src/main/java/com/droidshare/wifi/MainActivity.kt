package com.droidshare.wifi

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
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

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                var status by remember { mutableStateOf("Ready to discover a Windows device") }
                var busy by remember { mutableStateOf(false) }
                val scope = rememberCoroutineScope()

                Surface(modifier = Modifier.fillMaxSize()) {
                    Column(
                        modifier = Modifier.fillMaxSize().padding(24.dp),
                        verticalArrangement = Arrangement.Center
                    ) {
                        Text("DroidShare-WiFi", style = MaterialTheme.typography.headlineMedium)
                        Spacer(Modifier.height(8.dp))
                        Text("Phase 1 · Local connection test")
                        Spacer(Modifier.height(24.dp))
                        Text(status, style = MaterialTheme.typography.bodyLarge)
                        Spacer(Modifier.height(20.dp))
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
                        ) {
                            Text(if (busy) "Searching…" else "Find Windows device")
                        }
                        Spacer(Modifier.height(12.dp))
                        Text(
                            "Both devices must be connected to a network that allows local device communication. " +
                                "This diagnostic build does not transfer files yet.",
                            style = MaterialTheme.typography.bodySmall
                        )
                    }
                }
            }
        }
    }

    private fun discoverAndHandshake(): String {
        val discoveryPort = 45820
        val request = "DROIDSHARE_DISCOVER_V1".toByteArray(StandardCharsets.UTF_8)

        return try {
            DatagramSocket().use { udp ->
                udp.broadcast = true
                udp.soTimeout = 2500
                val broadcast = InetAddress.getByName("255.255.255.255")
                udp.send(DatagramPacket(request, request.size, broadcast, discoveryPort))

                val buffer = ByteArray(2048)
                val response = DatagramPacket(buffer, buffer.size)
                udp.receive(response)

                val device = JSONObject(String(response.data, 0, response.length, StandardCharsets.UTF_8))
                if (device.optString("type") != "DROIDSHARE_DEVICE" ||
                    device.optInt("protocolVersion") != 1
                ) return "Received an unsupported discovery response."

                val port = device.optInt("tcpPort", 0)
                if (port !in 1..65535) return "Windows device returned an invalid port."

                Socket().use { tcp ->
                    tcp.connect(InetSocketAddress(response.address, port), 3000)
                    tcp.soTimeout = 3000
                    val output = tcp.getOutputStream()
                    output.write(
                        "{\"type\":\"HELLO\",\"protocolVersion\":1,\"client\":\"Android\"}\n"
                            .toByteArray(StandardCharsets.UTF_8)
                    )
                    output.flush()

                    val input = tcp.getInputStream()
                    val line = buildString {
                        while (length < 16 * 1024) {
                            val next = input.read()
                            if (next == -1 || next == 10) break
                            append(next.toChar())
                        }
                    }
                    val welcome = JSONObject(line)
                    if (welcome.optString("type") == "WELCOME" &&
                        welcome.optInt("protocolVersion") == 1
                    ) {
                        "Connected to ${device.optString("deviceName")} successfully."
                    } else {
                        "Windows device responded, but the handshake was rejected."
                    }
                }
            }
        } catch (error: Exception) {
            "Connection not established: ${error.localizedMessage ?: error.javaClass.simpleName}. " +
                "Check that both devices are on the same reachable Wi-Fi and Windows firewall allows DroidShare-WiFi."
        }
    }
}
