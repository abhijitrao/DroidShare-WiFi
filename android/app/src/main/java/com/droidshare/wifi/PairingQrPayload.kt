package com.droidshare.wifi

import android.util.Base64
import org.json.JSONObject
import java.net.Inet4Address
import java.net.InetAddress
import java.time.Instant

data class PairingQrPayload(
    val deviceId: String,
    val deviceName: String,
    val host: String,
    val port: Int,
    val certificateSha256: String,
    val nonce: String,
    val expiresAt: Instant
) {
    companion object {
        private const val MAX_FUTURE_SECONDS = 150L

        fun parse(json: String, now: Instant = Instant.now()): PairingQrPayload {
            require(json.toByteArray(Charsets.UTF_8).size <= 4096) { "QR payload is too large." }
            val root = JSONObject(json)
            require(root.optString("type") == "DROIDSHARE_PAIR") {
                "This QR code is not a DroidShare pairing code."
            }
            require(root.optInt("protocolVersion", -1) == 1) {
                "Unsupported pairing protocol version."
            }

            val deviceId = root.optString("deviceId")
            val deviceName = root.optString("deviceName")
            val host = root.optString("host")
            val port = root.optInt("port", -1)
            val fingerprint = root.optString("certificateSha256").lowercase()
            val nonce = root.optString("nonce")

            require(deviceId.matches(Regex("^[a-f0-9]{32}$"))) { "Invalid Windows device identity." }
            require(deviceName.isNotBlank() && deviceName.length <= 64) { "Invalid Windows device name." }
            require(isValidIpv4(host)) { "The QR code contains an invalid IPv4 address." }
            require(port in 1..65535) { "The QR code contains an invalid port." }
            require(fingerprint.matches(Regex("^[a-f0-9]{64}$"))) { "Invalid TLS certificate fingerprint." }
            require(deviceId == fingerprint.take(32)) {
                "Device identity does not match its certificate fingerprint."
            }

            val nonceBytes = try {
                Base64.decode(nonce, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
            } catch (_: IllegalArgumentException) {
                throw IllegalArgumentException("Invalid pairing nonce.")
            }
            require(nonceBytes.size == 32) { "Pairing nonce must contain 256 bits." }

            val expiry = try {
                Instant.parse(root.optString("expiresAt"))
            } catch (_: Exception) {
                throw IllegalArgumentException("Invalid QR expiry time.")
            }
            require(expiry.isAfter(now)) { "This QR code has expired. Generate a new code on Windows." }
            require(expiry <= now.plusSeconds(MAX_FUTURE_SECONDS)) {
                "QR expiry is outside the allowed pairing window."
            }

            return PairingQrPayload(deviceId, deviceName, host, port, fingerprint, nonce, expiry)
        }

        private fun isValidIpv4(value: String): Boolean {
            if (!value.matches(Regex("^[0-9]{1,3}(\\.[0-9]{1,3}){3}$"))) return false
            return try {
                val address = InetAddress.getByName(value)
                address is Inet4Address && address.hostAddress == value &&
                    !address.isLoopbackAddress && !address.isAnyLocalAddress &&
                    !address.isLinkLocalAddress && !address.isMulticastAddress
            } catch (_: Exception) { false }
        }
    }
}
