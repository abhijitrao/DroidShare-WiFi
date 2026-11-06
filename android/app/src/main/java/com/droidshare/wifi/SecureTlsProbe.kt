package com.droidshare.wifi

import org.json.JSONObject
import java.net.InetSocketAddress
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.X509TrustManager

object SecureTlsProbe {
    fun connect(pairing: PairingQrPayload): String {
        require(pairing.expiresAt.isAfter(java.time.Instant.now())) {
            "This QR code has expired. Refresh it on Windows and scan again."
        }

        val expectedFingerprint = pairing.certificateSha256.lowercase()
        val pinnedTrustManager = object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {
                throw java.security.cert.CertificateException("Client certificates are not used by this diagnostic endpoint.")
            }

            override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
                if (chain.isEmpty()) {
                    throw java.security.cert.CertificateException("Windows did not present a TLS certificate.")
                }
                val certificate = chain[0]
                certificate.checkValidity()
                val actualFingerprint = MessageDigest.getInstance("SHA-256")
                    .digest(certificate.encoded)
                    .joinToString("") { byte -> "%02x".format(byte) }
                if (actualFingerprint != expectedFingerprint) {
                    throw java.security.cert.CertificateException(
                        "Windows certificate fingerprint does not match the scanned QR code."
                    )
                }
            }

            override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
        }

        val context = SSLContext.getInstance("TLS")
        context.init(null, arrayOf(pinnedTrustManager), SecureRandom())

        val socket = context.socketFactory.createSocket() as SSLSocket
        socket.use { tls ->
            tls.connect(InetSocketAddress(pairing.host, pairing.port), 5000)
            tls.soTimeout = 5000
            tls.enabledProtocols = tls.supportedProtocols.filter {
                it == "TLSv1.3" || it == "TLSv1.2"
            }.toTypedArray()
            check(tls.enabledProtocols.isNotEmpty()) { "This Android device does not support TLS 1.2 or newer." }
            tls.startHandshake()

            val request = JSONObject()
                .put("type", "SECURE_HELLO")
                .put("protocolVersion", 1)
                .put("client", "Android")
            tls.outputStream.write((request.toString() + "\n").toByteArray(Charsets.UTF_8))
            tls.outputStream.flush()

            val response = JSONObject(readLine(tls.inputStream))
            check(response.optString("type") == "TLS_READY" &&
                response.optInt("protocolVersion") == 1) {
                response.optString("message", "Windows rejected the secure diagnostic handshake.")
            }
            return "TLS " + tls.session.protocol + " established · certificate fingerprint matched · " +
                pairing.deviceName + ". Pairing is not completed."
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
        check(bytes.size() > 0) { "Windows closed the TLS connection without a response." }
        return bytes.toString(Charsets.UTF_8.name())
    }
}
