package com.droidshare.wifi

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import org.json.JSONObject
import java.net.InetSocketAddress
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.Signature
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.UUID
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.X509TrustManager

object SecureTlsProbe {
    private const val KEY_ALIAS = "droidshare_android_pairing_v1"
    private const val PREFS = "droidshare_trust_v1"

    fun connect(context: Context, pairing: PairingQrPayload): String {
        require(pairing.expiresAt.isAfter(java.time.Instant.now())) {
            "This QR code has expired. Refresh it on Windows and scan again."
        }

        val expectedFingerprint = pairing.certificateSha256.lowercase()
        val pinnedTrustManager = object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {
                throw java.security.cert.CertificateException("Client certificates are not used by this endpoint.")
            }

            override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
                if (chain.isEmpty()) throw java.security.cert.CertificateException("Windows did not present a TLS certificate.")
                val certificate = chain[0]
                certificate.checkValidity()
                val actualFingerprint = MessageDigest.getInstance("SHA-256")
                    .digest(certificate.encoded)
                    .joinToString("") { byte -> "%02x".format(byte) }
                if (actualFingerprint != expectedFingerprint) {
                    throw java.security.cert.CertificateException("Windows certificate fingerprint does not match the scanned QR code.")
                }
            }
            override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
        }

        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        if (!keyStore.containsAlias(KEY_ALIAS)) {
            val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
            generator.initialize(
                KeyGenParameterSpec.Builder(
                    KEY_ALIAS,
                    KeyProperties.PURPOSE_SIGN
                )
                    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .build()
            )
            generator.generateKeyPair()
        }
        val publicKey = keyStore.getCertificate(KEY_ALIAS).publicKey
        val privateKey = keyStore.getKey(KEY_ALIAS, null) as java.security.PrivateKey
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val androidDeviceId = prefs.getString("android_device_id", null) ?: UUID.randomUUID().toString().also {
            prefs.edit().putString("android_device_id", it).apply()
        }
        val androidName = (Build.MODEL ?: "Android device").take(64)

        val contextTls = SSLContext.getInstance("TLS")
        contextTls.init(null, arrayOf(pinnedTrustManager), SecureRandom())
        val socket = contextTls.socketFactory.createSocket() as SSLSocket
        socket.use { tls ->
            tls.connect(InetSocketAddress(pairing.host, pairing.port), 5000)
            tls.soTimeout = 45000
            tls.enabledProtocols = tls.supportedProtocols.filter {
                it == "TLSv1.3" || it == "TLSv1.2"
            }.toTypedArray()
            check(tls.enabledProtocols.isNotEmpty()) { "This Android device does not support TLS 1.2 or newer." }
            tls.startHandshake()

            val hello = JSONObject()
                .put("type", "PAIR_HELLO")
                .put("protocolVersion", 1)
                .put("nonce", pairing.nonce)
                .put("androidDeviceId", androidDeviceId)
                 .put("deviceName", androidName)
                .put("publicKeyAlgorithm", "ECDSA_P256")
                .put("publicKey", android.util.Base64.encodeToString(publicKey.encoded, android.util.Base64.NO_WRAP))
            writeLine(tls, hello)

            val challengeResponse = JSONObject(readLine(tls.inputStream))
            if (challengeResponse.optString("type") == "PAIR_ERROR") {
                throw IllegalStateException(challengeResponse.optString("message", "Windows rejected pairing."))
            }
            check(challengeResponse.optString("type") == "PAIR_CHALLENGE" &&
                challengeResponse.optInt("protocolVersion") == 1) {
                "Windows returned an invalid pairing challenge."
            }
            val challenge = try {
                android.util.Base64.decode(challengeResponse.getString("challenge"), android.util.Base64.DEFAULT)
            } catch (_: Exception) {
                throw IllegalStateException("Windows pairing challenge is malformed.")
            }
            require(challenge.size == 32) { "Windows pairing challenge must contain 256 bits." }

            val signer = Signature.getInstance("SHA256withECDSA")
            signer.initSign(privateKey)
            signer.update(challenge)
            val proof = JSONObject()
                .put("type", "PAIR_PROOF")
                .put("protocolVersion", 1)
                .put("signature", android.util.Base64.encodeToString(signer.sign(), android.util.Base64.NO_WRAP))
            writeLine(tls, proof)

            val approval = JSONObject(readLine(tls.inputStream))
            if (approval.optString("type") == "PAIR_ERROR") {
                throw IllegalStateException(approval.optString("message", "Windows rejected pairing."))
            }
            check(approval.optString("type") == "PAIR_APPROVED" &&
                approval.optInt("protocolVersion") == 1 &&
                approval.optString("androidDeviceId") == androidDeviceId &&
                approval.optString("windowsDeviceId") == pairing.deviceId &&
                approval.optString("certificateSha256").equals(expectedFingerprint, ignoreCase = true)) {
                "Windows pairing confirmation did not match the scanned device."
            }

            // Persist only after Windows has confirmed successful pairing.
            prefs.edit()
                .putString("trusted_windows_" + pairing.deviceId, expectedFingerprint)
                .putString("trusted_windows_name_" + pairing.deviceId, pairing.deviceName)
                .apply()
            return "Paired with " + pairing.deviceName + " · TLS " + tls.session.protocol +
                " · Android key proof verified. File sharing is not enabled yet."
        }
    }

    private fun writeLine(socket: SSLSocket, json: JSONObject) {
        socket.outputStream.write((json.toString() + "\n").toByteArray(Charsets.UTF_8))
        socket.outputStream.flush()
    }

    private fun readLine(input: java.io.InputStream): String {
        val bytes = java.io.ByteArrayOutputStream()
        while (bytes.size() < 16 * 1024) {
            val next = input.read()
            if (next == -1 || next == 10) break
            bytes.write(next)
        }
        check(bytes.size() < 16 * 1024) { "Protocol message exceeded 16 KiB." }
        check(bytes.size() > 0) { "Windows closed the pairing connection without a response." }
        return bytes.toString(Charsets.UTF_8.name())
    }
}
