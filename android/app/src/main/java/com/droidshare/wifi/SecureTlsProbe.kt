package com.droidshare.wifi


import android.content.Context
import android.os.Build
import android.net.Uri
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

data class RemoteDirectoryEntry(
    val name: String,
    val isDirectory: Boolean,
    val size: Long,
    val modifiedUtc: String
)

data class RemoteShare(
    val shareId: String,
    val name: String,
    val canWrite: Boolean,
    val canDelete: Boolean,
    val canStream: Boolean,
    val entries: List<RemoteDirectoryEntry>,
    val truncated: Boolean,
    val currentPath: String = ""
)

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
                " · Android key proof verified. Secure browsing and file downloads are ready."
        }
    }


    fun connectTrusted(context: Context, host: String, port: Int, windowsDeviceId: String, browseShareId: String? = null, browsePath: String = ""): List<RemoteShare> {
        require(windowsDeviceId.matches(Regex("^[a-f0-9]{32}$"))) { "Invalid Windows device identity." }
        require(browsePath.length <= 2048 && !browsePath.startsWith("/") && !browsePath.startsWith("\\\\")) { "Invalid shared folder path." }
        require(browsePath.split('/').none { it == "." || it == ".." || it.contains('\\') }) { "Invalid shared folder path." }
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val fingerprint = prefs.getString("trusted_windows_" + windowsDeviceId, null)
            ?: throw IllegalStateException("This Windows device is not paired yet. Scan its pairing QR first.")
        require(fingerprint.matches(Regex("^[a-f0-9]{64}$")) &&
            fingerprint.take(32) == windowsDeviceId) { "Saved Windows trust information is invalid." }

        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        check(keyStore.containsAlias(KEY_ALIAS)) { "Android identity key is missing. Pair this device again." }
        val publicKey = keyStore.getCertificate(KEY_ALIAS).publicKey
        val privateKey = keyStore.getKey(KEY_ALIAS, null) as java.security.PrivateKey
        val androidDeviceId = prefs.getString("android_device_id", null)
            ?: throw IllegalStateException("Android device identity is missing. Pair this device again.")

        val trustManager = pinnedTrustManager(fingerprint)
        val contextTls = SSLContext.getInstance("TLS")
        contextTls.init(null, arrayOf(trustManager), SecureRandom())
        val socket = contextTls.socketFactory.createSocket() as SSLSocket
        socket.use { tls ->
            tls.connect(InetSocketAddress(host, port), 5000)
            tls.soTimeout = 15000
            tls.enabledProtocols = tls.supportedProtocols.filter {
                it == "TLSv1.3" || it == "TLSv1.2"
            }.toTypedArray()
            check(tls.enabledProtocols.isNotEmpty()) { "This Android device does not support TLS 1.2 or newer." }
            tls.startHandshake()

            writeLine(tls, JSONObject()
                .put("type", "SESSION_HELLO")
                .put("protocolVersion", 1)
                .put("androidDeviceId", androidDeviceId)
                .put("publicKey", android.util.Base64.encodeToString(publicKey.encoded, android.util.Base64.NO_WRAP)))

            val challengeResponse = JSONObject(readLine(tls.inputStream))
            if (challengeResponse.optString("type") == "PAIR_ERROR")
                throw IllegalStateException(challengeResponse.optString("message", "Windows rejected the secure session."))
            check(challengeResponse.optString("type") == "SESSION_CHALLENGE" &&
                challengeResponse.optInt("protocolVersion") == 1) {
                "Windows returned an invalid session challenge."
            }
            val challenge = android.util.Base64.decode(
                challengeResponse.getString("challenge"), android.util.Base64.DEFAULT)
            require(challenge.size == 32) { "Windows session challenge is malformed." }

            val signer = Signature.getInstance("SHA256withECDSA")
            signer.initSign(privateKey)
            signer.update(challenge)
            writeLine(tls, JSONObject()
                .put("type", "SESSION_PROOF")
                .put("protocolVersion", 1)
                .put("signature", android.util.Base64.encodeToString(signer.sign(), android.util.Base64.NO_WRAP)))

            val ready = JSONObject(readLine(tls.inputStream))
            if (ready.optString("type") == "PAIR_ERROR")
                throw IllegalStateException(ready.optString("message", "Windows rejected the secure session."))
            check(ready.optString("type") == "SESSION_READY" &&
                ready.optInt("protocolVersion") == 1 &&
                ready.optString("windowsDeviceId") == windowsDeviceId) {
                "Windows session identity did not match the saved trust record."
            }

            val sharesJson = ready.optJSONArray("shares") ?: org.json.JSONArray()
            val shares = mutableListOf<RemoteShare>()
            for (index in 0 until sharesJson.length()) {
                val share = sharesJson.getJSONObject(index)
                val shareId = share.getString("shareId")
                val name = share.getString("name")
                val requestedPath = if (browseShareId == shareId) browsePath else ""
                writeLine(tls, JSONObject()
                    .put("type", "LIST_DIRECTORY")
                    .put("protocolVersion", 1)
                    .put("shareId", shareId)
                    .put("path", requestedPath))

                val listing = JSONObject(readLine(tls.inputStream))
                if (listing.optString("type") == "SESSION_ERROR")
                    throw IllegalStateException(listing.optString("message", "Could not list shared folder."))
                check(listing.optString("type") == "DIRECTORY_LIST" &&
                    listing.optString("shareId") == shareId) {
                    "Windows returned an invalid folder listing."
                }
                val entriesJson = listing.optJSONArray("entries") ?: org.json.JSONArray()
                val entries = buildList {
                    for (entryIndex in 0 until entriesJson.length()) {
                        val entry = entriesJson.getJSONObject(entryIndex)
                        add(RemoteDirectoryEntry(
                            name = entry.optString("name"),
                            isDirectory = entry.optBoolean("isDirectory"),
                            size = entry.optLong("size"),
                            modifiedUtc = entry.optString("modifiedUtc")
                        ))
                    }
                }
                shares += RemoteShare(
                    shareId = shareId,
                    name = name,
                    canWrite = share.optBoolean("canWrite"),
                    canDelete = share.optBoolean("canDelete"),
                    canStream = share.optBoolean("canStream"),
                    entries = entries,
                    truncated = listing.optBoolean("truncated"),
                    currentPath = listing.optString("path")
                )
            }
            return shares
        }
    }

    fun disconnectAndForget(context: Context, host: String, port: Int, windowsDeviceId: String) {
        require(windowsDeviceId.matches(Regex("^[a-f0-9]{32}$"))) { "Invalid Windows device identity." }
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val fingerprint = prefs.getString("trusted_windows_" + windowsDeviceId, null)
            ?: throw IllegalStateException("This Windows device is not paired.")
        require(fingerprint.matches(Regex("^[a-f0-9]{64}$")) && fingerprint.take(32) == windowsDeviceId) {
            "Saved Windows trust information is invalid."
        }

        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        check(keyStore.containsAlias(KEY_ALIAS)) { "Android identity key is missing. Pair this device again." }
        val publicKey = keyStore.getCertificate(KEY_ALIAS).publicKey
        val privateKey = keyStore.getKey(KEY_ALIAS, null) as java.security.PrivateKey
        val androidDeviceId = prefs.getString("android_device_id", null)
            ?: throw IllegalStateException("Android device identity is missing.")

        val tlsContext = SSLContext.getInstance("TLS")
        tlsContext.init(null, arrayOf(pinnedTrustManager(fingerprint)), SecureRandom())
        val socket = tlsContext.socketFactory.createSocket() as SSLSocket
        socket.use { tls ->
            tls.connect(InetSocketAddress(host, port), 5000)
            tls.soTimeout = 15000
            tls.tcpNoDelay = true
            tls.enabledProtocols = tls.supportedProtocols.filter {
                it == "TLSv1.3" || it == "TLSv1.2"
            }.toTypedArray()
            check(tls.enabledProtocols.isNotEmpty()) { "TLS 1.2 or newer is required." }
            tls.startHandshake()

            writeLine(tls, JSONObject()
                .put("type", "SESSION_HELLO")
                .put("protocolVersion", 1)
                .put("androidDeviceId", androidDeviceId)
                .put("publicKey", android.util.Base64.encodeToString(publicKey.encoded, android.util.Base64.NO_WRAP)))

            val challengeResponse = JSONObject(readLine(tls.inputStream))
            check(challengeResponse.optString("type") == "SESSION_CHALLENGE" &&
                challengeResponse.optInt("protocolVersion") == 1) {
                challengeResponse.optString("message", "Windows rejected the secure session.")
            }
            val challenge = android.util.Base64.decode(
                challengeResponse.getString("challenge"), android.util.Base64.DEFAULT)
            require(challenge.size == 32) { "Windows session challenge is malformed." }

            val signer = Signature.getInstance("SHA256withECDSA")
            signer.initSign(privateKey)
            signer.update(challenge)
            writeLine(tls, JSONObject()
                .put("type", "SESSION_PROOF")
                .put("protocolVersion", 1)
                .put("signature", android.util.Base64.encodeToString(signer.sign(), android.util.Base64.NO_WRAP)))

            val ready = JSONObject(readLine(tls.inputStream))
            check(ready.optString("type") == "SESSION_READY" &&
                ready.optInt("protocolVersion") == 1 &&
                ready.optString("windowsDeviceId") == windowsDeviceId) {
                ready.optString("message", "Windows identity did not match the saved trust record.")
            }

            writeLine(tls, JSONObject()
                .put("type", "REVOKE_SELF")
                .put("protocolVersion", 1))
            val revoked = JSONObject(readLine(tls.inputStream))
            check(revoked.optString("type") == "SELF_REVOKED" &&
                revoked.optInt("protocolVersion") == 1 &&
                revoked.optString("androidDeviceId") == androidDeviceId) {
                revoked.optString("message", "Windows did not confirm device revocation.")
            }
        }

        // Remove the local pin only after Windows confirms that it revoked this identity.
        prefs.edit()
            .remove("trusted_windows_" + windowsDeviceId)
            .remove("trusted_windows_name_" + windowsDeviceId)
            .apply()
    }

    fun downloadFile(
        context: Context,
        host: String,
        port: Int,
        windowsDeviceId: String,
        shareId: String,
        relativePath: String,
        destination: Uri,
        onProgress: (Long, Long) -> Unit
    ): String {
        require(windowsDeviceId.matches(Regex("^[a-f0-9]{32}$"))) { "Invalid Windows device identity." }
        require(shareId.matches(Regex("^[a-fA-F0-9-]{36}$"))) { "Invalid shared folder ID." }
        require(relativePath.isNotBlank() && relativePath.length <= 2048 &&
            !relativePath.startsWith("/") && !relativePath.startsWith("\\\\") &&
            relativePath.split('/').none { it.isBlank() || it == "." || it == ".." || it.contains('\\') }) {
            "Invalid shared file path."
        }

        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val fingerprint = prefs.getString("trusted_windows_" + windowsDeviceId, null)
            ?: throw IllegalStateException("This Windows device is not paired.")
        require(fingerprint.matches(Regex("^[a-f0-9]{64}$")) && fingerprint.take(32) == windowsDeviceId) {
            "Saved Windows trust information is invalid."
        }
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        check(keyStore.containsAlias(KEY_ALIAS)) { "Android identity key is missing. Pair this device again." }
        val publicKey = keyStore.getCertificate(KEY_ALIAS).publicKey
        val privateKey = keyStore.getKey(KEY_ALIAS, null) as java.security.PrivateKey
        val androidDeviceId = prefs.getString("android_device_id", null)
            ?: throw IllegalStateException("Android device identity is missing. Pair this device again.")

        val tlsContext = SSLContext.getInstance("TLS")
        tlsContext.init(null, arrayOf(pinnedTrustManager(fingerprint)), SecureRandom())
        val socket = tlsContext.socketFactory.createSocket() as SSLSocket
        try {
            socket.use { tls ->
                tls.connect(InetSocketAddress(host, port), 5000)
                tls.tcpNoDelay = true
                tls.soTimeout = 120000
                tls.enabledProtocols = tls.supportedProtocols.filter {
                    it == "TLSv1.3" || it == "TLSv1.2"
                }.toTypedArray()
                check(tls.enabledProtocols.isNotEmpty()) { "TLS 1.2 or newer is required." }
                tls.startHandshake()

                writeLine(tls, JSONObject()
                    .put("type", "SESSION_HELLO")
                    .put("protocolVersion", 1)
                    .put("androidDeviceId", androidDeviceId)
                    .put("publicKey", android.util.Base64.encodeToString(publicKey.encoded, android.util.Base64.NO_WRAP)))

                val challengeResponse = JSONObject(readLine(tls.inputStream))
                check(challengeResponse.optString("type") == "SESSION_CHALLENGE" &&
                    challengeResponse.optInt("protocolVersion") == 1) {
                    challengeResponse.optString("message", "Windows rejected the secure session.")
                }
                val challenge = android.util.Base64.decode(challengeResponse.getString("challenge"), android.util.Base64.DEFAULT)
                require(challenge.size == 32) { "Windows session challenge is malformed." }
                val signer = Signature.getInstance("SHA256withECDSA")
                signer.initSign(privateKey)
                signer.update(challenge)
                writeLine(tls, JSONObject()
                    .put("type", "SESSION_PROOF")
                    .put("protocolVersion", 1)
                    .put("signature", android.util.Base64.encodeToString(signer.sign(), android.util.Base64.NO_WRAP)))

                val ready = JSONObject(readLine(tls.inputStream))
                check(ready.optString("type") == "SESSION_READY" &&
                    ready.optInt("protocolVersion") == 1 &&
                    ready.optString("windowsDeviceId") == windowsDeviceId) {
                    ready.optString("message", "Windows session identity did not match the saved trust record.")
                }
                val shares = ready.optJSONArray("shares") ?: org.json.JSONArray()
                check((0 until shares.length()).any { shares.getJSONObject(it).optString("shareId") == shareId }) {
                    "This shared folder is no longer available for reading."
                }

                writeLine(tls, JSONObject()
                    .put("type", "DOWNLOAD_FILE")
                    .put("protocolVersion", 1)
                    .put("shareId", shareId)
                    .put("path", relativePath))

                val start = JSONObject(readLine(tls.inputStream))
                if (start.optString("type") == "SESSION_ERROR" || start.optString("type") == "PAIR_ERROR")
                    throw IllegalStateException(start.optString("message", "Windows could not open this file."))
                check(start.optString("type") == "FILE_START" && start.optInt("protocolVersion") == 1) {
                    "Windows returned an invalid file-transfer response."
                }
                val expectedSize = start.optLong("size", -1)
                require(expectedSize >= 0) { "Windows returned an invalid file size." }
                check(start.optString("transferMode") == "RAW") {
                    "Windows selected an unsupported file-transfer mode."
                }
                val chunkSize = start.optInt("chunkSize", -1)
                require(chunkSize in (16 * 1024)..(1024 * 1024)) {
                    "Windows returned an invalid transfer buffer size."
                }
                val digest = MessageDigest.getInstance("SHA-256")
                var received = 0L
                val buffer = ByteArray(chunkSize)
                val input = tls.inputStream
                val output = context.contentResolver.openOutputStream(destination, "w")
                    ?: throw IllegalStateException("Android could not open the selected destination.")
                output.use { target ->
                    while (received < expectedSize) {
                        val requested = minOf(buffer.size.toLong(), expectedSize - received).toInt()
                        val count = input.read(buffer, 0, requested)
                        check(count > 0) { "Windows closed the connection before the complete file arrived." }
                        target.write(buffer, 0, count)
                        digest.update(buffer, 0, count)
                        received += count
                        onProgress(received, expectedSize)
                    }
                    target.flush()
                }

                val end = JSONObject(readLine(tls.inputStream))
                check(end.optString("type") == "FILE_END" &&
                    end.optInt("protocolVersion") == 1 &&
                    end.optLong("bytesSent", -1) == expectedSize &&
                    received == expectedSize) {
                    "Windows did not complete the file transfer."
                }
                val actualHash = digest.digest().joinToString("") { byte -> "%02x".format(byte) }
                val expectedHash = end.optString("sha256")
                check(expectedHash.matches(Regex("^[a-f0-9]{64}$")) &&
                    actualHash.equals(expectedHash, ignoreCase = true)) {
                    "SHA-256 verification failed. The downloaded file may be incomplete or corrupted."
                }
                return "Download complete · ${formatBytes(received)} · SHA-256 verified"
            }
        } catch (error: Exception) {
            runCatching { context.contentResolver.delete(destination, null, null) }
            throw error
        }
    }

    private fun formatBytes(value: Long): String = when {
        value >= 1024L * 1024 * 1024 -> "%.2f GB".format(value / (1024.0 * 1024 * 1024))
        value >= 1024L * 1024 -> "%.1f MB".format(value / (1024.0 * 1024))
        value >= 1024L -> "%.1f KB".format(value / 1024.0)
        else -> "$value B"
    }

    private fun pinnedTrustManager(expectedFingerprint: String): X509TrustManager =
        object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {
                throw java.security.cert.CertificateException("Client certificates are not used by this endpoint.")
            }

            override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
                if (chain.isEmpty()) throw java.security.cert.CertificateException("Windows did not present a TLS certificate.")
                val certificate = chain[0]
                certificate.checkValidity()
                val actual = MessageDigest.getInstance("SHA-256").digest(certificate.encoded)
                    .joinToString("") { byte -> "%02x".format(byte) }
                if (!actual.equals(expectedFingerprint, ignoreCase = true))
                    throw java.security.cert.CertificateException("Windows certificate fingerprint does not match the saved trust record.")
            }

            override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
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
