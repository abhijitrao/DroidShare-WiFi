package com.droidshare.wifi

import android.os.Bundle
import android.os.SystemClock
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.graphics.Color
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
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

data class DiscoveryResult(val message: String, val shares: List<RemoteShare> = emptyList(), val host: String? = null, val tlsPort: Int = 0, val windowsDeviceId: String = "")

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

    private fun collectFolderUploadSources(
        treeUri: android.net.Uri,
        targetFolder: String
    ): Pair<List<SecureTlsProbe.UploadSource>, List<String>> {
        val resolver = contentResolver
        val rootDocumentId = android.provider.DocumentsContract.getTreeDocumentId(treeUri)
        val rootDocumentUri = android.provider.DocumentsContract.buildDocumentUriUsingTree(treeUri, rootDocumentId)
        val rootName = resolver.query(
            rootDocumentUri, arrayOf(android.provider.DocumentsContract.Document.COLUMN_DISPLAY_NAME),
            null, null, null
        )?.use { cursor ->
            if (cursor.moveToFirst()) cursor.getString(0) else null
        }?.takeIf { it.isNotBlank() } ?: throw IllegalStateException("Could not read the selected folder name.")

        fun validateSegment(value: String): String {
            require(value.isNotBlank() && value.length <= 240 && value !in setOf(".", "..") &&
                value.none { it == '/' || it == '\\' || it == '\u0000' }) {
                "Folder contains an invalid file or folder name."
            }
            return value
        }

        val rootPath = if (targetFolder.isBlank()) validateSegment(rootName)
            else "${targetFolder}/${validateSegment(rootName)}"
        val files = mutableListOf<SecureTlsProbe.UploadSource>()
        val directories = linkedSetOf<String>()
        val visited = hashSetOf<String>()

        fun walk(documentId: String, relativePath: String, depth: Int) {
            require(depth <= 64) { "Selected folder nesting exceeds 64 levels." }
            require(visited.add(documentId)) { "Folder provider returned a directory cycle." }
            directories.add(relativePath)
            val childrenUri = android.provider.DocumentsContract.buildChildDocumentsUriUsingTree(treeUri, documentId)
            resolver.query(
                childrenUri,
                arrayOf(
                    android.provider.DocumentsContract.Document.COLUMN_DOCUMENT_ID,
                    android.provider.DocumentsContract.Document.COLUMN_DISPLAY_NAME,
                    android.provider.DocumentsContract.Document.COLUMN_MIME_TYPE
                ),
                null, null, null
            )?.use { cursor ->
                val idColumn = cursor.getColumnIndexOrThrow(android.provider.DocumentsContract.Document.COLUMN_DOCUMENT_ID)
                val nameColumn = cursor.getColumnIndexOrThrow(android.provider.DocumentsContract.Document.COLUMN_DISPLAY_NAME)
                val mimeColumn = cursor.getColumnIndexOrThrow(android.provider.DocumentsContract.Document.COLUMN_MIME_TYPE)
                while (cursor.moveToNext()) {
                    val childId = cursor.getString(idColumn)
                    val childName = validateSegment(cursor.getString(nameColumn) ?: "")
                    val childPath = "${relativePath}/${childName}"
                    require(childPath.length <= 2048) { "A selected file or folder path is too long." }
                    if (cursor.getString(mimeColumn) == android.provider.DocumentsContract.Document.MIME_TYPE_DIR) {
                        walk(childId, childPath, depth + 1)
                    } else {
                        require(files.size < 1000) { "A folder upload is limited to 1,000 files." }
                        files.add(
                            SecureTlsProbe.UploadSource(
                                android.provider.DocumentsContract.buildDocumentUriUsingTree(treeUri, childId),
                                childPath
                            )
                        )
                    }
                    require(directories.size <= 10000) { "A folder upload is limited to 10,000 folders." }
                }
            } ?: throw IllegalStateException("Android could not read a folder's contents.")
        }

        walk(rootDocumentId, rootPath, 0)
        return files to directories.toList()
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
            var showDisconnectDialog by remember { mutableStateOf(false) }
            var tlsStatus by remember { mutableStateOf("Pairing has not been attempted.") }
            var connectedEndpoint by remember { mutableStateOf<Triple<String, Int, String>?>(null) }
            var pendingDownload by remember { mutableStateOf<Pair<RemoteShare, RemoteDirectoryEntry>?>(null) }
            var pendingUpload by remember { mutableStateOf<RemoteShare?>(null) }
            var transferStatus by remember { mutableStateOf<String?>(null) }
            var transferBytes by remember { mutableStateOf(0L) }
            var transferTotal by remember { mutableStateOf(0L) }
            var transferSpeed by remember { mutableStateOf(0L) }
            val scope = rememberCoroutineScope()
            fun browseShare(share: RemoteShare, path: String) {
                val endpoint = connectedEndpoint ?: return
                scope.launch {
                    busy = true
                    status = if (path.isBlank()) "Opening shared folder…" else "Opening $path…"
                    val result = withContext(Dispatchers.IO) {
                        runCatching {
                            SecureTlsProbe.connectTrusted(
                                this@MainActivity, endpoint.first, endpoint.second, endpoint.third,
                                share.shareId, path
                            ).firstOrNull { it.shareId == share.shareId }
                                ?: throw IllegalStateException("The shared folder is no longer available.")
                        }
                    }
                    result.onSuccess { browsed ->
                        discoveredShares.value = discoveredShares.value.map {
                            if (it.shareId == share.shareId) browsed else it
                        }
                        status = "Folder loaded."
                    }.onFailure {
                        status = "Could not open folder: " + (it.localizedMessage ?: "Connection error")
                    }
                    busy = false
                }
            }

            val downloadLauncher = rememberLauncherForActivityResult(
                ActivityResultContracts.CreateDocument("application/octet-stream")
            ) { destination ->
                val pending = pendingDownload
                val endpoint = connectedEndpoint
                pendingDownload = null
                if (destination == null) {
                    transferStatus = "Download cancelled."
                } else if (pending != null && endpoint != null) {
                    val (share, entry) = pending
                    val relativePath = if (share.currentPath.isBlank()) entry.name else share.currentPath + "/" + entry.name
                    scope.launch {
                        busy = true
                        transferBytes = 0L
                        transferTotal = entry.size
                        transferSpeed = 0L
                        transferStatus = "Preparing secure download…"
                        val transferStartedAt = SystemClock.elapsedRealtime()
                        val result = withContext(Dispatchers.IO) {
                            runCatching {
                                SecureTlsProbe.downloadFile(
                                    this@MainActivity, endpoint.first, endpoint.second, endpoint.third,
                                    share.shareId, relativePath, destination
                                ) { received, total ->
                                    transferBytes = received
                                    transferTotal = total
                                    val elapsed = (SystemClock.elapsedRealtime() - transferStartedAt).coerceAtLeast(1L)
                                    transferSpeed = received * 1000L / elapsed
                                }
                            }
                        }
                        result.onSuccess { transferStatus = it }
                            .onFailure { transferStatus = "Download failed: " + (it.localizedMessage ?: "Transfer error") }
                        busy = false
                    }
                }
            }

            val uploadLauncher = rememberLauncherForActivityResult(
                ActivityResultContracts.OpenMultipleDocuments()
            ) { selectedUris ->
                val share = pendingUpload
                val endpoint = connectedEndpoint
                pendingUpload = null
                if (selectedUris.isEmpty()) {
                    transferStatus = "Upload cancelled."
                } else if (share != null && endpoint != null) {
                    val sources = runCatching {
                        selectedUris.map { uri ->
                            runCatching {
                                contentResolver.takePersistableUriPermission(
                                    uri, android.content.Intent.FLAG_GRANT_READ_URI_PERMISSION
                                )
                            }
                            val name = contentResolver.query(
                                uri, arrayOf(android.provider.OpenableColumns.DISPLAY_NAME),
                                null, null, null
                            )?.use { cursor ->
                                if (cursor.moveToFirst()) cursor.getString(0) else null
                            }?.takeIf { it.isNotBlank() }
                                ?: throw IllegalArgumentException("Could not read a selected file name.")
                            SecureTlsProbe.UploadSource(
                                uri,
                                if (share.currentPath.isBlank()) name else "${share.currentPath}/$name"
                            )
                        }
                    }
                    sources.onSuccess { uploadSources ->
                        scope.launch {
                            busy = true
                            transferBytes = 0L
                            transferTotal = 0L
                            transferSpeed = 0L
                            transferStatus = "Preparing ${uploadSources.size} file(s)…"
                            val transferStartedAt = SystemClock.elapsedRealtime()
                            val result = withContext(Dispatchers.IO) {
                                runCatching {
                                    SecureTlsProbe.uploadFiles(
                                        this@MainActivity, endpoint.first, endpoint.second, endpoint.third,
                                        share.shareId, uploadSources
                                    ) { index, fileSent, fileTotal, totalSent, totalBytes ->
                                        transferBytes = totalSent
                                        transferTotal = totalBytes
                                        val elapsed = (SystemClock.elapsedRealtime() - transferStartedAt).coerceAtLeast(1L)
                                        transferSpeed = totalSent * 1000L / elapsed
                                        transferStatus = "Uploading ${index + 1}/${uploadSources.size} · ${fileSent} / ${fileTotal} bytes"
                                    }
                                }
                            }
                            result.onSuccess { messages ->
                                transferStatus = "Uploaded ${messages.size} file(s) · SHA-256 verified"
                                browseShare(share, share.currentPath)
                            }.onFailure {
                                transferStatus = "Upload failed: " + (it.localizedMessage ?: "Transfer error")
                            }
                            busy = false
                        }
                    }.onFailure {
                        transferStatus = "Could not prepare upload: " + (it.localizedMessage ?: "Invalid file")
                    }
                }
            }

                        val folderUploadLauncher = rememberLauncherForActivityResult(
                ActivityResultContracts.OpenDocumentTree()
            ) { treeUri ->
                val share = pendingUpload
                val endpoint = connectedEndpoint
                pendingUpload = null
                if (treeUri == null) {
                    transferStatus = "Folder upload cancelled."
                } else if (share != null && endpoint != null) {
                    runCatching {
                        contentResolver.takePersistableUriPermission(
                            treeUri, android.content.Intent.FLAG_GRANT_READ_URI_PERMISSION
                        )
                    }
                    scope.launch {
                        busy = true
                        transferBytes = 0L
                        transferTotal = 0L
                        transferSpeed = 0L
                        transferStatus = "Scanning selected folder…"
                        val transferStartedAt = SystemClock.elapsedRealtime()
                        val result = withContext(Dispatchers.IO) {
                            runCatching {
                                val (files, directories) = collectFolderUploadSources(treeUri, share.currentPath)
                                SecureTlsProbe.uploadFiles(
                                    this@MainActivity, endpoint.first, endpoint.second, endpoint.third,
                                    share.shareId, files, directories
                                ) { index, fileSent, fileTotal, totalSent, totalBytes ->
                                    transferBytes = totalSent
                                    transferTotal = totalBytes
                                    val elapsed = (SystemClock.elapsedRealtime() - transferStartedAt).coerceAtLeast(1L)
                                    transferSpeed = totalSent * 1000L / elapsed
                                    transferStatus = if (files.isEmpty()) {
                                        "Creating folder structure…"
                                    } else {
                                        "Uploading ${index + 1}/${files.size} · ${fileSent} / ${fileTotal} bytes"
                                    }
                                }
                                "Uploaded folder structure · ${files.size} file(s), ${directories.size} folder(s)"
                            }
                        }
                        result.onSuccess {
                            transferStatus = it
                            browseShare(share, share.currentPath)
                        }.onFailure {
                            transferStatus = "Folder upload failed: " + (it.localizedMessage ?: "Transfer error")
                        }
                        busy = false
                    }
                }
            }

            LaunchedEffect(Unit) {
                busy = true
                status = "Checking for a previously paired Windows device…"
                val result = withContext(Dispatchers.IO) { discoverAndHandshake(autoReconnectOnly = true) }
                status = result.message
                discoveredShares.value = result.shares
                connectedEndpoint = if (
                    result.host != null && result.tlsPort in 1..65535 &&
                    result.windowsDeviceId.isNotBlank()
                ) Triple(result.host, result.tlsPort, result.windowsDeviceId) else null
                busy = false
            }


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
                                            connectedEndpoint = if (result.host != null && result.tlsPort in 1..65535 && result.windowsDeviceId.isNotBlank()) Triple(result.host, result.tlsPort, result.windowsDeviceId) else null
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
                                Spacer(Modifier.height(10.dp))
                                OutlinedButton(
                                    modifier = Modifier.fillMaxWidth().height(48.dp),
                                    enabled = !busy,
                                    shape = androidx.compose.foundation.shape.RoundedCornerShape(14.dp),
                                    colors = ButtonDefaults.outlinedButtonColors(
                                        contentColor = androidx.compose.ui.graphics.Color(0xFFB45353)
                                    ),
                                    onClick = { showDisconnectDialog = true }
                                ) {
                                    Text("Disconnect & forget device")
                                }
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
                                                if (tlsStatus.startsWith("Paired")) {
                                                    connectedEndpoint = Triple(pairing.host, pairing.port, pairing.deviceId)
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

                        if (transferStatus != null) {
                            Spacer(Modifier.height(16.dp))
                            Card(
                                modifier = Modifier.fillMaxWidth(),
                                shape = androidx.compose.foundation.shape.RoundedCornerShape(16.dp),
                                colors = CardDefaults.cardColors(containerColor = androidx.compose.ui.graphics.Color.White)
                            ) {
                                Column(Modifier.padding(16.dp)) {
                                    Row(verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
                                        Text("FILE TRANSFER", color = muted, style = MaterialTheme.typography.labelMedium,
                                            fontWeight = androidx.compose.ui.text.font.FontWeight.Bold)
                                        Spacer(Modifier.weight(1f))
                                        if (busy) CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp)
                                    }
                                    Spacer(Modifier.height(8.dp))
                                    Text(transferStatus ?: "", color = ink, style = MaterialTheme.typography.bodyMedium)
                                    if (busy && transferTotal > 0L) {
                                        Spacer(Modifier.height(10.dp))
                                        LinearProgressIndicator(
                                            progress = (transferBytes.toFloat() / transferTotal.toFloat()).coerceIn(0f, 1f),
                                            modifier = Modifier.fillMaxWidth()
                                        )
                                        Spacer(Modifier.height(6.dp))
                                        Text("${formatFileSize(transferBytes)} of ${formatFileSize(transferTotal)} · ${formatFileSize(transferSpeed)}/s",
                                            color = muted, style = MaterialTheme.typography.labelSmall)
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
                                        if (share.canWrite) {
                                            OutlinedButton(
                                                modifier = Modifier.fillMaxWidth(),
                                                enabled = !busy && connectedEndpoint != null,
                                                shape = androidx.compose.foundation.shape.RoundedCornerShape(12.dp),
                                                onClick = {
                                                    pendingUpload = share
                                                    uploadLauncher.launch(arrayOf("*/*"))
                                                }
                                            ) {
                                                Text(if (share.currentPath.isBlank()) "UPLOAD TO THIS FOLDER" else "UPLOAD TO CURRENT FOLDER",
                                                    color = violet)
                                            }
                                            OutlinedButton(
                                                modifier = Modifier.fillMaxWidth(),
                                                enabled = !busy && connectedEndpoint != null,
                                                shape = androidx.compose.foundation.shape.RoundedCornerShape(12.dp),
                                                onClick = {
                                                    pendingUpload = share
                                                    folderUploadLauncher.launch(null)
                                                }
                                            ) {
                                                Text("UPLOAD FOLDER", color = violet)
                                            }
                                        }
                                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                            if (share.canWrite) PermissionTag("WRITE", violet)
                                            if (share.canDelete) PermissionTag("DELETE", androidx.compose.ui.graphics.Color(0xFFB45353))
                                            if (share.canStream) PermissionTag("STREAM", green)
                                        }
                                        if (share.currentPath.isNotEmpty()) {
                                            Row(verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
                                                TextButton(
                                                    enabled = !busy && connectedEndpoint != null,
                                                    onClick = { browseShare(share, share.currentPath.substringBeforeLast('/', "")) }
                                                ) { Text("← Back") }
                                                Spacer(Modifier.width(4.dp))
                                                TextButton(
                                                    enabled = !busy && connectedEndpoint != null,
                                                    onClick = { browseShare(share, "") }
                                                ) { Text(share.name) }
                                                var breadcrumbPath = ""
                                                share.currentPath.split('/').filter { it.isNotBlank() }.forEach { segment ->
                                                    breadcrumbPath = if (breadcrumbPath.isBlank()) segment else breadcrumbPath + "/" + segment
                                                    Text("›", color = muted)
                                                    val targetPath = breadcrumbPath
                                                    TextButton(
                                                        enabled = !busy && connectedEndpoint != null,
                                                        onClick = { browseShare(share, targetPath) }
                                                    ) { Text(segment, maxLines = 1) }
                                                }
                                            }
                                        } else {
                                            Text("Shared folder", color = muted, style = MaterialTheme.typography.labelSmall)
                                        }
                                        if (share.entries.isEmpty()) {
                                            Text("This folder is empty.", color = muted,
                                                style = MaterialTheme.typography.bodySmall,
                                                modifier = Modifier.padding(top = 12.dp))
                                        } else {
                                            Spacer(Modifier.height(8.dp))
                                            share.entries.forEach { entry ->
                                                Row(
                                                    modifier = Modifier.fillMaxWidth().padding(vertical = 5.dp)
                                                        .then(if (entry.isDirectory) Modifier.clickable(enabled = !busy && connectedEndpoint != null) {
                                                            val endpoint = connectedEndpoint
                                                            if (endpoint != null) {
                                                                val childPath = if (share.currentPath.isBlank()) entry.name else share.currentPath + "/" + entry.name
                                                                browseShare(share, childPath)
                                                            }
                                                        } else Modifier),
                                                    verticalAlignment = androidx.compose.ui.Alignment.CenterVertically
                                                ) {
                                                    Text(if (entry.isDirectory) "📁" else "📄")
                                                    Spacer(Modifier.width(9.dp))
                                                    Text(entry.name, color = ink, style = MaterialTheme.typography.bodySmall,
                                                        modifier = Modifier.weight(1f), maxLines = 1)
                                                    if (entry.isDirectory) {
                                                        Text("OPEN  ›", color = violet,
                                                            style = MaterialTheme.typography.labelSmall)
                                                    } else {
                                                        Column(horizontalAlignment = androidx.compose.ui.Alignment.End) {
                                                            Text(formatFileSize(entry.size), color = muted,
                                                                style = MaterialTheme.typography.labelSmall)
                                                            TextButton(
                                                                enabled = !busy && connectedEndpoint != null,
                                                                onClick = {
                                                                    pendingDownload = share to entry
                                                                    downloadLauncher.launch(entry.name)
                                                                },
                                                                contentPadding = PaddingValues(horizontal = 6.dp, vertical = 0.dp)
                                                            ) { Text("DOWNLOAD", color = violet, style = MaterialTheme.typography.labelSmall) }
                                                        }
                                                    }
                                                }
                                            }
                                            if (share.truncated)
                                                Text("This folder contains more items. The list is limited for safety.",
                                                    color = muted, style = MaterialTheme.typography.labelSmall,
                                                    modifier = Modifier.padding(top = 6.dp))
                                        }
                                    }
                                }
                            }
                        }

                        Spacer(Modifier.height(18.dp))
                        Text("Both devices must allow local device communication. QR pairing does not bypass Wi-Fi client isolation or firewall rules.",
                            style = MaterialTheme.typography.bodySmall, color = muted)
                    }

                    if (showDisconnectDialog) {
                        AlertDialog(
                            onDismissRequest = { if (!busy) showDisconnectDialog = false },
                            title = { Text("Disconnect and forget Windows device?") },
                            text = {
                                Text(
                                    if (connectedEndpoint != null) {
                                        "DroidShare will ask Windows to revoke this Android device, then remove the saved trust on this phone. Automatic reconnect will stop. To connect again, scan the Windows QR and approve pairing on Windows."
                                    } else {
                                        "Windows is currently unreachable. DroidShare will remove the saved pairing from this phone so it will not auto-reconnect. Windows may still list this phone as trusted; if needed, revoke it later from the Windows Trusted Devices screen."
                                    }
                                )
                            },
                            confirmButton = {
                                TextButton(
                                    enabled = !busy,
                                    onClick = {
                                        val endpoint = connectedEndpoint
                                        scope.launch {
                                            busy = true
                                            val result = withContext(Dispatchers.IO) {
                                                runCatching {
                                                    if (endpoint != null) {
                                                        SecureTlsProbe.disconnectAndForget(
                                                            this@MainActivity,
                                                            endpoint.first,
                                                            endpoint.second,
                                                            endpoint.third
                                                        )
                                                    } else {
                                                        SecureTlsProbe.forgetSavedWindowsTrust(this@MainActivity)
                                                    }
                                                }
                                            }
                                            result.onSuccess {
                                                connectedEndpoint = null
                                                discoveredShares.value = emptyList()
                                                scannedQr.value = null
                                                scanMessage.value = "Saved pairing forgotten. Scan the Windows QR to pair again."
                                                tlsStatus = if (endpoint != null) {
                                                    "Windows trust revoked and local pairing forgotten."
                                                } else {
                                                    "Local pairing forgotten. Windows-side trust was not changed."
                                                }
                                                status = if (endpoint != null) {
                                                    "Windows device disconnected and forgotten."
                                                } else {
                                                    "Saved Windows pairing forgotten on this phone."
                                                }
                                                transferStatus = null
                                            }.onFailure {
                                                status = "Could not disconnect and forget: " + (it.localizedMessage ?: "Connection error")
                                            }
                                            busy = false
                                            showDisconnectDialog = false
                                        }
                                    }
                                ) { Text("Disconnect & forget", color = androidx.compose.ui.graphics.Color(0xFFB45353)) }
                            },
                            dismissButton = {
                                TextButton(
                                    enabled = !busy,
                                    onClick = { showDisconnectDialog = false }
                                ) { Text("Keep connected") }
                            }
                        )
                    }
                }
            }
        }
    }

    private fun discoverAndHandshake(autoReconnectOnly: Boolean = false): DiscoveryResult {
        if (!autoReconnectOnly) return discoverAndHandshakeOnce(autoReconnectOnly = false)

        // Wi-Fi may still be associating or restoring its LAN route immediately after app launch.
        // Retry discovery and the authenticated session sequentially; never weaken trust checks.
        val retryDelaysMs = longArrayOf(0L, 1000L, 2000L, 3000L)
        var lastResult = DiscoveryResult("No previously paired Windows device found.")
        for (delayMs in retryDelaysMs) {
            if (delayMs > 0) Thread.sleep(delayMs)
            lastResult = discoverAndHandshakeOnce(autoReconnectOnly = true)
            if (lastResult.host != null) return lastResult
        }
        return DiscoveryResult(
            "Could not reconnect after ${retryDelaysMs.size} attempts. ${lastResult.message}",
            emptyList()
        )
    }

    private fun discoverAndHandshakeOnce(autoReconnectOnly: Boolean): DiscoveryResult {
        val request = "DROIDSHARE_DISCOVER_V1".toByteArray(StandardCharsets.UTF_8)
        return try {
            val connectivity = getSystemService(android.content.Context.CONNECTIVITY_SERVICE)
                as android.net.ConnectivityManager
            val wifiNetwork = connectivity.allNetworks.firstOrNull { network ->
                connectivity.getNetworkCapabilities(network)
                    ?.hasTransport(android.net.NetworkCapabilities.TRANSPORT_WIFI) == true
            } ?: throw IllegalStateException("No active Wi-Fi network found. Connect the phone to the same Wi-Fi as Windows.")

            val wifiLink = connectivity.getLinkProperties(wifiNetwork)
                ?: throw IllegalStateException("Could not read the active Wi-Fi network configuration.")
            val ipv4Link = wifiLink.linkAddresses.firstOrNull {
                it.address is java.net.Inet4Address
            } ?: throw IllegalStateException("The active Wi-Fi network has no IPv4 address.")

            val ipBytes = ipv4Link.address.address
            val prefix = ipv4Link.prefixLength
            val broadcastBytes = ipBytes.copyOf()
            for (index in broadcastBytes.indices) {
                val bitsRemaining = prefix - (index * 8)
                val mask = when {
                    bitsRemaining >= 8 -> 0xFF
                    bitsRemaining <= 0 -> 0
                    else -> (0xFF shl (8 - bitsRemaining)) and 0xFF
                }
                broadcastBytes[index] = ((ipBytes[index].toInt() and 0xFF) or (mask.inv() and 0xFF)).toByte()
            }
            val broadcast = InetAddress.getByAddress(broadcastBytes)

            DatagramSocket(null).use { udp ->
                // Bind discovery to Wi-Fi explicitly. The default Android route may still point
                // to mobile data or a previous network immediately after a Wi-Fi switch.
                wifiNetwork.bindSocket(udp)
                udp.bind(null)
                udp.broadcast = true
                udp.soTimeout = 3500
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
                            shares,
                            response.address.hostAddress,
                            tlsPort,
                            windowsDeviceId
                        )
                    }
                }

                if (autoReconnectOnly) {
                    return DiscoveryResult(
                        "No previously paired Windows device found. Tap Find Windows device or scan its QR to connect."
                    )
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
