using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

namespace WiFiTransfer.App.Services;

public sealed record PairingApprovalRequest(string DeviceId, string DeviceName, string PublicKeyFingerprint);

public sealed class TlsHostService : IAsyncDisposable
{
    public const int Port = 45822;
    private readonly X509Certificate2 _certificate;
    private readonly PendingPairingRegistry _pendingPairing;
    private readonly TrustedDeviceStore _trustedDevices;
    private readonly SharedFolderStore _sharedFolders;
    private readonly Func<PairingApprovalRequest, Task<bool>> _approvePairing;
    private readonly CancellationTokenSource _shutdown = new();
    private TcpListener? _listener;

    public event Action<string>? SecureClientConnected;

    public TlsHostService(X509Certificate2 certificate, PendingPairingRegistry pendingPairing,
        TrustedDeviceStore trustedDevices, SharedFolderStore sharedFolders,
        Func<PairingApprovalRequest, Task<bool>> approvePairing)
    {
        _certificate = certificate ?? throw new ArgumentNullException(nameof(certificate));
        _pendingPairing = pendingPairing;
        _trustedDevices = trustedDevices;
        _sharedFolders = sharedFolders;
        _approvePairing = approvePairing;
        if (!certificate.HasPrivateKey) throw new ArgumentException("TLS certificate must have a private key.", nameof(certificate));
    }

    public Task StartAsync()
    {
        _listener = new TcpListener(IPAddress.Any, Port);
        _listener.Start();
        _ = AcceptLoopAsync(_shutdown.Token);
        return Task.CompletedTask;
    }

    private async Task AcceptLoopAsync(CancellationToken cancellationToken)
    {
        if (_listener is null) return;
        try
        {
            while (!cancellationToken.IsCancellationRequested)
                _ = HandleClientAsync(await _listener.AcceptTcpClientAsync(cancellationToken), cancellationToken);
        }
        catch (OperationCanceledException) { }
        catch (ObjectDisposedException) { }
        catch (SocketException) when (cancellationToken.IsCancellationRequested) { }
    }

    private async Task HandleClientAsync(TcpClient client, CancellationToken cancellationToken)
    {
        client.NoDelay = true;
        using (client)
        await using (var network = client.GetStream())
        await using (var tls = new System.Net.Security.SslStream(network, leaveInnerStreamOpen: false))
        {
            string? reservedNonce = null;
            var consumed = false;
            try
            {
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                timeout.CancelAfter(TimeSpan.FromMinutes(30));
                await tls.AuthenticateAsServerAsync(new System.Net.Security.SslServerAuthenticationOptions
                {
                    ServerCertificate = _certificate,
                    EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                    ClientCertificateRequired = false,
                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck
                }, timeout.Token);

                using var reader = new StreamReader(tls, new UTF8Encoding(false), false, 1024, leaveOpen: true);
                await using var writer = new StreamWriter(tls, new UTF8Encoding(false), 1024, leaveOpen: true)
                { AutoFlush = true, NewLine = "\n" };

                var helloLine = await ReadLineAsync(reader, timeout.Token);
                if (string.IsNullOrWhiteSpace(helloLine)) return;
                using var helloDoc = JsonDocument.Parse(helloLine);
                var hello = helloDoc.RootElement;
                var requestType = GetString(hello, "type");
                if (requestType == "SESSION_HELLO")
                {
                    await HandleAuthenticatedSessionAsync(hello, reader, writer, tls, timeout.Token);
                    return;
                }
                if (requestType != "PAIR_HELLO" || GetInt(hello, "protocolVersion") != 1)
                { await SendErrorAsync(writer, "Unsupported pairing request."); return; }

                var nonce = GetString(hello, "nonce");
                var deviceId = GetString(hello, "androidDeviceId");
                var deviceName = GetString(hello, "deviceName");
                var publicKeyBase64 = GetString(hello, "publicKey");
                var publicKeyAlgorithm = GetString(hello, "publicKeyAlgorithm");
                if (nonce is null || deviceId is null || !Guid.TryParse(deviceId, out _) ||
                    string.IsNullOrWhiteSpace(deviceName) || deviceName.Length > 64 ||
                    publicKeyAlgorithm != "ECDSA_P256" || publicKeyBase64 is null || publicKeyBase64.Length > 4096)
                { await SendErrorAsync(writer, "Pairing identity fields are invalid."); return; }

                if (!_pendingPairing.TryReserve(nonce))
                { await SendErrorAsync(writer, "QR nonce is invalid, expired, already in use, or consumed."); return; }
                reservedNonce = nonce;

                byte[] publicKeyBytes;
                using var ecdsa = ECDsa.Create();
                try
                {
                    publicKeyBytes = Convert.FromBase64String(publicKeyBase64);
                    ecdsa.ImportSubjectPublicKeyInfo(publicKeyBytes, out var bytesRead);
                    if (bytesRead != publicKeyBytes.Length || ecdsa.KeySize != 256)
                        throw new CryptographicException("Expected P-256 public key.");
                }
                catch (Exception ex) when (ex is FormatException or CryptographicException)
                { await SendErrorAsync(writer, "Android public key is invalid."); return; }

                var publicKeyFingerprint = Convert.ToHexString(SHA256.HashData(publicKeyBytes)).ToLowerInvariant();
                var existingTrustedDevice = _trustedDevices.GetAll()
                    .FirstOrDefault(d => d.DeviceId == deviceId && !d.IsRevoked);
                if (existingTrustedDevice is not null &&
                    !CryptographicOperations.FixedTimeEquals(
                        Convert.FromBase64String(existingTrustedDevice.PublicKeyBase64), publicKeyBytes))
                {
                    await SendErrorAsync(writer, "This Android device ID is already trusted with a different key. Revoke it before pairing a new identity.");
                    return;
                }

                var approved = await _approvePairing(new PairingApprovalRequest(deviceId, deviceName, publicKeyFingerprint));
                if (!approved) { await SendErrorAsync(writer, "Pairing was rejected on Windows."); return; }

                var challenge = RandomNumberGenerator.GetBytes(32);
                await writer.WriteLineAsync(JsonSerializer.Serialize(new
                { type = "PAIR_CHALLENGE", protocolVersion = 1, challenge = Convert.ToBase64String(challenge) }));

                var proofLine = await ReadLineAsync(reader, timeout.Token);
                if (string.IsNullOrWhiteSpace(proofLine)) return;
                using var proofDoc = JsonDocument.Parse(proofLine);
                var proof = proofDoc.RootElement;
                var signatureBase64 = GetString(proof, "signature");
                if (GetString(proof, "type") != "PAIR_PROOF" || GetInt(proof, "protocolVersion") != 1 || signatureBase64 is null)
                { await SendErrorAsync(writer, "Pairing proof message is invalid."); return; }

                byte[] signature;
                try { signature = Convert.FromBase64String(signatureBase64); }
                catch (FormatException) { await SendErrorAsync(writer, "Pairing proof signature is invalid."); return; }
                if (!ecdsa.VerifyData(challenge, signature, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence))
                { await SendErrorAsync(writer, "Android device identity proof failed."); return; }

                if (!_pendingPairing.TryConsume(nonce))
                {
                    await SendErrorAsync(writer, "QR nonce expired or was replaced before pairing completed. Refresh the QR and try again.");
                    return;
                }
                consumed = true;
                if (existingTrustedDevice is null)
                    _trustedDevices.AddOrReplace(deviceId, deviceName, publicKeyBase64);
                var certFingerprint = WindowsIdentityService.GetSha256Fingerprint(_certificate);
                await writer.WriteLineAsync(JsonSerializer.Serialize(new
                {
                    type = "PAIR_APPROVED", protocolVersion = 1,
                    windowsDeviceId = certFingerprint[..32], certificateSha256 = certFingerprint,
                    androidDeviceId = deviceId
                }));
                SecureClientConnected?.Invoke("Paired Android device " + deviceName + " (" +
                    (client.Client.RemoteEndPoint?.ToString() ?? "Unknown device") + ")");
            }
            catch (Exception ex) when (ex is IOException or JsonException or SocketException or
                OperationCanceledException or AuthenticationException or CryptographicException or
                InvalidDataException or InvalidOperationException)
            {
                // Failed and interrupted pairing attempts never create a trusted-device record.
            }
            finally
            {
                if (reservedNonce is not null && !consumed)
                    _pendingPairing.Release(reservedNonce);
            }
        }
    }


    private async Task HandleAuthenticatedSessionAsync(JsonElement hello, StreamReader reader,
        StreamWriter writer, System.Net.Security.SslStream tls, CancellationToken cancellationToken)
    {
        if (GetInt(hello, "protocolVersion") != 1)
        { await SendErrorAsync(writer, "Unsupported session protocol."); return; }

        var deviceId = GetString(hello, "androidDeviceId");
        var publicKeyBase64 = GetString(hello, "publicKey");
        if (deviceId is null || !Guid.TryParse(deviceId, out _) ||
            publicKeyBase64 is null || publicKeyBase64.Length > 4096)
        { await SendErrorAsync(writer, "Session identity fields are invalid."); return; }

        byte[] publicKeyBytes;
        using var identity = ECDsa.Create();
        try
        {
            publicKeyBytes = Convert.FromBase64String(publicKeyBase64);
            identity.ImportSubjectPublicKeyInfo(publicKeyBytes, out var bytesRead);
            if (bytesRead != publicKeyBytes.Length || identity.KeySize != 256)
                throw new CryptographicException("Expected P-256 public key.");
        }
        catch (Exception ex) when (ex is FormatException or CryptographicException)
        { await SendErrorAsync(writer, "Android public key is invalid."); return; }

        if (!IsTrustedIdentity(deviceId, publicKeyBytes))
        { await SendErrorAsync(writer, "This Android device is not trusted. Pair it again on Windows."); return; }

        var challenge = RandomNumberGenerator.GetBytes(32);
        await writer.WriteLineAsync(JsonSerializer.Serialize(new
        {
            type = "SESSION_CHALLENGE",
            protocolVersion = 1,
            challenge = Convert.ToBase64String(challenge)
        }));

        var proofLine = await ReadLineAsync(reader, cancellationToken);
        if (string.IsNullOrWhiteSpace(proofLine)) return;
        using var proofDocument = JsonDocument.Parse(proofLine);
        var proof = proofDocument.RootElement;
        if (GetString(proof, "type") != "SESSION_PROOF" ||
            GetInt(proof, "protocolVersion") != 1 ||
            GetString(proof, "signature") is not { } signatureText)
        { await SendErrorAsync(writer, "Session proof message is invalid."); return; }

        byte[] signature;
        try { signature = Convert.FromBase64String(signatureText); }
        catch (FormatException) { await SendErrorAsync(writer, "Session proof signature is invalid."); return; }

        if (!identity.VerifyData(challenge, signature, HashAlgorithmName.SHA256,
                DSASignatureFormat.Rfc3279DerSequence))
        { await SendErrorAsync(writer, "Android device authentication failed."); return; }

        // Re-check trust after proof and immediately before each directory operation.
        if (!IsTrustedIdentity(deviceId, publicKeyBytes))
        { await SendErrorAsync(writer, "This Android device was revoked."); return; }

        var certFingerprint = WindowsIdentityService.GetSha256Fingerprint(_certificate);
        var visibleShares = _sharedFolders.GetAll()
            .Where(share => share.CanRead)
            .Take(50)
            .Select(share => new
            {
                shareId = share.ShareId,
                name = share.DisplayName,
                canRead = share.CanRead,
                canWrite = share.CanWrite,
                canDelete = share.CanDelete,
                canStream = share.CanStream
            }).ToArray();

        await writer.WriteLineAsync(JsonSerializer.Serialize(new
        {
            type = "SESSION_READY",
            protocolVersion = 1,
            windowsDeviceId = certFingerprint[..32],
            deviceName = Environment.MachineName,
            shares = visibleShares
        }));
        SecureClientConnected?.Invoke("Authenticated session from " + deviceId);

        while (!cancellationToken.IsCancellationRequested)
        {
            var line = await ReadLineAsync(reader, cancellationToken);
            if (string.IsNullOrWhiteSpace(line)) return;
            using var requestDocument = JsonDocument.Parse(line);
            var request = requestDocument.RootElement;
            var requestType = GetString(request, "type");
            if (GetInt(request, "protocolVersion") != 1 ||
                requestType is not ("LIST_DIRECTORY" or "DOWNLOAD_FILE" or "UPLOAD_FILE" or "REVOKE_SELF"))
            {
                await SendErrorAsync(writer, "Unsupported authenticated session request.");
                continue;
            }

            if (!IsTrustedIdentity(deviceId, publicKeyBytes))
            {
                await SendErrorAsync(writer, "This Android device was revoked.");
                return;
            }

            if (requestType == "REVOKE_SELF")
            {
                var revoked = _trustedDevices.Revoke(deviceId);
                if (!revoked)
                {
                    await SendErrorAsync(writer, "This Android device is already revoked or is no longer trusted.");
                    return;
                }

                await writer.WriteLineAsync(JsonSerializer.Serialize(new
                {
                    type = "SELF_REVOKED",
                    protocolVersion = 1,
                    androidDeviceId = deviceId
                }));
                await writer.FlushAsync(cancellationToken);
                return;
            }

            if (!Guid.TryParse(GetString(request, "shareId"), out var shareId))
            {
                await SendErrorAsync(writer, "Shared folder ID is invalid.");
                continue;
            }

            if (requestType == "DOWNLOAD_FILE")
            {
                var fileRelativePath = GetString(request, "path");
                if (string.IsNullOrWhiteSpace(fileRelativePath) || fileRelativePath.Length > 2048)
                {
                    await SendErrorAsync(writer, "File path is invalid.");
                    continue;
                }

                var binaryTransferStarted = false;
                try
                {
                    if (!IsTrustedIdentity(deviceId, publicKeyBytes))
                    {
                        await SendErrorAsync(writer, "This Android device was revoked.");
                        return;
                    }

                    var filePath = _sharedFolders.ResolveAuthorizedPath(shareId, fileRelativePath, ShareOperation.Read);
                    var attributes = File.GetAttributes(filePath);
                    if ((attributes & FileAttributes.Directory) != 0 ||
                        (attributes & FileAttributes.ReparsePoint) != 0 ||
                        !File.Exists(filePath))
                        throw new UnauthorizedAccessException("The requested item is not a regular shared file.");

                    const int transferBufferSize = 256 * 1024;
                    await using var file = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read,
                        bufferSize: transferBufferSize, useAsync: true);
                    var expectedSize = file.Length;
                    await writer.WriteLineAsync(JsonSerializer.Serialize(new
                    {
                        type = "FILE_START",
                        protocolVersion = 1,
                        transferMode = "RAW",
                        chunkSize = transferBufferSize,
                        fileName = Path.GetFileName(filePath),
                        size = expectedSize
                    }));
                    await writer.FlushAsync(cancellationToken);

                    // After FILE_START, exactly expectedSize raw bytes follow on the TLS stream.
                    // The following FILE_END JSON line resumes the control-message framing.
                    binaryTransferStarted = true;
                    using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                    var buffer = new byte[transferBufferSize];
                    long sent = 0;
                    while (sent < expectedSize)
                    {
                        var read = await file.ReadAsync(buffer.AsMemory(0,
                            (int)Math.Min(buffer.Length, expectedSize - sent)), cancellationToken);
                        if (read == 0)
                            throw new IOException("The source file changed during transfer.");
                        hash.AppendData(buffer, 0, read);
                        await tls.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
                        sent += read;
                    }

                    await writer.WriteLineAsync(JsonSerializer.Serialize(new
                    {
                        type = "FILE_END",
                        protocolVersion = 1,
                        bytesSent = sent,
                        sha256 = Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant()
                    }));
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or OperationCanceledException)
                {
                    // Once raw bytes start, a JSON error would corrupt the fixed-length stream.
                    // Closing the TLS session makes the Android receiver detect an incomplete transfer.
                    if (binaryTransferStarted) return;
                    await writer.WriteLineAsync(JsonSerializer.Serialize(new
                    {
                        type = "SESSION_ERROR",
                        protocolVersion = 1,
                        message = ex.Message
                    }));
                }
                continue;
            }

            if (requestType == "CREATE_DIRECTORY")
            {
                var directoryRelativePath = GetString(request, "path");
                if (string.IsNullOrWhiteSpace(directoryRelativePath) || directoryRelativePath.Length > 2048 ||
                    directoryRelativePath.StartsWith('/') || directoryRelativePath.StartsWith('\\\\') ||
                    directoryRelativePath.Split('/', '\\\\').Any(segment =>
                        string.IsNullOrWhiteSpace(segment) || segment is "." or ".."))
                {
                    await SendErrorAsync(writer, "Folder path is invalid.");
                    continue;
                }

                try
                {
                    if (!IsTrustedIdentity(deviceId, publicKeyBytes))
                        throw new UnauthorizedAccessException("This Android device was revoked.");

                    var directoryPath = _sharedFolders.ResolveAuthorizedPath(
                        shareId, directoryRelativePath, ShareOperation.Write);
                    if (File.Exists(directoryPath))
                        throw new IOException("A file already exists with this folder name.");

                    if (Directory.Exists(directoryPath))
                    {
                        var attributes = File.GetAttributes(directoryPath);
                        if ((attributes & FileAttributes.ReparsePoint) != 0)
                            throw new UnauthorizedAccessException("Reparse-point folders cannot be used.");
                    }
                    else
                    {
                        Directory.CreateDirectory(directoryPath);
                    }

                    if (!IsTrustedIdentity(deviceId, publicKeyBytes))
                        throw new UnauthorizedAccessException("This Android device was revoked.");
                    _ = _sharedFolders.ResolveAuthorizedPath(shareId, directoryRelativePath, ShareOperation.Write);
                    await writer.WriteLineAsync(JsonSerializer.Serialize(new
                    {
                        type = "DIRECTORY_CREATED",
                        protocolVersion = 1,
                        path = directoryRelativePath
                    }));
                    await writer.FlushAsync(cancellationToken);
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
                {
                    await writer.WriteLineAsync(JsonSerializer.Serialize(new
                    {
                        type = "SESSION_ERROR",
                        protocolVersion = 1,
                        message = ex.Message
                    }));
                }
                continue;
            }

            if (requestType == "UPLOAD_FILE")
            {
                var uploadRelativePath = GetString(request, "path");
                var uploadSize = request.TryGetProperty("size", out var sizeElement) && sizeElement.TryGetInt64(out var parsedSize)
                    ? parsedSize : -1;
                var expectedHash = GetString(request, "sha256");
                if (string.IsNullOrWhiteSpace(uploadRelativePath) || uploadRelativePath.Length > 2048 ||
                    uploadSize < 0 || uploadSize > 4L * 1024 * 1024 * 1024 ||
                    expectedHash is null || !System.Text.RegularExpressions.Regex.IsMatch(expectedHash, "^[a-fA-F0-9]{64}$"))
                {
                    await SendErrorAsync(writer, "Upload metadata is invalid.");
                    continue;
                }

                string? temporaryPath = null;
                var rawUploadStarted = false;
                try
                {
                    if (!IsTrustedIdentity(deviceId, publicKeyBytes))
                        throw new UnauthorizedAccessException("This Android device was revoked.");

                    var destinationPath = _sharedFolders.ResolveAuthorizedPath(shareId, uploadRelativePath, ShareOperation.Write);
                    var fileName = Path.GetFileName(destinationPath);
                    if (string.IsNullOrWhiteSpace(fileName) || fileName is "." or ".." ||
                        !string.Equals(fileName, uploadRelativePath.Split('/', '\\').Last(), StringComparison.Ordinal))
                        throw new ArgumentException("Upload file name is invalid.");
                    var parentDirectory = Path.GetDirectoryName(destinationPath)
                        ?? throw new ArgumentException("Upload destination folder is invalid.");
                    if (!Directory.Exists(parentDirectory))
                        throw new DirectoryNotFoundException("The destination folder does not exist.");
                    if (File.Exists(destinationPath) || Directory.Exists(destinationPath))
                        throw new IOException("A file or folder with this name already exists.");

                    temporaryPath = Path.Combine(parentDirectory, ".droidshare-" + Guid.NewGuid().ToString("N") + ".upload");
                    const int uploadBufferSize = 256 * 1024;
                    await writer.WriteLineAsync(JsonSerializer.Serialize(new
                    {
                        type = "UPLOAD_READY",
                        protocolVersion = 1,
                        transferMode = "RAW",
                        chunkSize = uploadBufferSize,
                        size = uploadSize
                    }));
                    await writer.FlushAsync(cancellationToken);
                    rawUploadStarted = true;

                    using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                    await using (var destination = new FileStream(temporaryPath, FileMode.CreateNew, FileAccess.Write,
                        FileShare.None, uploadBufferSize, FileOptions.Asynchronous | FileOptions.WriteThrough))
                    {
                        var buffer = new byte[uploadBufferSize];
                        long received = 0;
                        while (received < uploadSize)
                        {
                            var count = await tls.ReadAsync(buffer.AsMemory(0,
                                (int)Math.Min(buffer.Length, uploadSize - received)), cancellationToken);
                            if (count <= 0) throw new IOException("Android closed the connection before upload completed.");
                            hash.AppendData(buffer, 0, count);
                            await destination.WriteAsync(buffer.AsMemory(0, count), cancellationToken);
                            received += count;
                        }
                        await destination.FlushAsync(cancellationToken);
                        destination.Flush(flushToDisk: true);
                    }

                    var endLine = await ReadLineAsync(reader, cancellationToken);
                    if (string.IsNullOrWhiteSpace(endLine))
                        throw new IOException("Upload completion message was not received.");
                    using var endDocument = JsonDocument.Parse(endLine);
                    var end = endDocument.RootElement;
                    var actualHash = Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
                    var reportedBytes = end.TryGetProperty("bytesSent", out var bytesElement) && bytesElement.TryGetInt64(out var parsedBytes)
                        ? parsedBytes : -1;
                    if (GetString(end, "type") != "UPLOAD_END" || GetInt(end, "protocolVersion") != 1 ||
                        reportedBytes != uploadSize ||
                        !string.Equals(GetString(end, "sha256"), actualHash, StringComparison.OrdinalIgnoreCase) ||
                        !string.Equals(actualHash, expectedHash, StringComparison.OrdinalIgnoreCase))
                        throw new InvalidDataException("Upload size or SHA-256 verification failed.");

                    if (!IsTrustedIdentity(deviceId, publicKeyBytes))
                        throw new UnauthorizedAccessException("This Android device was revoked during upload.");
                    _ = _sharedFolders.ResolveAuthorizedPath(shareId, uploadRelativePath, ShareOperation.Write);
                    if (File.Exists(destinationPath) || Directory.Exists(destinationPath))
                        throw new IOException("A file or folder with this name already exists.");
                    File.Move(temporaryPath, destinationPath, overwrite: false);
                    temporaryPath = null;
                    await writer.WriteLineAsync(JsonSerializer.Serialize(new
                    {
                        type = "UPLOAD_COMPLETE",
                        protocolVersion = 1,
                        bytesReceived = uploadSize,
                        sha256 = actualHash,
                        fileName
                    }));
                    await writer.FlushAsync(cancellationToken);
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or OperationCanceledException)
                {
                    if (temporaryPath is not null)
                    {
                        try { File.Delete(temporaryPath); } catch (IOException) { }
                    }
                    if (rawUploadStarted) return;
                    await writer.WriteLineAsync(JsonSerializer.Serialize(new
                    {
                        type = "SESSION_ERROR",
                        protocolVersion = 1,
                        message = ex.Message
                    }));
                }
                continue;
            }

            var relativePath = GetString(request, "path") ?? "";
            if (relativePath.Length > 2048)
            {
                await SendErrorAsync(writer, "Folder path is too long.");
                continue;
            }

            try
            {
                var directoryPath = _sharedFolders.ResolveAuthorizedPath(shareId, relativePath, ShareOperation.Read);
                if (!Directory.Exists(directoryPath))
                    throw new DirectoryNotFoundException("The requested folder does not exist.");

                var entryPaths = Directory.EnumerateFileSystemEntries(directoryPath)
                    .OrderBy(path => Directory.Exists(path) ? 0 : 1)
                    .ThenBy(path => Path.GetFileName(path), StringComparer.OrdinalIgnoreCase)
                    .Take(501)
                    .ToArray();
                var entries = new List<object>();
                foreach (var entryPath in entryPaths.Take(500))
                {
                    var attributes = File.GetAttributes(entryPath);
                    if ((attributes & FileAttributes.ReparsePoint) != 0) continue;
                    var isDirectory = (attributes & FileAttributes.Directory) != 0;
                    var info = isDirectory ? (FileSystemInfo)new DirectoryInfo(entryPath) : new FileInfo(entryPath);
                    entries.Add(new
                    {
                        name = info.Name,
                        isDirectory,
                        size = isDirectory ? 0L : ((FileInfo)info).Length,
                        modifiedUtc = info.LastWriteTimeUtc
                    });
                }

                var truncated = entryPaths.Length > 500;
                var listingJson = JsonSerializer.Serialize(new
                {
                    type = "DIRECTORY_LIST",
                    protocolVersion = 1,
                    shareId,
                    path = relativePath,
                    entries,
                    truncated
                });
                // Keep the response comfortably below the 16 KiB line protocol limit.
                while (Encoding.UTF8.GetByteCount(listingJson) > 12 * 1024 && entries.Count > 0)
                {
                    entries.RemoveAt(entries.Count - 1);
                    truncated = true;
                    listingJson = JsonSerializer.Serialize(new
                    {
                        type = "DIRECTORY_LIST",
                        protocolVersion = 1,
                        shareId,
                        path = relativePath,
                        entries,
                        truncated
                    });
                }
                await writer.WriteLineAsync(listingJson);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
            {
                await writer.WriteLineAsync(JsonSerializer.Serialize(new
                {
                    type = "SESSION_ERROR",
                    protocolVersion = 1,
                    message = ex.Message
                }));
            }
        }
    }

    private bool IsTrustedIdentity(string deviceId, byte[] publicKeyBytes)
    {
        var trusted = _trustedDevices.GetAll()
            .FirstOrDefault(device => device.DeviceId == deviceId && !device.IsRevoked);
        if (trusted is null) return false;
        try
        {
            return CryptographicOperations.FixedTimeEquals(
                Convert.FromBase64String(trusted.PublicKeyBase64), publicKeyBytes);
        }
        catch (FormatException) { return false; }
    }

    private static string? GetString(JsonElement e, string n) =>
        e.TryGetProperty(n, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
    private static int GetInt(JsonElement e, string n) =>
        e.TryGetProperty(n, out var v) && v.TryGetInt32(out var number) ? number : 0;
    private static Task SendErrorAsync(StreamWriter writer, string message) =>
        writer.WriteLineAsync(JsonSerializer.Serialize(new { type = "PAIR_ERROR", protocolVersion = 1, message }));

    private static async Task<string?> ReadLineAsync(StreamReader reader, CancellationToken cancellationToken)
    {
        var line = new StringBuilder();
        var buffer = new char[1];
        while (line.Length <= 16 * 1024)
        {
            var count = await reader.ReadAsync(buffer.AsMemory(), cancellationToken);
            if (count == 0) return line.Length == 0 ? null : line.ToString();
            if (buffer[0] == '\n') return line.ToString();
            if (buffer[0] != '\r') line.Append(buffer[0]);
        }
        throw new InvalidDataException("Protocol message exceeded 16 KiB.");
    }

    public ValueTask DisposeAsync()
    {
        _shutdown.Cancel();
        _pendingPairing.Invalidate();
        _listener?.Stop();
        _shutdown.Dispose();
        return ValueTask.CompletedTask;
    }
}