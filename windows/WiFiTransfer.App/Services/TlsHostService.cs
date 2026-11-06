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
    private readonly Func<PairingApprovalRequest, Task<bool>> _approvePairing;
    private readonly CancellationTokenSource _shutdown = new();
    private TcpListener? _listener;

    public event Action<string>? SecureClientConnected;

    public TlsHostService(X509Certificate2 certificate, PendingPairingRegistry pendingPairing,
        TrustedDeviceStore trustedDevices, Func<PairingApprovalRequest, Task<bool>> approvePairing)
    {
        _certificate = certificate ?? throw new ArgumentNullException(nameof(certificate));
        _pendingPairing = pendingPairing;
        _trustedDevices = trustedDevices;
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
        using (client)
        await using (var network = client.GetStream())
        await using (var tls = new System.Net.Security.SslStream(network, leaveInnerStreamOpen: false))
        {
            string? reservedNonce = null;
            var consumed = false;
            try
            {
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                timeout.CancelAfter(TimeSpan.FromSeconds(45));
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
                if (GetString(hello, "type") != "PAIR_HELLO" || GetInt(hello, "protocolVersion") != 1)
                { await SendErrorAsync(writer, "Unsupported pairing request."); return; }

                var nonce = GetString(hello, "nonce");
                var deviceId = GetString(hello, "androidDeviceId");
                var deviceName = GetString(hello, "deviceName");
                var publicKeyBase64 = GetString(hello, "publicKey");
                if (nonce is null || deviceId is null || !Guid.TryParse(deviceId, out _) ||
                    deviceName is null || deviceName.Length is < 1 or > 64 ||
                    publicKeyBase64 is null || publicKeyBase64.Length > 4096)
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
                if (_trustedDevices.GetAll().Any(d => d.DeviceId == deviceId && !d.IsRevoked))
                { await SendErrorAsync(writer, "This Android device is already paired. Revoke it before pairing again."); return; }

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
                if (!ecdsa.VerifyData(challenge, signature, HashAlgorithmName.SHA256))
                { await SendErrorAsync(writer, "Android device identity proof failed."); return; }

                if (!_pendingPairing.TryConsume(nonce))
                {
                    await SendErrorAsync(writer, "QR nonce expired or was replaced before pairing completed. Refresh the QR and try again.");
                    return;
                }
                consumed = true;
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