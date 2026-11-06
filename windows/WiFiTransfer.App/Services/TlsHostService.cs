using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

namespace WiFiTransfer.App.Services;

public sealed class TlsHostService : IAsyncDisposable
{
    public const int Port = 45822;
    private readonly X509Certificate2 _certificate;
    private readonly CancellationTokenSource _shutdown = new();
    private TcpListener? _listener;

    public event Action<string>? SecureClientConnected;

    public TlsHostService(X509Certificate2 certificate)
    {
        _certificate = certificate ?? throw new ArgumentNullException(nameof(certificate));
        if (!certificate.HasPrivateKey)
            throw new ArgumentException("The TLS server certificate must have a private key.", nameof(certificate));
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
            {
                var client = await _listener.AcceptTcpClientAsync(cancellationToken);
                _ = HandleClientAsync(client, cancellationToken);
            }
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
            try
            {
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                timeout.CancelAfter(TimeSpan.FromSeconds(8));
                await tls.AuthenticateAsServerAsync(new System.Net.Security.SslServerAuthenticationOptions
                {
                    ServerCertificate = _certificate,
                    EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                    ClientCertificateRequired = false,
                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck
                }, timeout.Token);

                using var reader = new StreamReader(tls, new UTF8Encoding(false), false, 1024, leaveOpen: true);
                await using var writer = new StreamWriter(tls, new UTF8Encoding(false), 1024, leaveOpen: true)
                {
                    AutoFlush = true,
                    NewLine = "\n"
                };

                var line = await ReadLineAsync(reader, timeout.Token);
                if (string.IsNullOrWhiteSpace(line) || line.Length > 16 * 1024) return;
                using var document = JsonDocument.Parse(line);
                var root = document.RootElement;
                var type = root.TryGetProperty("type", out var typeValue) ? typeValue.GetString() : null;
                var version = root.TryGetProperty("protocolVersion", out var versionValue)
                    ? versionValue.GetInt32() : 0;
                if (type != "SECURE_HELLO" || version != 1)
                {
                    await writer.WriteLineAsync("{\"type\":\"ERROR\",\"protocolVersion\":1,\"message\":\"Unsupported secure diagnostic handshake\"}");
                    return;
                }

                var remote = client.Client.RemoteEndPoint?.ToString() ?? "Unknown device";
                SecureClientConnected?.Invoke(remote);
                await writer.WriteLineAsync(JsonSerializer.Serialize(new
                {
                    type = "TLS_READY",
                    protocolVersion = 1,
                    server = "DroidShare-WiFi",
                    purpose = "certificate-pin-validation"
                }));
            }
            catch (Exception ex) when (ex is IOException or JsonException or SocketException or
                                           OperationCanceledException or AuthenticationException or
                                           InvalidDataException)
            {
                // Invalid TLS clients and incomplete diagnostic probes are isolated to this connection.
            }
        }
    }

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
        _listener?.Stop();
        _shutdown.Dispose();
        return ValueTask.CompletedTask;
    }
}
