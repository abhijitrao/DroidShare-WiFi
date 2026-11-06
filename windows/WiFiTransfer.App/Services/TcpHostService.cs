using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;

namespace WiFiTransfer.App.Services;

public sealed class TcpHostService : IAsyncDisposable
{
    public const int Port = 45821;
    private readonly CancellationTokenSource _shutdown = new();
    private TcpListener? _listener;

    public event Action<string>? ClientConnected;

    public async Task StartAsync()
    {
        _listener = new TcpListener(IPAddress.Any, Port);
        _listener.Start();
        _ = AcceptLoopAsync(_shutdown.Token);
        await Task.CompletedTask;
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
        {
            client.ReceiveTimeout = 5000;
            client.SendTimeout = 5000;
            await using var stream = client.GetStream();
            using var reader = new StreamReader(stream, new UTF8Encoding(false), false, 1024, leaveOpen: true);
            await using var writer = new StreamWriter(stream, new UTF8Encoding(false), 1024, leaveOpen: true)
            {
                AutoFlush = true,
                NewLine = "\n"
            };

            try
            {
                var line = await reader.ReadLineAsync(cancellationToken);
                if (string.IsNullOrWhiteSpace(line) || line.Length > 16 * 1024) return;

                using var document = JsonDocument.Parse(line);
                var root = document.RootElement;
                var type = root.TryGetProperty("type", out var typeValue) ? typeValue.GetString() : null;
                var version = root.TryGetProperty("protocolVersion", out var versionValue) ? versionValue.GetInt32() : 0;

                if (type != "HELLO" || version != 1)
                {
                    await writer.WriteLineAsync("{\"type\":\"ERROR\",\"protocolVersion\":1,\"message\":\"Unsupported handshake\"}");
                    return;
                }

                var remote = client.Client.RemoteEndPoint?.ToString() ?? "Unknown device";
                ClientConnected?.Invoke(remote);
                await writer.WriteLineAsync(JsonSerializer.Serialize(new
                {
                    type = "WELCOME",
                    protocolVersion = 1,
                    server = "DroidShare-WiFi"
                }));
            }
            catch (Exception ex) when (ex is IOException or JsonException or SocketException or OperationCanceledException)
            {
                // A malformed or disconnected diagnostic client must not stop the listener.
            }
        }
    }

    public ValueTask DisposeAsync()
    {
        _shutdown.Cancel();
        _listener?.Stop();
        _shutdown.Dispose();
        return ValueTask.CompletedTask;
    }
}
