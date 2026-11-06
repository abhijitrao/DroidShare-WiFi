using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;

namespace WiFiTransfer.App.Services;

public sealed class UdpDiscoveryService : IAsyncDisposable
{
    public const int Port = 45820;
    private readonly CancellationTokenSource _shutdown = new();
    private UdpClient? _udp;
    public string WindowsDeviceId { get; set; } = string.Empty;

    public async Task StartAsync()
    {
        _udp = new UdpClient(AddressFamily.InterNetwork);
        _udp.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
        _udp.Client.Bind(new IPEndPoint(IPAddress.Any, Port));
        _ = ReceiveLoopAsync(_shutdown.Token);
        await Task.CompletedTask;
    }

    private async Task ReceiveLoopAsync(CancellationToken cancellationToken)
    {
        if (_udp is null) return;

        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                var packet = await _udp.ReceiveAsync(cancellationToken);
                var message = Encoding.UTF8.GetString(packet.Buffer);
                if (!string.Equals(message, "DROIDSHARE_DISCOVER_V1", StringComparison.Ordinal))
                    continue;

                var response = JsonSerializer.SerializeToUtf8Bytes(new
                {
                    type = "DROIDSHARE_DEVICE",
                    protocolVersion = 1,
                    deviceName = Environment.MachineName,
                    deviceId = WindowsDeviceId,
                    tlsPort = TlsHostService.Port,
                    tcpPort = TcpHostService.Port
                });

                await _udp.SendAsync(response, packet.RemoteEndPoint, cancellationToken);
            }
        }
        catch (OperationCanceledException) { }
        catch (ObjectDisposedException) { }
        catch (SocketException) when (cancellationToken.IsCancellationRequested) { }
    }

    public ValueTask DisposeAsync()
    {
        _shutdown.Cancel();
        _udp?.Dispose();
        _shutdown.Dispose();
        return ValueTask.CompletedTask;
    }
}
