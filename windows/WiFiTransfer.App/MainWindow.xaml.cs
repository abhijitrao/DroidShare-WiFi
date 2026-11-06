using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Windows;
using WiFiTransfer.App.Services;

namespace WiFiTransfer.App;

public partial class MainWindow : Window
{
    private readonly TcpHostService _tcp = new();
    private readonly UdpDiscoveryService _discovery = new();

    public MainWindow()
    {
        InitializeComponent();
        Loaded += OnLoaded;
        Closed += OnClosed;
    }

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        try
        {
            await _tcp.StartAsync();
            await _discovery.StartAsync();
            _tcp.ClientConnected += remote =>
                Dispatcher.Invoke(() => LastEventText.Text = $"Android diagnostic handshake from {remote}");
            StatusText.Text = "Running — waiting for Android discovery";
            NetworkText.Text = $"Active IPv4: {GetLocalIpv4Summary()}";
        }
        catch (Exception ex)
        {
            StatusText.Text = $"Could not start network services: {ex.Message}";
        }
    }

    private async void OnClosed(object? sender, EventArgs e)
    {
        await _discovery.DisposeAsync();
        await _tcp.DisposeAsync();
    }

    private static string GetLocalIpv4Summary()
    {
        var addresses = NetworkInterface.GetAllNetworkInterfaces()
            .Where(n => n.OperationalStatus == OperationalStatus.Up &&
                        n.NetworkInterfaceType != NetworkInterfaceType.Loopback)
            .SelectMany(n => n.GetIPProperties().UnicastAddresses)
            .Where(a => a.Address.AddressFamily == AddressFamily.InterNetwork &&
                        !IPAddress.IsLoopback(a.Address))
            .Select(a => a.Address.ToString())
            .Distinct()
            .ToArray();

        return addresses.Length == 0 ? "No active IPv4 interface detected" : string.Join("  •  ", addresses);
    }
}
