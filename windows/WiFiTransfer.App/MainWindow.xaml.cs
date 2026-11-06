using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Windows;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using QRCoder;
using WiFiTransfer.App.Services;

namespace WiFiTransfer.App;

public partial class MainWindow : Window
{
    private readonly TcpHostService _tcp = new();
    private TlsHostService? _tls;
    private readonly UdpDiscoveryService _discovery = new();
    private readonly WindowsIdentityService _identityService = new();
    private readonly PairingQrService _pairingQrService = new();
    private readonly DispatcherTimer _qrExpiryTimer = new() { Interval = TimeSpan.FromSeconds(1) };
    private X509Certificate2? _certificate;
    private PairingQrData? _pairingQrData;

    public MainWindow()
    {
        InitializeComponent();
        Loaded += OnLoaded;
        Closed += OnClosed;
        _qrExpiryTimer.Tick += OnQrExpiryTimerTick;
    }

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        try
        {
            _certificate = _identityService.GetOrCreateCertificate();
            _tls = new TlsHostService(_certificate);
            await _tls.StartAsync();
            _tls.SecureClientConnected += remote =>
                Dispatcher.Invoke(() => LastEventText.Text = $"Certificate-pinned TLS diagnostic from {remote}");
            await _tcp.StartAsync();
            await _discovery.StartAsync();
            _tcp.ClientConnected += remote =>
                Dispatcher.Invoke(() => LastEventText.Text = $"Android diagnostic handshake from {remote}");

            StatusText.Text = "Running — waiting for Android discovery";
            var addresses = GetLocalIpv4Addresses();
            NetworkText.Text = addresses.Count == 0
                ? "No active IPv4 interface detected"
                : $"Active IPv4: {string.Join("  •  ", addresses)}";

            FingerprintText.Text = $"Certificate SHA-256: {WindowsIdentityService.GetSha256Fingerprint(_certificate)}";
            RefreshQrButton.IsEnabled = addresses.Count > 0;
            if (addresses.Count > 0)
                CreateQrPreview(addresses[0]);
            else
                PairingStatusText.Text = "Connect Windows to Wi-Fi, then refresh the QR preview.";
        }
        catch (Exception ex)
        {
            StatusText.Text = $"Could not start services: {ex.Message}";
            PairingStatusText.Text = "Could not prepare the Windows pairing identity.";
        }
    }

    private void RefreshQrButton_Click(object sender, RoutedEventArgs e)
    {
        var address = GetLocalIpv4Addresses().FirstOrDefault();
        if (address is null || _certificate is null)
        {
            PairingStatusText.Text = "No active IPv4 address or Windows certificate is available.";
            return;
        }

        CreateQrPreview(address);
    }

    private void CreateQrPreview(string hostAddress)
    {
        if (_certificate is null) return;

        _pairingQrData = _pairingQrService.Create(_certificate, hostAddress);
        using var generator = new QRCodeGenerator();
        using var data = generator.CreateQrCode(_pairingQrData.Payload, QRCodeGenerator.ECCLevel.Q);
        var png = new PngByteQRCode(data).GetGraphic(8);

        using var memory = new MemoryStream(png);
        var bitmap = new BitmapImage();
        bitmap.BeginInit();
        bitmap.CacheOption = BitmapCacheOption.OnLoad;
        bitmap.StreamSource = memory;
        bitmap.EndInit();
        bitmap.Freeze();

        PairingQrImage.Source = bitmap;
        PairingStatusText.Text =
            $"TLS diagnostic endpoint · {Environment.MachineName} · {hostAddress}:{TlsHostService.Port}. " +
            "QR scan and TLS pin check are available; pairing and file access remain disabled.";
        UpdateQrExpiryText();
        _qrExpiryTimer.Start();
    }

    private void OnQrExpiryTimerTick(object? sender, EventArgs e)
    {
        UpdateQrExpiryText();
        if (_pairingQrData is not null && DateTimeOffset.UtcNow >= _pairingQrData.ExpiresAt)
        {
            _qrExpiryTimer.Stop();
            PairingQrImage.Source = null;
            PairingStatusText.Text = "QR preview expired. Refresh it when the secure pairing flow is ready.";
            ExpiryText.Text = "QR expires in: expired";
        }
    }

    private void UpdateQrExpiryText()
    {
        if (_pairingQrData is null) return;
        var remaining = _pairingQrData.ExpiresAt - DateTimeOffset.UtcNow;
        ExpiryText.Text = remaining <= TimeSpan.Zero
            ? "QR expires in: expired"
            : $"QR preview expires in: {Math.Ceiling(remaining.TotalSeconds)} seconds";
    }

    private async void OnClosed(object? sender, EventArgs e)
    {
        _qrExpiryTimer.Stop();
        _pairingQrData = null;
        _certificate?.Dispose();
        if (_tls is not null) await _tls.DisposeAsync();
        await _discovery.DisposeAsync();
        await _tcp.DisposeAsync();
    }

    private static IReadOnlyList<string> GetLocalIpv4Addresses()
    {
        return NetworkInterface.GetAllNetworkInterfaces()
            .Where(n => n.OperationalStatus == OperationalStatus.Up &&
                        n.NetworkInterfaceType != NetworkInterfaceType.Loopback)
            .OrderByDescending(n => n.NetworkInterfaceType == NetworkInterfaceType.Wireless80211)
            .SelectMany(n => n.GetIPProperties().UnicastAddresses)
            .Where(a => a.Address.AddressFamily == AddressFamily.InterNetwork &&
                        !IPAddress.IsLoopback(a.Address) &&
                        !a.Address.ToString().StartsWith("169.254.", StringComparison.Ordinal))
            .Select(a => a.Address.ToString())
            .Distinct()
            .ToArray();
    }
}
