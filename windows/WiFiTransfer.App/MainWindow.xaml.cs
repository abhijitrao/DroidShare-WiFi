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
    private readonly PendingPairingRegistry _pendingPairing = new();
    private readonly TrustedDeviceStore _trustedDevices = new();
    private readonly SharedFolderStore _sharedFolders = new();
    private PairingQrService _pairingQrService = null!;
    private readonly DispatcherTimer _qrExpiryTimer = new() { Interval = TimeSpan.FromSeconds(1) };
    private X509Certificate2? _certificate;
    private PairingQrData? _pairingQrData;

    public MainWindow()
    {
        InitializeComponent();
        _pairingQrService = new PairingQrService(_pendingPairing);
        Loaded += OnLoaded;
        Closed += OnClosed;
        _qrExpiryTimer.Tick += OnQrExpiryTimerTick;
    }

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        try
        {
            _certificate = _identityService.GetOrCreateCertificate();
            _tls = new TlsHostService(_certificate, _pendingPairing, _trustedDevices, ApprovePairingAsync);
            await _tls.StartAsync();
            _tls.SecureClientConnected += remote =>
                Dispatcher.Invoke(() => LastEventText.Text = $"Secure pairing completed with {remote}");
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

    private Task<bool> ApprovePairingAsync(PairingApprovalRequest request)
    {
        return Dispatcher.InvokeAsync(() =>
        {
            var message = "Allow this Android device to pair?\n\nName: " + request.DeviceName +
                "\nDevice ID: " + request.DeviceId +
                "\nPublic key SHA-256: " + request.PublicKeyFingerprint +
                "\n\nOnly approve if you initiated this pairing.";
            return MessageBox.Show(this, message, "Approve Android device",
                MessageBoxButton.YesNo, MessageBoxImage.Question, MessageBoxResult.No) == MessageBoxResult.Yes;
        }).Task;
    }

    private void ManageDevicesButton_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new TrustedDevicesWindow(_trustedDevices) { Owner = this };
        dialog.ShowDialog();
    }

    private void ManageSharedFoldersButton_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new SharedFoldersWindow(_sharedFolders) { Owner = this };
        dialog.ShowDialog();
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
            "Scan to pair with explicit Windows approval; file access remains disabled.";
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
            _pendingPairing.Invalidate();
            PairingStatusText.Text = "Pairing QR expired. Refresh it to start a new pairing attempt.";
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
        _pendingPairing.Invalidate();
        if (_tls is not null) await _tls.DisposeAsync();
        await _discovery.DisposeAsync();
        await _tcp.DisposeAsync();
        _certificate?.Dispose();
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
