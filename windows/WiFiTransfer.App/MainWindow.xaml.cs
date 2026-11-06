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
    private readonly DispatcherTimer _networkRefreshTimer = new() { Interval = TimeSpan.FromMilliseconds(750) };
    private X509Certificate2? _certificate;
    private PairingQrData? _pairingQrData;

    public MainWindow()
    {
        InitializeComponent();
        _pairingQrService = new PairingQrService(_pendingPairing);
        Loaded += OnLoaded;
        Closed += OnClosed;
        _qrExpiryTimer.Tick += OnQrExpiryTimerTick;
        _networkRefreshTimer.Tick += OnNetworkRefreshTimerTick;
        NetworkChange.NetworkAddressChanged += OnNetworkAddressChanged;
    }

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        try
        {
            _certificate = _identityService.GetOrCreateCertificate();
            _tls = new TlsHostService(_certificate, _pendingPairing, _trustedDevices, _sharedFolders, ApprovePairingAsync);
            await _tls.StartAsync();
            _tls.SecureClientConnected += remote =>
                Dispatcher.Invoke(() => LastEventText.Text = $"Secure pairing completed with {remote}");
            await _tcp.StartAsync();
            _discovery.WindowsDeviceId = WindowsIdentityService.GetSha256Fingerprint(_certificate)[..32];
            await _discovery.StartAsync();
            _tcp.ClientConnected += remote =>
                Dispatcher.Invoke(() => LastEventText.Text = $"Android diagnostic handshake from {remote}");

            StatusText.Text = "Running — waiting for Android discovery";
            RefreshNetworkStateAndQr(forceQrRefresh: true);
            FingerprintText.Text = $"Certificate SHA-256: {WindowsIdentityService.GetSha256Fingerprint(_certificate)}";
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
        RefreshNetworkStateAndQr(forceQrRefresh: true);
    }

    private void OnNetworkAddressChanged(object? sender, EventArgs e)
    {
        Dispatcher.BeginInvoke(() =>
        {
            if (!_networkRefreshTimer.IsEnabled)
                _networkRefreshTimer.Start();
        });
    }

    private void OnNetworkRefreshTimerTick(object? sender, EventArgs e)
    {
        _networkRefreshTimer.Stop();
        RefreshNetworkStateAndQr(forceQrRefresh: false);
    }

    private void RefreshNetworkStateAndQr(bool forceQrRefresh)
    {
        var addresses = GetLocalIpv4Addresses();
        NetworkText.Text = addresses.Count == 0
            ? "No active IPv4 interface detected"
            : $"Active IPv4: {string.Join("  •  ", addresses)}";
        RefreshQrButton.IsEnabled = addresses.Count > 0;

        var preferredAddress = addresses.FirstOrDefault();
        if (_certificate is null) return;

        if (preferredAddress is null)
        {
            PairingQrImage.Source = null;
            _pairingQrData = null;
            _qrExpiryTimer.Stop();
            _pendingPairing.Invalidate();
            PairingStatusText.Text = "No active IPv4 address. Connect Windows to Wi-Fi or Ethernet.";
            ExpiryText.Text = "QR unavailable";
            return;
        }

        if (forceQrRefresh || _pairingQrData is null ||
            !string.Equals(_pairingQrData.Host, preferredAddress, StringComparison.Ordinal))
        {
            CreateQrPreview(preferredAddress);
        }
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
            $"Secure pairing endpoint · {Environment.MachineName} · {hostAddress}:{TlsHostService.Port}. " +
            "Scan to pair with explicit Windows approval; trusted devices can browse explicitly shared folders.";
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
        _networkRefreshTimer.Stop();
        NetworkChange.NetworkAddressChanged -= OnNetworkAddressChanged;
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
