using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

namespace WiFiTransfer.App.Services;

public sealed record PairingQrData(
    string Payload,
    DateTimeOffset ExpiresAt,
    string Host,
    string DeviceId,
    string CertificateFingerprint);

public sealed class PairingQrService
{
    public const int PairingWindowSeconds = 120;

    public PairingQrData Create(
        X509Certificate2 certificate,
        string hostAddress,
        int port = TcpHostService.Port)
    {
        if (!IPAddress.TryParse(hostAddress, out var address) ||
            address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork ||
            IPAddress.IsLoopback(address))
        {
            throw new ArgumentException("A reachable IPv4 address is required.", nameof(hostAddress));
        }

        if (port is < 1 or > 65535)
            throw new ArgumentOutOfRangeException(nameof(port));

        var now = DateTimeOffset.UtcNow;
        var expiresAt = now.AddSeconds(PairingWindowSeconds);
        var nonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
        var fingerprint = WindowsIdentityService.GetSha256Fingerprint(certificate);
        var deviceId = fingerprint[..32];

        var payload = JsonSerializer.Serialize(new
        {
            type = "DROIDSHARE_PAIR",
            protocolVersion = 1,
            deviceId,
            deviceName = Environment.MachineName,
            host = address.ToString(),
            port,
            certificateSha256 = fingerprint,
            nonce,
            expiresAt = expiresAt.UtcDateTime.ToString("O")
        });

        return new PairingQrData(payload, expiresAt, address.ToString(), deviceId, fingerprint);
    }
}
