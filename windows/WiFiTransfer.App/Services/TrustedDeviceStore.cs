using System.IO;
using System.Security.Cryptography;
using System.Text.Json;

namespace WiFiTransfer.App.Services;

public sealed record TrustedDevice(string DeviceId, string DeviceName, string PublicKeyBase64,
    string PublicKeySha256, DateTimeOffset PairedAt, bool IsRevoked);

public sealed class TrustedDeviceStore
{
    private readonly object _gate = new();
    private readonly string _path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "DroidShare-WiFi", "trusted-devices.json");

    public void AddOrReplace(string deviceId, string deviceName, string publicKeyBase64)
    {
        var publicKey = Convert.FromBase64String(publicKeyBase64);
        var fingerprint = Convert.ToHexString(SHA256.HashData(publicKey)).ToLowerInvariant();
        lock (_gate)
        {
            var devices = Load();
            devices.RemoveAll(d => d.DeviceId == deviceId);
            devices.Add(new TrustedDevice(deviceId, deviceName, publicKeyBase64, fingerprint, DateTimeOffset.UtcNow, false));
            Save(devices);
        }
    }

    public IReadOnlyList<TrustedDevice> GetAll()
    {
        lock (_gate) return Load().AsReadOnly();
    }

    private List<TrustedDevice> Load()
    {
        if (!File.Exists(_path)) return [];
        try { return JsonSerializer.Deserialize<List<TrustedDevice>>(File.ReadAllText(_path)) ?? []; }
        catch (JsonException) { throw new InvalidDataException("Trusted-device storage is invalid; preserve the file before pairing again."); }
    }

    private void Save(List<TrustedDevice> devices)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
        var temp = _path + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(devices, new JsonSerializerOptions { WriteIndented = true }));
        File.Move(temp, _path, overwrite: true);
    }
}