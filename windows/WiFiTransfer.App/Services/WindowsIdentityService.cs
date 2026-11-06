using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace WiFiTransfer.App.Services;

public sealed class WindowsIdentityService
{
    private const string CertificateSubject = "CN=DroidShare-WiFi Local Device";
    private const string ServerAuthenticationOid = "1.3.6.1.5.5.7.3.1";

    public X509Certificate2 GetOrCreateCertificate()
    {
        using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadWrite);

        var existing = store.Certificates
            .Find(X509FindType.FindBySubjectDistinguishedName, CertificateSubject, validOnly: false)
            .OfType<X509Certificate2>()
            .Where(certificate =>
                certificate.HasPrivateKey &&
                certificate.NotBefore <= DateTime.UtcNow &&
                certificate.NotAfter > DateTime.UtcNow &&
                HasServerAuthenticationUsage(certificate))
            .OrderByDescending(certificate => certificate.NotBefore)
            .FirstOrDefault();

        if (existing is not null)
            return new X509Certificate2(existing);

        using var rsa = RSA.Create(3072);
        var request = new CertificateRequest(
            new X500DistinguishedName(CertificateSubject),
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
            critical: true));
        var eku = new OidCollection { new(ServerAuthenticationOid) };
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(eku, critical: true));
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName("localhost");
        san.AddDnsName(Environment.MachineName);
        request.CertificateExtensions.Add(san.Build());

        using var generated = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-5),
            DateTimeOffset.UtcNow.AddYears(5));

        // Re-import through a PFX with a random in-memory password so Windows persists
        // the private key in the current user's key store when adding the certificate.
        var password = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        var pfx = generated.Export(X509ContentType.Pfx, password);
        using var persisted = new X509Certificate2(
            pfx,
            password,
            X509KeyStorageFlags.UserKeySet | X509KeyStorageFlags.PersistKeySet);

        store.Add(persisted);
        CryptographicOperations.ZeroMemory(pfx);
        return new X509Certificate2(persisted);
    }

    public static string GetSha256Fingerprint(X509Certificate2 certificate) =>
        Convert.ToHexString(SHA256.HashData(certificate.RawData)).ToLowerInvariant();

    private static bool HasServerAuthenticationUsage(X509Certificate2 certificate)
    {
        var extension = certificate.Extensions
            .OfType<X509EnhancedKeyUsageExtension>()
            .FirstOrDefault();

        return extension?.EnhancedKeyUsages
            .Cast<Oid>()
            .Any(oid => oid.Value == ServerAuthenticationOid) == true;
    }
}
