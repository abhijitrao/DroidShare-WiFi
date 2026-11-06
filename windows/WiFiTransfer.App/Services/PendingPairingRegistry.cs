using System.Security.Cryptography;
using System.Text;

namespace WiFiTransfer.App.Services;

public sealed class PendingPairingRegistry
{
    private readonly object _gate = new();
    private string? _nonce;
    private DateTimeOffset _expiresAt;
    private bool _reserved;

    public void Register(string nonce, DateTimeOffset expiresAt)
    {
        lock (_gate) { _nonce = nonce; _expiresAt = expiresAt; _reserved = false; }
    }

    public bool TryReserve(string nonce)
    {
        lock (_gate)
        {
            if (_nonce is null || _reserved || DateTimeOffset.UtcNow >= _expiresAt) return false;
            if (!CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(_nonce), Encoding.UTF8.GetBytes(nonce))) return false;
            _reserved = true;
            return true;
        }
    }

    public bool TryConsume(string nonce)
    {
        lock (_gate)
        {
            if (_nonce is null || !_reserved || DateTimeOffset.UtcNow >= _expiresAt ||
                !CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(_nonce), Encoding.UTF8.GetBytes(nonce)))
                return false;
            _nonce = null;
            _reserved = false;
            return true;
        }
    }

    public void Release(string nonce)
    {
        lock (_gate)
        {
            if (_nonce is null || !CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(_nonce), Encoding.UTF8.GetBytes(nonce))) return;
            if (DateTimeOffset.UtcNow >= _expiresAt) { _nonce = null; _reserved = false; }
            else _reserved = false;
        }
    }

    public void Invalidate()
    {
        lock (_gate) { _nonce = null; _reserved = false; }
    }
}