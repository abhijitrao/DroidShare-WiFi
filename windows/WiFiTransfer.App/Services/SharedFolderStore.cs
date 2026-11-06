using System.IO;
using System.Text.Json;

namespace WiFiTransfer.App.Services;

public enum ShareOperation
{
    Read,
    Write,
    Delete,
    Stream
}

public sealed record SharedFolderShare(
    Guid ShareId,
    string DisplayName,
    string RootPath,
    bool CanRead,
    bool CanWrite,
    bool CanDelete,
    bool CanStream,
    DateTimeOffset AddedAt);

public sealed class SharedFolderStore
{
    private readonly object _gate = new();
    private readonly string _path = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "DroidShare-WiFi", "shared-folders.json");

    public IReadOnlyList<SharedFolderShare> GetAll()
    {
        lock (_gate) return Load().AsReadOnly();
    }

    public SharedFolderShare Add(string selectedPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(selectedPath);
        var root = Path.GetFullPath(selectedPath.Trim());
        if (!Directory.Exists(root))
            throw new DirectoryNotFoundException("The selected folder does not exist.");
        RejectReparsePoint(root);

        lock (_gate)
        {
            var shares = Load();
            if (shares.Any(s => string.Equals(Path.GetFullPath(s.RootPath), root,
                    OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal)))
                throw new InvalidOperationException("This folder is already shared.");

            var share = new SharedFolderShare(
                Guid.NewGuid(), new DirectoryInfo(root).Name, root,
                CanRead: true, CanWrite: false, CanDelete: false, CanStream: true,
                DateTimeOffset.UtcNow);
            shares.Add(share);
            Save(shares);
            return share;
        }
    }

    public void UpdatePermissions(Guid shareId, bool canRead, bool canWrite, bool canDelete, bool canStream)
    {
        lock (_gate)
        {
            var shares = Load();
            var index = shares.FindIndex(s => s.ShareId == shareId);
            if (index < 0) throw new KeyNotFoundException("Shared folder no longer exists.");
            if ((canWrite || canDelete) && !canRead)
                throw new ArgumentException("Write and Delete require Read permission.");
            shares[index] = shares[index] with
            {
                CanRead = canRead,
                CanWrite = canWrite,
                CanDelete = canDelete,
                CanStream = canStream
            };
            Save(shares);
        }
    }

    public bool Remove(Guid shareId)
    {
        lock (_gate)
        {
            var shares = Load();
            var removed = shares.RemoveAll(s => s.ShareId == shareId) > 0;
            if (removed) Save(shares);
            return removed;
        }
    }

    // Authorization/path validation primitive for the future authenticated file API.
    // Call this immediately before each filesystem operation; never trust a path from a client.
    public string ResolveAuthorizedPath(Guid shareId, string relativePath, ShareOperation operation)
    {
        ArgumentNullException.ThrowIfNull(relativePath);
        lock (_gate)
        {
            var share = Load().FirstOrDefault(s => s.ShareId == shareId)
                ?? throw new UnauthorizedAccessException("Shared folder is not configured.");
            var allowed = operation switch
            {
                ShareOperation.Read => share.CanRead,
                ShareOperation.Write => share.CanWrite,
                ShareOperation.Delete => share.CanDelete,
                ShareOperation.Stream => share.CanStream,
                _ => false
            };
            if (!allowed) throw new UnauthorizedAccessException("This operation is not allowed for the selected share.");

            var normalized = relativePath.Replace(Path.AltDirectorySeparatorChar, Path.DirectorySeparatorChar);
            if (Path.IsPathRooted(normalized) || normalized.Split(Path.DirectorySeparatorChar).Any(part => part == ".."))
                throw new UnauthorizedAccessException("The requested path is outside the shared folder.");

            var root = Path.GetFullPath(share.RootPath);
            var candidate = Path.GetFullPath(Path.Combine(root, normalized));
            var relative = Path.GetRelativePath(root, candidate);
            if (relative == ".." || relative.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal) ||
                Path.IsPathRooted(relative))
                throw new UnauthorizedAccessException("The requested path is outside the shared folder.");

            RejectExistingReparsePoints(root, candidate);
            return candidate;
        }
    }

    private static void RejectExistingReparsePoints(string root, string candidate)
    {
        // Reject reparse points in the selected root and every ancestor as well.
        // Otherwise a normal-looking child path could still be rooted below a junction.
        var ancestor = new DirectoryInfo(root);
        while (ancestor is not null)
        {
            if (ancestor.Exists) RejectReparsePoint(ancestor.FullName);
            ancestor = ancestor.Parent;
        }

        var relative = Path.GetRelativePath(root, candidate);
        if (relative == ".") return;
        var current = root;
        foreach (var segment in relative.Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, segment);
            if (File.Exists(current) || Directory.Exists(current))
                RejectReparsePoint(current);
            else
                break;
        }
    }

    private static void RejectReparsePoint(string path)
    {
        var attributes = File.GetAttributes(path);
        if ((attributes & FileAttributes.ReparsePoint) != 0)
            throw new UnauthorizedAccessException("Shared folders cannot contain or use symbolic links or reparse points.");
    }

    private List<SharedFolderShare> Load()
    {
        if (!File.Exists(_path)) return [];
        try
        {
            var shares = JsonSerializer.Deserialize<List<SharedFolderShare>>(File.ReadAllText(_path)) ?? [];
            return shares.Where(s => !string.IsNullOrWhiteSpace(s.RootPath) && Guid.TryParse(s.ShareId.ToString(), out _)).ToList();
        }
        catch (JsonException)
        {
            throw new InvalidDataException("Shared-folder settings are invalid; preserve the file before changing shares.");
        }
    }

    private void Save(List<SharedFolderShare> shares)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
        var temp = _path + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(shares, new JsonSerializerOptions { WriteIndented = true }));
        File.Move(temp, _path, overwrite: true);
    }
}
