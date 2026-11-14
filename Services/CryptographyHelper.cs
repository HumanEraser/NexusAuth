using System.Security.Cryptography;
using System.Text;

namespace NexusAuth.Services;

public static class CryptographyHelper
{
    public static string ComputeSha256(string rawInput)
    {
        byte[] bytes = SHA256.HashData(Encoding.UTF8.GetBytes(rawInput));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    public static (string RawKey, string KeyPrefix, string TokenHash) GenerateToken(string environment = "Production")
    {
        string prefix = environment.Equals("Development", StringComparison.OrdinalIgnoreCase)
            ? "nx_dev_"
            : "nx_live_";

        byte[] randomBytes = RandomNumberGenerator.GetBytes(24);
        string secretPart = Convert.ToHexString(randomBytes).ToLowerInvariant();

        string rawKey = $"{prefix}{secretPart}";
        string keyPrefix = rawKey[..12]; // e.g., "nx_live_9f8a"
        string tokenHash = ComputeSha256(rawKey);

        return (rawKey, keyPrefix, tokenHash);
    }
}