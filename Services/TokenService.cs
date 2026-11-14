using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using NexusAuth.Data;
using NexusAuth.Models;

namespace NexusAuth.Services;

public class TokenService : ITokenService
{
    private readonly AppDbContext _db;
    private readonly IAuditService _audit;

    public TokenService(AppDbContext db, IAuditService audit)
    {
        _db = db;
        _audit = audit;
    }

    public async Task<(string RawKey, ApiToken TokenRecord)> IssueTokenAsync(
        int applicationId, string tokenName, string environment, string scopes, int rateLimit, int userId, string clientIp)
    {
        var (rawKey, keyPrefix, tokenHash) = CryptographyHelper.GenerateToken(environment);

        var token = new ApiToken
        {
            ApplicationId = applicationId,
            TokenName = tokenName,
            KeyPrefix = keyPrefix,
            TokenHash = tokenHash,
            AllowedScopes = scopes,
            RateLimitPerMinute = rateLimit,
            IsRevoked = false,
            CreatedAt = DateTime.UtcNow
        };

        using var transaction = await _db.Database.BeginTransactionAsync();

        _db.ApiTokens.Add(token);
        await _db.SaveChangesAsync();

        await _audit.LogAsync(
            userId,
            "TOKEN_CREATED",
            "ApiTokens",
            token.TokenId.ToString(),
            null,
            new { token.TokenName, token.KeyPrefix, token.AllowedScopes },
            clientIp
        );

        await transaction.CommitAsync();

        return (rawKey, token);
    }

    public async Task<bool> RevokeTokenAsync(int tokenId, int userId, string clientIp)
    {
        var token = await _db.ApiTokens.FindAsync(tokenId);
        if (token == null || token.IsRevoked) return false;

        using var transaction = await _db.Database.BeginTransactionAsync();

        token.IsRevoked = true;
        token.RevokedAt = DateTime.UtcNow;
        await _db.SaveChangesAsync();

        await _audit.LogAsync(
            userId,
            "TOKEN_REVOKED",
            "ApiTokens",
            tokenId.ToString(),
            new { IsRevoked = false },
            new { IsRevoked = true, RevokedAt = token.RevokedAt },
            clientIp
        );

        await transaction.CommitAsync();
        return true;
    }

    public async Task<bool> RotateTokenAsync(int oldTokenId, string newTokenName, int userId, string clientIp)
    {
        var oldToken = await _db.ApiTokens.Include(t => t.Application).FirstOrDefaultAsync(t => t.TokenId == oldTokenId);
        if (oldToken == null) return false;

        var (_, newPrefix, newHash) = CryptographyHelper.GenerateToken(oldToken.Application.Environment);

        // Execute T-SQL stored procedure for atomic database-level transaction
        await _db.Database.ExecuteSqlInterpolatedAsync(
            $"EXEC sp_RotateApiToken @OldTokenId={oldTokenId}, @NewTokenName={newTokenName}, @NewKeyPrefix={newPrefix}, @NewTokenHash={newHash}, @UserId={userId}, @ClientIp={clientIp}"
        );

        return true;
    }

    public async Task<(string RawKey, ApiToken Token)> IssueTokenAsync(
        int applicationId,
        string tokenName,
        string environment,
        string scopes,
        int rateLimit,
        string? allowedIpAddresses,
        int issuedByUserId,
        string clientIp)
    {
        string envPrefix = environment.Equals("Production", StringComparison.OrdinalIgnoreCase) ? "nx_live_" : "nx_test_";
        string randomSecret = Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(24)).ToLowerInvariant();
        string rawKey = $"{envPrefix}{randomSecret}";
        string keyPrefix = rawKey[..16];
        string tokenHash = ComputeSha256(rawKey);

        string? sanitizedIps = NormalizeIpAllowlist(allowedIpAddresses);

        var token = new ApiToken
        {
            ApplicationId = applicationId,
            TokenName = tokenName,
            KeyPrefix = keyPrefix,
            TokenHash = tokenHash,
            AllowedScopes = scopes,
            RateLimitPerMinute = rateLimit,
            AllowedIpAddresses = sanitizedIps,
            IsRevoked = false,
            CreatedAt = DateTime.UtcNow
        };

        _db.ApiTokens.Add(token);
        await _db.SaveChangesAsync();

        await _audit.LogAsync(
            issuedByUserId,
            "TOKEN_ISSUED",
            "ApiTokens",
            token.TokenId.ToString(),
            null,
            new { tokenName, scopes, rateLimit, allowedIps = sanitizedIps ?? "ANY" },
            clientIp);

        return (rawKey, token);
    }
    private static string ComputeSha256(string rawData)
    {
        byte[] bytes = SHA256.HashData(Encoding.UTF8.GetBytes(rawData));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    public static string? NormalizeIpAllowlist(string? rawIps)
    {
        if (string.IsNullOrWhiteSpace(rawIps)) return null;

        var validIps = rawIps
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(ip => ip == "::1" ? "127.0.0.1" : ip)
            .Where(ip => System.Net.IPAddress.TryParse(ip, out _))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        return validIps.Count > 0 ? string.Join(",", validIps) : null;
    }
}