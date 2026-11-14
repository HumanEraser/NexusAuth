using NexusAuth.Models;

namespace NexusAuth.Services;

public interface ITokenService
{
    Task<(string RawKey, ApiToken TokenRecord)> IssueTokenAsync(int applicationId, string tokenName, string environment, string scopes, int rateLimit, int userId, string clientIp);
    Task<bool> RevokeTokenAsync(int tokenId, int userId, string clientIp);
    Task<bool> RotateTokenAsync(int oldTokenId, string newTokenName, int userId, string clientIp);
    Task<(string RawKey, ApiToken Token)> IssueTokenAsync(
    int applicationId,
    string tokenName,
    string environment,
    string scopes,
    int rateLimit,
    string? allowedIpAddresses,
    int issuedByUserId,
    string clientIp);
}