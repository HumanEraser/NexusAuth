using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace NexusAuth.Models;

public class ApiToken
{
    [Key]
    public int TokenId { get; set; }

    public int ApplicationId { get; set; }

    [ForeignKey(nameof(ApplicationId))]
    public Application Application { get; set; } = null!;

    [Required, StringLength(100)]
    public string TokenName { get; set; } = string.Empty;

    [Required, StringLength(16)]
    public string KeyPrefix { get; set; } = string.Empty;

    [Required, StringLength(64)]
    public string TokenHash { get; set; } = string.Empty;

    [Required, StringLength(500)]
    public string AllowedScopes { get; set; } = "read:data";

    // Comma-separated server IPs (e.g., "127.0.0.1, 203.177.42.18"). Null/empty = any IP allowed.
    [StringLength(500)]
    public string? AllowedIpAddresses { get; set; }

    public int RateLimitPerMinute { get; set; } = 1000;
    public bool IsRevoked { get; set; } = false;
    public DateTime? ExpirationDate { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? RevokedAt { get; set; }

    public ICollection<TokenUsageLog> TokenUsageLogs { get; set; } = new List<TokenUsageLog>();
}