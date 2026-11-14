using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace NexusAuth.Models;

public class TokenUsageLog
{
    [Key]
    public long LogId { get; set; }

    public int TokenId { get; set; }

    [ForeignKey(nameof(TokenId))]
    public ApiToken ApiToken { get; set; } = null!;

    [Required, StringLength(255)]
    public string RequestedEndpoint { get; set; } = string.Empty;

    [Required, StringLength(10)]
    public string HttpMethod { get; set; } = string.Empty;

    public int ResponseStatusCode { get; set; }

    [Required, StringLength(45)]
    public string ClientIp { get; set; } = string.Empty;

    public int ExecutionTimeMs { get; set; }
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
}

public class AuditLog
{
    [Key]
    public int AuditId { get; set; }

    public int? UserId { get; set; }
    public User? User { get; set; }

    [Required, StringLength(50)]
    public string ActionType { get; set; } = string.Empty;

    [Required, StringLength(50)]
    public string TargetEntity { get; set; } = string.Empty;

    [StringLength(100)]
    public string? TargetEntityId { get; set; }

    public string? OldValuesJson { get; set; }
    public string? NewValuesJson { get; set; }

    [Required, StringLength(45)]
    public string ClientIp { get; set; } = string.Empty;

    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
}