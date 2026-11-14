using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace NexusAuth.Models;

public class QuotaRequest
{
    [Key]
    public int RequestId { get; set; }

    public int UserId { get; set; }

    [ForeignKey(nameof(UserId))]
    public User User { get; set; } = null!;

    public int? TokenId { get; set; }

    [ForeignKey(nameof(TokenId))]
    public ApiToken? ApiToken { get; set; }

    [Required, StringLength(30)]
    public string RequestType { get; set; } = "RateLimitUpgrade"; // RateLimitUpgrade | TokenSlotIncrease

    public int RequestedValue { get; set; }

    [Required, StringLength(500)]
    public string Justification { get; set; } = string.Empty;

    [Required, StringLength(20)]
    public string Status { get; set; } = "Pending"; // Pending | Approved | Rejected

    public int? ReviewedByUserId { get; set; }

    [ForeignKey(nameof(ReviewedByUserId))]
    public User? ReviewedByUser { get; set; }

    [StringLength(300)]
    public string? AdminNotes { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? ReviewedAt { get; set; }
}