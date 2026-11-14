using System.ComponentModel.DataAnnotations;

namespace NexusAuth.Models;

public class Application
{
    [Key]
    public int ApplicationId { get; set; }

    public int OwnerUserId { get; set; }
    public User OwnerUser { get; set; } = null!;

    [Required, StringLength(100)]
    public string AppName { get; set; } = string.Empty;

    [StringLength(500)]
    public string? Description { get; set; }

    [Required, StringLength(20)]
    public string Environment { get; set; } = "Production";

    public bool IsActive { get; set; } = true;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public ICollection<ApiToken> ApiTokens { get; set; } = new List<ApiToken>();
}