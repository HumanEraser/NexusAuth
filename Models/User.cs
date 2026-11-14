using System.ComponentModel.DataAnnotations;
using static System.Net.Mime.MediaTypeNames;

namespace NexusAuth.Models;

public class User
{
    [Key]
    public int UserId { get; set; }

    [Required, StringLength(100)]
    public string Username { get; set; } = string.Empty;

    [Required, StringLength(150), EmailAddress]
    public string Email { get; set; } = string.Empty;

    [Required, StringLength(255)]
    public string PasswordHash { get; set; } = string.Empty;

    public bool IsActive { get; set; } = true;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public int MaxActiveTokens { get; set; } = 2;
    public int FailedLoginAttempts { get; set; } = 0;
    public DateTime? LockoutEnd { get; set; }

    public ICollection<UserRole> UserRoles { get; set; } = new List<UserRole>();
    public ICollection<Application> Applications { get; set; } = new List<Application>();
    public ICollection<AuditLog> AuditLogs { get; set; } = new List<AuditLog>();
}