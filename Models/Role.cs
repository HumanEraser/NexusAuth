using System.ComponentModel.DataAnnotations;

namespace NexusAuth.Models;

public class Role
{
    [Key]
    public int RoleId { get; set; }

    [Required, StringLength(50)]
    public string RoleName { get; set; } = string.Empty;

    [StringLength(255)]
    public string? Description { get; set; }

    public ICollection<UserRole> UserRoles { get; set; } = new List<UserRole>();
}