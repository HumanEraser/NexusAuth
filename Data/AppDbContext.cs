using Microsoft.EntityFrameworkCore;
using NexusAuth.Models;

namespace NexusAuth.Data;

public class AppDbContext : DbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

    public DbSet<Role> Roles => Set<Role>();
    public DbSet<User> Users => Set<User>();
    public DbSet<UserRole> UserRoles => Set<UserRole>();
    public DbSet<Application> Applications => Set<Application>();
    public DbSet<ApiToken> ApiTokens => Set<ApiToken>();
    public DbSet<TokenUsageLog> TokenUsageLogs => Set<TokenUsageLog>();
    public DbSet<AuditLog> AuditLogs => Set<AuditLog>();
    public DbSet<QuotaRequest> QuotaRequests { get; set; }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        // Composite primary key for UserRoles
        modelBuilder.Entity<UserRole>()
            .HasKey(ur => new { ur.UserId, ur.RoleId });

        // Restrict onDelete for Application -> OwnerUser to match SQL schema
        modelBuilder.Entity<Application>()
            .HasOne(a => a.OwnerUser)
            .WithMany(u => u.Applications)
            .HasForeignKey(a => a.OwnerUserId)
            .OnDelete(DeleteBehavior.Restrict);

        // Map AuditLog optional relationship
        modelBuilder.Entity<AuditLog>()
            .HasOne(al => al.User)
            .WithMany(u => u.AuditLogs)
            .HasForeignKey(al => al.UserId)
            .OnDelete(DeleteBehavior.SetNull);

        modelBuilder.Entity<QuotaRequest>()
            .HasOne(q => q.User)
            .WithMany()
            .HasForeignKey(q => q.UserId)
            .OnDelete(DeleteBehavior.Restrict);

        modelBuilder.Entity<QuotaRequest>()
            .HasOne(q => q.ReviewedByUser)
            .WithMany()
            .HasForeignKey(q => q.ReviewedByUserId)
            .OnDelete(DeleteBehavior.Restrict);
    }
}