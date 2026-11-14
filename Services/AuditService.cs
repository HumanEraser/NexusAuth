using System.Text.Json;
using NexusAuth.Data;
using NexusAuth.Models;

namespace NexusAuth.Services;

public class AuditService : IAuditService
{
    private readonly AppDbContext _db;

    public AuditService(AppDbContext db)
    {
        _db = db;
    }

    public async Task LogAsync(int? userId, string actionType, string targetEntity, string? targetEntityId, object? oldValues, object? newValues, string clientIp)
    {
        var log = new AuditLog
        {
            UserId = userId,
            ActionType = actionType,
            TargetEntity = targetEntity,
            TargetEntityId = targetEntityId,
            OldValuesJson = oldValues != null ? JsonSerializer.Serialize(oldValues) : null,
            NewValuesJson = newValues != null ? JsonSerializer.Serialize(newValues) : null,
            ClientIp = clientIp,
            Timestamp = DateTime.UtcNow
        };

        _db.AuditLogs.Add(log);
        await _db.SaveChangesAsync();
    }
}