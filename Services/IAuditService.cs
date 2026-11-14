namespace NexusAuth.Services;

public interface IAuditService
{
    Task LogAsync(int? userId, string actionType, string targetEntity, string? targetEntityId, object? oldValues, object? newValues, string clientIp);
}