using System.Diagnostics;
using Microsoft.EntityFrameworkCore;
using NexusAuth.Data;
using NexusAuth.Models;
using NexusAuth.Services;

namespace NexusAuth.Middleware;

public class ApiTokenGatewayMiddleware
{
    private readonly RequestDelegate _next;

    public ApiTokenGatewayMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context, AppDbContext db)
    {
        // Only inspect requests hitting the /api path
        if (!context.Request.Path.StartsWithSegments("/api"))
        {
            await _next(context);
            return;
        }

        var stopwatch = Stopwatch.StartNew();
        var clientIp = context.Connection.RemoteIpAddress?.ToString() ?? "127.0.0.1";

        if (!context.Request.Headers.TryGetValue("Authorization", out var authHeader) ||
            !authHeader.ToString().StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            await context.Response.WriteAsJsonAsync(new { error = "Unauthorized: Missing or invalid Bearer token header." });
            return;
        }

        var rawToken = authHeader.ToString()["Bearer ".Length..].Trim();
        var hashedInput = CryptographyHelper.ComputeSha256(rawToken);
        var keyPrefix = rawToken.Length >= 12 ? rawToken[..12] : string.Empty;

        // Uses IX_ApiTokens_Lookup non-clustered index
        var tokenRecord = await db.ApiTokens
            .FirstOrDefaultAsync(t => t.KeyPrefix == keyPrefix && t.TokenHash == hashedInput);

        if (tokenRecord == null || tokenRecord.IsRevoked || (tokenRecord.ExpirationDate.HasValue && tokenRecord.ExpirationDate < DateTime.UtcNow))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            await context.Response.WriteAsJsonAsync(new { error = "Forbidden: Token is invalid, revoked, or expired." });
            return;
        }

        context.Items["CurrentToken"] = tokenRecord;

        await _next(context);

        stopwatch.Stop();

        // High-throughput Telemetry Audit Logging
        var usageLog = new TokenUsageLog
        {
            TokenId = tokenRecord.TokenId,
            RequestedEndpoint = context.Request.Path,
            HttpMethod = context.Request.Method,
            ResponseStatusCode = context.Response.StatusCode,
            ClientIp = clientIp,
            ExecutionTimeMs = (int)stopwatch.ElapsedMilliseconds,
            Timestamp = DateTime.UtcNow
        };

        db.TokenUsageLogs.Add(usageLog);
        await db.SaveChangesAsync();
    }
}