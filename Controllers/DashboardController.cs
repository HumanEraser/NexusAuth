using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using NexusAuth.Data;

namespace NexusAuth.Controllers;

[Authorize]
public class DashboardController : Controller
{
    private readonly AppDbContext _db;

    public DashboardController(AppDbContext db)
    {
        _db = db;
    }

    public async Task<IActionResult> Index()
    {
        int userId = int.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
        bool isCustomer = User.IsInRole("Customer");
        DateTime last24Hours = DateTime.UtcNow.AddHours(-24);

        // 1. Base queries scoped by tenant ownership for Customers
        var appsQuery = _db.Applications.AsQueryable();
        var tokensQuery = _db.ApiTokens.AsQueryable();
        var usageQuery = _db.TokenUsageLogs.AsQueryable();
        var auditQuery = _db.AuditLogs.Include(a => a.User).AsQueryable();

        if (isCustomer)
        {
            appsQuery = appsQuery.Where(a => a.OwnerUserId == userId);

            var customerAppIds = appsQuery.Select(a => a.ApplicationId);
            tokensQuery = tokensQuery.Where(t => customerAppIds.Contains(t.ApplicationId));

            var customerTokenIds = tokensQuery.Select(t => t.TokenId);
            usageQuery = usageQuery.Where(u => customerTokenIds.Contains(u.TokenId));

            auditQuery = auditQuery.Where(a => a.UserId == userId);
        }

        // 2. Exact ViewBag names expected by Views/Dashboard/Index.cshtml
        ViewBag.ActiveTokens = await tokensQuery.CountAsync(t => !t.IsRevoked);
        ViewBag.TotalApplications = await appsQuery.CountAsync(a => a.IsActive);
        ViewBag.TotalRequests24h = await usageQuery.CountAsync(u => u.Timestamp >= last24Hours);
        ViewBag.RevokedTokens = await tokensQuery.CountAsync(t => t.IsRevoked);

        // 3. Exact Chart.js Telemetry Breakdown counts
        ViewBag.SuccessCount = await usageQuery.CountAsync(u => u.ResponseStatusCode >= 200 && u.ResponseStatusCode < 300);
        ViewBag.UnauthorizedCount = await usageQuery.CountAsync(u => u.ResponseStatusCode == 401);
        ViewBag.ForbiddenCount = await usageQuery.CountAsync(u => u.ResponseStatusCode == 403);

        // 4. Recent System Audit Log (Top 10)
        var recentLogs = await auditQuery
            .OrderByDescending(a => a.Timestamp)
            .Take(10)
            .ToListAsync();

        return View(recentLogs);
    }
}