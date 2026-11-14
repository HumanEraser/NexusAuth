using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using NexusAuth.Data;
using NexusAuth.Models;
using NexusAuth.Services;

namespace NexusAuth.Controllers;

[Authorize]
public class QuotaRequestsController : Controller
{
    private readonly AppDbContext _db;
    private readonly IAuditService _auditService;

    public QuotaRequestsController(AppDbContext db, IAuditService auditService)
    {
        _db = db;
        _auditService = auditService;
    }

    public async Task<IActionResult> Index()
    {
        int userId = int.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
        bool isCustomer = User.IsInRole("Customer");

        var requestsQuery = _db.QuotaRequests
            .Include(q => q.User)
            .Include(q => q.ApiToken)
            .Include(q => q.ReviewedByUser)
            .AsQueryable();

        if (isCustomer)
        {
            requestsQuery = requestsQuery.Where(q => q.UserId == userId);

            // Provide Customer's active tokens for the Rate Limit Upgrade dropdown
            ViewBag.CustomerTokens = await _db.ApiTokens
                .Include(t => t.Application)
                .Where(t => !t.IsRevoked && t.Application != null && t.Application.OwnerUserId == userId)
                .ToListAsync();

            var currentUser = await _db.Users.FindAsync(userId);
            ViewBag.CurrentMaxTokens = currentUser?.MaxActiveTokens ?? 2;
        }

        var requests = await requestsQuery
            .OrderByDescending(q => q.CreatedAt)
            .ToListAsync();

        return View(requests);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    [Authorize(Roles = "Customer")]
    public async Task<IActionResult> Submit(string requestType, int? tokenId, int requestedValue, string justification)
    {
        int userId = int.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
        var clientIp = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "127.0.0.1";

        if (requestType == "RateLimitUpgrade")
        {
            if (tokenId == null)
            {
                TempData["ErrorMessage"] = "Please select an active API token to upgrade.";
                return RedirectToAction(nameof(Index));
            }

            var token = await _db.ApiTokens
                .Include(t => t.Application)
                .FirstOrDefaultAsync(t => t.TokenId == tokenId && !t.IsRevoked);

            // IDOR Check: Ensure Customer owns the selected token
            if (token == null || token.Application?.OwnerUserId != userId)
            {
                return Forbid();
            }

            if (requestedValue <= token.RateLimitPerMinute)
            {
                TempData["ErrorMessage"] = $"Requested rate limit must be higher than current limit ({token.RateLimitPerMinute} req/min).";
                return RedirectToAction(nameof(Index));
            }
        }
        else if (requestType == "TokenSlotIncrease")
        {
            tokenId = null;
            var user = await _db.Users.FindAsync(userId);
            int currentCap = user?.MaxActiveTokens ?? 2;

            if (requestedValue <= currentCap || requestedValue > 20)
            {
                TempData["ErrorMessage"] = $"Requested token slots must be between {currentCap + 1} and 20.";
                return RedirectToAction(nameof(Index));
            }
        }
        else
        {
            return BadRequest();
        }

        var request = new QuotaRequest
        {
            UserId = userId,
            TokenId = tokenId,
            RequestType = requestType,
            RequestedValue = requestedValue,
            Justification = justification,
            Status = "Pending",
            CreatedAt = DateTime.UtcNow
        };

        _db.QuotaRequests.Add(request);
        await _db.SaveChangesAsync();

        await _auditService.LogAsync(
            userId,
            "QUOTA_REQUEST_SUBMITTED",
            "QuotaRequests",
            request.RequestId.ToString(),
            null,
            new { requestType, tokenId, requestedValue, justification },
            clientIp);

        TempData["SuccessMessage"] = "Quota upgrade request submitted for Administrator review.";
        return RedirectToAction(nameof(Index));
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    [Authorize(Roles = "Administrator")]
    public async Task<IActionResult> Approve(int requestId, string? adminNotes)
    {
        int adminId = int.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
        var clientIp = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "127.0.0.1";

        using var tx = await _db.Database.BeginTransactionAsync();

        var request = await _db.QuotaRequests
            .Include(q => q.User)
            .Include(q => q.ApiToken)
            .FirstOrDefaultAsync(q => q.RequestId == requestId);

        if (request == null || request.Status != "Pending")
        {
            TempData["ErrorMessage"] = "Request not found or already processed.";
            return RedirectToAction(nameof(Index));
        }

        object oldState;
        object newState;

        if (request.RequestType == "RateLimitUpgrade" && request.ApiToken != null)
        {
            int oldRate = request.ApiToken.RateLimitPerMinute;
            request.ApiToken.RateLimitPerMinute = request.RequestedValue;
            oldState = new { tokenId = request.TokenId, rateLimit = oldRate };
            newState = new { tokenId = request.TokenId, rateLimit = request.RequestedValue, status = "Approved" };
        }
        else if (request.RequestType == "TokenSlotIncrease" && request.User != null)
        {
            int oldSlots = request.User.MaxActiveTokens;
            request.User.MaxActiveTokens = request.RequestedValue;
            oldState = new { userId = request.UserId, maxActiveTokens = oldSlots };
            newState = new { userId = request.UserId, maxActiveTokens = request.RequestedValue, status = "Approved" };
        }
        else
        {
            TempData["ErrorMessage"] = "Target resource for this upgrade request no longer exists.";
            return RedirectToAction(nameof(Index));
        }

        request.Status = "Approved";
        request.ReviewedByUserId = adminId;
        request.AdminNotes = adminNotes;
        request.ReviewedAt = DateTime.UtcNow;

        await _db.SaveChangesAsync();

        await _auditService.LogAsync(
            adminId,
            "QUOTA_REQUEST_APPROVED",
            "QuotaRequests",
            request.RequestId.ToString(),
            oldState,
            newState,
            clientIp);

        await tx.CommitAsync();

        TempData["SuccessMessage"] = $"Request #{request.RequestId} approved and database quotas updated.";
        return RedirectToAction(nameof(Index));
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    [Authorize(Roles = "Administrator")]
    public async Task<IActionResult> Reject(int requestId, string? adminNotes)
    {
        int adminId = int.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
        var clientIp = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "127.0.0.1";

        var request = await _db.QuotaRequests.FindAsync(requestId);
        if (request == null || request.Status != "Pending")
        {
            TempData["ErrorMessage"] = "Request not found or already processed.";
            return RedirectToAction(nameof(Index));
        }

        request.Status = "Rejected";
        request.ReviewedByUserId = adminId;
        request.AdminNotes = string.IsNullOrWhiteSpace(adminNotes) ? "Request declined by Administrator." : adminNotes;
        request.ReviewedAt = DateTime.UtcNow;

        await _db.SaveChangesAsync();

        await _auditService.LogAsync(
            adminId,
            "QUOTA_REQUEST_REJECTED",
            "QuotaRequests",
            request.RequestId.ToString(),
            new { status = "Pending" },
            new { status = "Rejected", adminNotes = request.AdminNotes },
            clientIp);

        TempData["SuccessMessage"] = $"Request #{request.RequestId} has been rejected.";
        return RedirectToAction(nameof(Index));
    }
}