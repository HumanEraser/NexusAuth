using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using NexusAuth.Data;
using NexusAuth.Models;
using NexusAuth.Services;

namespace NexusAuth.Controllers;

[Authorize]
public class TokensController : Controller
{
    private readonly AppDbContext _db;
    private readonly ITokenService _tokenService;
    private readonly IAuditService _auditService;

    public TokensController(AppDbContext db, ITokenService tokenService, IAuditService auditService)
    {
        _db = db;
        _tokenService = tokenService;
        _auditService = auditService;
    }

    public async Task<IActionResult> Index()
    {
        int userId = int.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
        bool isCustomer = User.IsInRole("Customer");

        // 1. Tenant-isolated Application list for Customers; global view for internal staff
        var appsQuery = _db.Applications.Where(a => a.IsActive);
        if (isCustomer)
        {
            appsQuery = appsQuery.Where(a => a.OwnerUserId == userId);
        }
        ViewBag.Applications = await appsQuery.ToListAsync();

        // 2. Tenant-isolated Token list for Customers
        var tokensQuery = _db.ApiTokens
            .Include(t => t.Application)
            .AsQueryable();

        if (isCustomer)
        {
            tokensQuery = tokensQuery.Where(t => t.Application != null && t.Application.OwnerUserId == userId);
        }

        var tokens = await tokensQuery
            .OrderByDescending(t => t.CreatedAt)
            .ToListAsync();

        if (TempData["NewRawToken"] != null)
        {
            ViewBag.NewRawToken = TempData["NewRawToken"]?.ToString();
            ViewBag.NewTokenName = TempData["NewTokenName"]?.ToString();
        }

        return View(tokens);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> CreateApp(string appName, string description, string environment)
    {
        int userId = int.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
        var clientIp = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "127.0.0.1";

        // Customers are restricted to Sandbox/Staging or Production self-service apps
        var app = new Application
        {
            OwnerUserId = userId,
            AppName = appName,
            Description = description,
            Environment = environment,
            IsActive = true
        };

        _db.Applications.Add(app);
        await _db.SaveChangesAsync();

        await _auditService.LogAsync(userId, "APPLICATION_CREATED", "Applications", app.ApplicationId.ToString(), null, new { appName, environment }, clientIp);

        TempData["SuccessMessage"] = $"Application '{appName}' created successfully.";
        return RedirectToAction(nameof(Index));
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> CreateToken(int applicationId, string tokenName, string scopes, int rateLimit, string? allowedIps)
    {
        
        int userId = int.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
        var clientIp = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "127.0.0.1";
        bool isCustomer = User.IsInRole("Customer");

        var app = await _db.Applications.FindAsync(applicationId);
        if (app == null) return NotFound();
        if (isCustomer)
        {
            var currentUser = await _db.Users.FindAsync(userId);
            int maxAllowedTokens = currentUser?.MaxActiveTokens ?? 2;

            int activeTokenCount = await _db.ApiTokens
                .Include(t => t.Application)
                .CountAsync(t => !t.IsRevoked && t.Application != null && t.Application.OwnerUserId == userId);

            if (activeTokenCount >= maxAllowedTokens)
            {
                TempData["ErrorMessage"] = $"Customer tier limit reached: Maximum of {maxAllowedTokens} active API tokens allowed. Submit a Quota Request to increase your limit.";
                return RedirectToAction(nameof(Index));
            }

            scopes = "read:data";
            rateLimit = Math.Clamp(rateLimit, 1, 100);
        }
        
        if (isCustomer && app.OwnerUserId != userId)
        {
            return Forbid();
        }

        if (isCustomer)
        {
            int activeTokenCount = await _db.ApiTokens
                .Include(t => t.Application)
                .CountAsync(t => !t.IsRevoked && t.Application != null && t.Application.OwnerUserId == userId);

            if (activeTokenCount >= 2)
            {
                TempData["ErrorMessage"] = "Customer tier limit reached: Maximum of 2 active API tokens allowed.";
                return RedirectToAction(nameof(Index));
            }

            scopes = "read:data";
            rateLimit = Math.Clamp(rateLimit, 1, 100);
        }

        var (rawKey, _) = await _tokenService.IssueTokenAsync(
            applicationId, tokenName, app.Environment, scopes, rateLimit, allowedIps, userId, clientIp);

        TempData["NewRawToken"] = rawKey;
        TempData["NewTokenName"] = tokenName;

        return RedirectToAction(nameof(Index));
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> UpdateTokenIps(int tokenId, string? allowedIps)
    {
        int userId = int.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
        var clientIp = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "127.0.0.1";

        var token = await _db.ApiTokens
            .Include(t => t.Application)
            .FirstOrDefaultAsync(t => t.TokenId == tokenId);

        if (token == null) return NotFound();

        if (User.IsInRole("Customer") && token.Application?.OwnerUserId != userId)
        {
            return Forbid();
        }

        string oldIps = token.AllowedIpAddresses ?? "ANY";
        string? normalizedIps = TokenService.NormalizeIpAllowlist(allowedIps);
        token.AllowedIpAddresses = normalizedIps;

        await _db.SaveChangesAsync();

        await _auditService.LogAsync(
            userId,
            "TOKEN_IP_ALLOWLIST_UPDATED",
            "ApiTokens",
            token.TokenId.ToString(),
            new { allowedIps = oldIps },
            new { allowedIps = normalizedIps ?? "ANY" },
            clientIp);

        TempData["SuccessMessage"] = normalizedIps != null
            ? $"IP allowlist updated for '{token.TokenName}': {normalizedIps}"
            : $"IP restriction cleared for '{token.TokenName}' (any IP allowed).";

        return RedirectToAction(nameof(Index));
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> RevokeToken(int tokenId)
    {
        int userId = int.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
        var clientIp = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "127.0.0.1";

        var token = await _db.ApiTokens
            .Include(t => t.Application)
            .FirstOrDefaultAsync(t => t.TokenId == tokenId);

        if (token == null) return NotFound();

        // IDOR Check: Prevent Customers from revoking another tenant's token
        if (User.IsInRole("Customer") && token.Application?.OwnerUserId != userId)
        {
            return Forbid();
        }

        bool success = await _tokenService.RevokeTokenAsync(tokenId, userId, clientIp);
        if (success)
        {
            TempData["SuccessMessage"] = "API Token revoked successfully.";
        }

        return RedirectToAction(nameof(Index));
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> RotateToken(int oldTokenId, string newTokenName)
    {
        int userId = int.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
        var clientIp = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "127.0.0.1";

        var token = await _db.ApiTokens
            .Include(t => t.Application)
            .FirstOrDefaultAsync(t => t.TokenId == oldTokenId);

        if (token == null) return NotFound();

        // IDOR Check: Prevent Customers from rotating another tenant's token
        if (User.IsInRole("Customer") && token.Application?.OwnerUserId != userId)
        {
            return Forbid();
        }

        bool success = await _tokenService.RotateTokenAsync(oldTokenId, newTokenName, userId, clientIp);
        if (success)
        {
            TempData["SuccessMessage"] = "API Token rotated atomically using T-SQL transaction.";
        }

        return RedirectToAction(nameof(Index));
    }
}