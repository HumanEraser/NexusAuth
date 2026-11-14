using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using NexusAuth.Data;
using NexusAuth.Models;
using NexusAuth.Services;

namespace NexusAuth.Controllers;

public class AccountController : Controller
{
    private readonly AppDbContext _db;
    private readonly IAuditService _audit;

    public AccountController(AppDbContext db, IAuditService audit)
    {
        _db = db;
        _audit = audit;
    }

    [HttpGet]
    public IActionResult Login() => View();

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Login(string email, string password)
    {
        var clientIp = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "127.0.0.1";
        var user = await _db.Users
            .Include(u => u.UserRoles)
            .ThenInclude(ur => ur.Role)
            .FirstOrDefaultAsync(u => u.Email == email);

        if (user == null || !user.IsActive)
        {
            await _audit.LogAsync(null, "LOGIN_FAILED", "Users", email, null, new { reason = "Invalid email or inactive account" }, clientIp);
            ViewBag.Error = "Invalid email or password.";
            return View();
        }

        // 1. Check if account is currently locked out
        if (user.LockoutEnd.HasValue && user.LockoutEnd.Value > DateTime.UtcNow)
        {
            int minutesLeft = (int)Math.Ceiling((user.LockoutEnd.Value - DateTime.UtcNow).TotalMinutes);
            await _audit.LogAsync(
                user.UserId,
                "LOGIN_BLOCKED_LOCKED_OUT",
                "Users",
                user.UserId.ToString(),
                null,
                new { lockoutEndUtc = user.LockoutEnd.Value },
                clientIp);

            ViewBag.Error = $"Account temporarily locked due to too many failed login attempts. Try again in {minutesLeft} minute(s) or contact an Administrator.";
            return View();
        }

        // 2. Verify BCrypt password
        if (!BCrypt.Net.BCrypt.Verify(password, user.PasswordHash))
        {
            user.FailedLoginAttempts += 1;

            if (user.FailedLoginAttempts >= 5)
            {
                user.LockoutEnd = DateTime.UtcNow.AddMinutes(15);
                await _db.SaveChangesAsync();

                await _audit.LogAsync(
                    user.UserId,
                    "ACCOUNT_LOCKED_OUT",
                    "Users",
                    user.UserId.ToString(),
                    null,
                    new { failedAttempts = user.FailedLoginAttempts, lockoutEndUtc = user.LockoutEnd },
                    clientIp);

                ViewBag.Error = "Maximum failed login attempts (5) reached. Your account has been locked for 15 minutes.";
            }
            else
            {
                int remaining = 5 - user.FailedLoginAttempts;
                await _db.SaveChangesAsync();

                await _audit.LogAsync(
                    user.UserId,
                    "LOGIN_FAILED",
                    "Users",
                    user.UserId.ToString(),
                    null,
                    new { failedAttempts = user.FailedLoginAttempts },
                    clientIp);

                ViewBag.Error = $"Invalid email or password. {remaining} attempt(s) remaining before account lockout.";
            }

            return View();
        }

        // 3. Successful login: clear any prior failed attempts or expired lockout
        if (user.FailedLoginAttempts > 0 || user.LockoutEnd != null)
        {
            user.FailedLoginAttempts = 0;
            user.LockoutEnd = null;
            await _db.SaveChangesAsync();
        }

        if (user == null || !BCrypt.Net.BCrypt.Verify(password, user.PasswordHash))
        {
            ModelState.AddModelError(string.Empty, "Invalid login credentials.");
            return View();
        }

        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, user.UserId.ToString()),
            new(ClaimTypes.Name, user.Username),
            new(ClaimTypes.Email, user.Email)
        };

        foreach (var userRole in user.UserRoles)
        {
            claims.Add(new Claim(ClaimTypes.Role, userRole.Role.RoleName));
        }

        var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        var authProperties = new AuthenticationProperties
        {
            IsPersistent = true,
            ExpiresUtc = DateTimeOffset.UtcNow.AddHours(8)
        };

        await HttpContext.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            new ClaimsPrincipal(claimsIdentity),
            authProperties);

        await _audit.LogAsync(user.UserId, "USER_LOGIN", "Users", user.UserId.ToString(), null, new { user.Email }, clientIp);

        return RedirectToAction("Index", "Dashboard");
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Logout()
    {
        var userIdClaim = User.FindFirstValue(ClaimTypes.NameIdentifier);
        int? userId = int.TryParse(userIdClaim, out var id) ? id : null;
        var clientIp = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "127.0.0.1";

        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

        if (userId.HasValue)
        {
            await _audit.LogAsync(userId.Value, "USER_LOGOUT", "Users", userId.Value.ToString(), null, null, clientIp);
        }

        return RedirectToAction("Login");
    }

    [HttpGet]
    public IActionResult AccessDenied() => View();
}