using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using NexusAuth.Data;
using NexusAuth.Models;
using NexusAuth.Services;

namespace NexusAuth.Controllers;

[Authorize(Roles = "Administrator")]
public class UsersController : Controller
{
    private readonly AppDbContext _db;
    private readonly IAuditService _audit;

    public UsersController(AppDbContext db, IAuditService audit)
    {
        _db = db;
        _audit = audit;
    }

    public async Task<IActionResult> Index()
    {
        ViewBag.Roles = await _db.Roles.ToListAsync();

        var users = await _db.Users
            .Include(u => u.UserRoles)
            .ThenInclude(ur => ur.Role)
            .OrderByDescending(u => u.CreatedAt)
            .ToListAsync();

        return View(users);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> CreateUser(string username, string email, string password, int roleId)
    {
        int currentUserId = int.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
        var clientIp = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "127.0.0.1";

        if (await _db.Users.AnyAsync(u => u.Email == email || u.Username == username))
        {
            TempData["ErrorMessage"] = "Username or Email already exists in the system.";
            return RedirectToAction(nameof(Index));
        }

        string passwordHash = BCrypt.Net.BCrypt.HashPassword(password);

        var user = new User
        {
            Username = username,
            Email = email,
            PasswordHash = passwordHash,
            IsActive = true
        };

        _db.Users.Add(user);
        await _db.SaveChangesAsync();

        _db.UserRoles.Add(new UserRole { UserId = user.UserId, RoleId = roleId });
        await _db.SaveChangesAsync();

        await _audit.LogAsync(currentUserId, "USER_CREATED", "Users", user.UserId.ToString(), null, new { username, email, roleId }, clientIp);

        TempData["SuccessMessage"] = $"User account '{username}' created successfully.";
        return RedirectToAction(nameof(Index));
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ToggleStatus(int userId)
    {
        int currentUserId = int.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
        var clientIp = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "127.0.0.1";

        var user = await _db.Users.FindAsync(userId);
        if (user == null) return NotFound();

        bool oldStatus = user.IsActive;
        user.IsActive = !user.IsActive;
        await _db.SaveChangesAsync();

        string action = user.IsActive ? "USER_ACTIVATED" : "USER_DEACTIVATED";
        await _audit.LogAsync(currentUserId, action, "Users", userId.ToString(), new { IsActive = oldStatus }, new { IsActive = user.IsActive }, clientIp);

        TempData["SuccessMessage"] = $"User '{user.Username}' account status updated.";
        return RedirectToAction(nameof(Index));
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> UnlockUser(int userId)
    {
        int adminId = int.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
        var clientIp = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "127.0.0.1";

        var targetUser = await _db.Users.FindAsync(userId);
        if (targetUser == null) return NotFound();

        int previousAttempts = targetUser.FailedLoginAttempts;
        targetUser.FailedLoginAttempts = 0;
        targetUser.LockoutEnd = null;

        await _db.SaveChangesAsync();

        await _audit.LogAsync(
            adminId,
            "ACCOUNT_UNLOCKED_BY_ADMIN",
            "Users",
            targetUser.UserId.ToString(),
            new { failedAttempts = previousAttempts, isLocked = true },
            new { failedAttempts = 0, isLocked = false },
            clientIp);

        TempData["SuccessMessage"] = $"Account '{targetUser.Email}' has been unlocked.";
        return RedirectToAction(nameof(Index));
    }
}