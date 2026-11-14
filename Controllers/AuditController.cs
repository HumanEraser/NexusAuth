using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using NexusAuth.Data;

namespace NexusAuth.Controllers;

[Authorize(Roles = "Administrator,Developer")]
public class AuditController : Controller
{
    private readonly AppDbContext _db;

    public AuditController(AppDbContext db)
    {
        _db = db;
    }

    public async Task<IActionResult> Index()
    {
        var logs = await _db.AuditLogs
            .Include(a => a.User)
            .OrderByDescending(a => a.Timestamp)
            .ToListAsync();

        return View(logs);
    }
}