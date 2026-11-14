using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using NexusAuth.Data;
using NexusAuth.Services;

namespace NexusAuth.Controllers;

[Authorize(Roles = "Administrator")]
public class AdminController : Controller
{
    private readonly AppDbContext _db;
    private readonly IAuditService _audit;
    private readonly IWebHostEnvironment _env;

    public AdminController(AppDbContext db, IAuditService audit, IWebHostEnvironment env)
    {
        _db = db;
        _audit = audit;
        _env = env;
    }

    public async Task<IActionResult> Index()
    {
        var dbConnection = _db.Database.GetDbConnection();
        ViewBag.DatabaseName = dbConnection.Database;

        // Query SQL Server Database Size
        var sizeQuery = @"
            SELECT SUM(size * 8.0 / 1024) AS SizeMB
            FROM sys.master_files
            WHERE database_id = DB_ID(@dbName);";

        using var command = dbConnection.CreateCommand();
        command.CommandText = sizeQuery;
        var param = command.CreateParameter();
        param.ParameterName = "@dbName";
        param.Value = dbConnection.Database;
        command.Parameters.Add(param);

        await _db.Database.OpenConnectionAsync();
        var result = await command.ExecuteScalarAsync();
        ViewBag.DatabaseSize = (result != DBNull.Value && result != null) ? Math.Round(Convert.ToDouble(result), 2) : 0;
        await _db.Database.CloseConnectionAsync();

        // Retrieve list of created .bak files
        var backupFolder = Path.Combine(_env.ContentRootPath, "Backups");
        if (!Directory.Exists(backupFolder)) Directory.CreateDirectory(backupFolder);

        var backupFiles = new DirectoryInfo(backupFolder)
            .GetFiles("*.bak")
            .OrderByDescending(f => f.CreationTime)
            .ToList();

        return View(backupFiles);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> CreateBackup()
    {
        int currentUserId = int.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
        var clientIp = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "127.0.0.1";

        var backupFolder = Path.Combine(_env.ContentRootPath, "Backups");
        if (!Directory.Exists(backupFolder)) Directory.CreateDirectory(backupFolder);

        var fileName = $"NexusAuthDB_Backup_{DateTime.Now:yyyyMMdd_HHmmss}.bak";
        var filePath = Path.Combine(backupFolder, fileName);

        try
        {
            // Execute native T-SQL backup command
            var sql = $"BACKUP DATABASE [{_db.Database.GetDbConnection().Database}] TO DISK = '{filePath}' WITH FORMAT, INIT, NAME = N'NexusAuthDB Full Backup';";
            await _db.Database.ExecuteSqlRawAsync(sql);

            await _audit.LogAsync(currentUserId, "DB_BACKUP_CREATED", "Database", "NexusAuthDB", null, new { BackupFile = fileName }, clientIp);
            TempData["SuccessMessage"] = $"Full database backup generated: {fileName}";
        }
        catch (Exception ex)
        {
            TempData["ErrorMessage"] = $"Database backup failed: {ex.Message}";
        }

        return RedirectToAction(nameof(Index));
    }
}