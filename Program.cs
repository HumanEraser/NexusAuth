using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;
using NexusAuth.Data;
using NexusAuth.Middleware;
using NexusAuth.Services;
using Scalar.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

// DbContext
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

// Cookie Authentication Registration
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/Account/Login";
        options.AccessDeniedPath = "/Account/AccessDenied";
        options.ExpireTimeSpan = TimeSpan.FromHours(8);
    });

builder.Services.AddControllersWithViews();
builder.Services.AddOpenApi();

// Application Services
builder.Services.AddScoped<IAuditService, AuditService>();
builder.Services.AddScoped<ITokenService, TokenService>();

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

// Authentication & Authorization Pipeline
app.UseAuthentication();
app.UseAuthorization();

// Custom API Gateway Middleware for /api routes
app.UseMiddleware<ApiTokenGatewayMiddleware>();

if (app.Environment.IsDevelopment() || app.Environment.IsProduction())
{
    app.MapOpenApi();
    app.MapScalarApiReference(options =>
    {
        options.WithTitle("NexusAuth API Gateway Portal").WithTheme(ScalarTheme.Moon);
    });
}

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Account}/{action=Login}/{id?}");

// Ensure admin account password hash is valid
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<NexusAuth.Data.AppDbContext>();
    var admin = db.Users.FirstOrDefault(u => u.Email == "admin@nexusauth.internal");
    if (admin != null)
    {
        admin.PasswordHash = BCrypt.Net.BCrypt.HashPassword("Admin123!");
        db.SaveChanges();
    }
}

app.Run();