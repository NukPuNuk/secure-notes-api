using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using NotesApi.Data;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<NotesDbContext>(o =>
    o.UseSqlite(builder.Configuration.GetConnectionString("Notes")));

builder.Services.AddAuthentication().AddJwtBearer();
// Secure by default: every endpoint requires an authenticated user unless explicitly opted out.
builder.Services.AddAuthorization(o =>
    o.FallbackPolicy = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build());

builder.Services.AddControllers();

builder.WebHost.ConfigureKestrel(o => o.AddServerHeader = false);

var app = builder.Build();

app.Use(async (ctx, next) =>
{
    ctx.Response.Headers["X-Content-Type-Options"] = "nosniff";
    ctx.Response.Headers["Cache-Control"] = "no-store";
    ctx.Response.Headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'";
    await next();
});

using (var scope = app.Services.CreateScope())
    scope.ServiceProvider.GetRequiredService<NotesDbContext>().Database.EnsureCreated();

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();
app.Run();