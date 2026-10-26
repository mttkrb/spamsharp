using System.Security.Cryptography;
using System.Text;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using SpamSharp;
using SpamSharp.Components;

// Fehlersuche: docker exec spamsharp /app/SpamSharp --discover name@domain.de
if (args is ["--discover", var address])
{
    Console.WriteLine((await Autodiscover.Find(address))?.ToString() ?? "nichts gefunden");
    return 0;
}

var adminPassword = Environment.GetEnvironmentVariable("ADMIN_PASSWORD");
if (string.IsNullOrEmpty(adminPassword))
{
    Console.Error.WriteLine("ADMIN_PASSWORD muss gesetzt sein.");
    return 1;
}
foreach (var dir in new[] { "", "redis", "rspamd", "keys" })
    Directory.CreateDirectory(Path.Combine(Paths.Data, dir));
Db.Init(Path.Combine(Paths.Data, "spamsharp.db"));

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddRazorComponents().AddInteractiveServerComponents();
builder.Services.AddDataProtection().PersistKeysToFileSystem(new DirectoryInfo(Path.Combine(Paths.Data, "keys")));
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme).AddCookie(o =>
{
    o.Cookie.Name = "spamsharp";
    o.ExpireTimeSpan = TimeSpan.FromDays(30);
});
builder.Services.AddSingleton<Scanner>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<Scanner>());
builder.Services.AddHostedService<Daemons>();

var app = builder.Build();
app.UseExceptionHandler("/Error", createScopeForErrors: true);

var expected = Encoding.UTF8.GetBytes(adminPassword);
app.Use(async (ctx, next) =>
{
    // Anfragen fremder Webseiten ablehnen (CSRF, auch für die Blazor-WebSocket-Verbindung und das Login-Formular)
    var origin = ctx.Request.Headers.Origin.ToString();
    if (origin != "" && (!Uri.TryCreate(origin, UriKind.Absolute, out var o) || o.Authority != ctx.Request.Host.Value))
    {
        ctx.Response.StatusCode = 403;
        return;
    }
    await next();
});
app.UseAuthentication();
app.Use(async (ctx, next) =>
{
    if (ctx.User.Identity?.IsAuthenticated == true || ctx.Request.Path == "/login" || ctx.Request.Path == "/app.css")
        await next();
    else
        ctx.Response.Redirect("/login");
});

app.MapGet("/login", () => LoginPage(null));
app.MapPost("/login", async (HttpContext ctx) =>
{
    var form = await ctx.Request.ReadFormAsync();
    if (!CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(form["password"].ToString()), expected))
    {
        await Task.Delay(1000); // bremst Durchprobieren
        return LoginPage("Falsches Passwort.");
    }
    var identity = new ClaimsIdentity([new Claim(ClaimTypes.Name, "admin")], CookieAuthenticationDefaults.AuthenticationScheme);
    await ctx.SignInAsync(new ClaimsPrincipal(identity), new AuthenticationProperties { IsPersistent = true });
    return Results.Redirect("/");
}).DisableAntiforgery();
app.MapPost("/logout", async (HttpContext ctx) =>
{
    await ctx.SignOutAsync();
    return Results.Redirect("/login");
}).DisableAntiforgery();

app.UseAntiforgery();
app.MapStaticAssets();
app.MapRazorComponents<App>().AddInteractiveServerRenderMode();
app.Run();
return 0;

static IResult LoginPage(string? error) => Results.Content($$"""
    <!DOCTYPE html>
    <html lang="de">
    <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <title>Anmelden – SpamSharp</title>
        <link rel="stylesheet" href="/app.css" />
        <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>📬</text></svg>" />
    </head>
    <body class="login">
        <form method="post" action="/login" class="form card">
            <h1>📬 SpamSharp</h1>
            <label>Passwort <input type="password" name="password" autocomplete="current-password" autofocus required /></label>
            {{(error is null ? "" : $"<p class=\"err\" role=\"alert\">{error}</p>")}}
            <button class="primary">Anmelden</button>
        </form>
    </body>
    </html>
    """, "text/html; charset=utf-8");
