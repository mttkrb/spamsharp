using System.Security.Cryptography;
using System.Text;
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
builder.Services.AddSingleton<Scanner>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<Scanner>());
builder.Services.AddHostedService<Daemons>();

var app = builder.Build();
app.UseExceptionHandler("/Error", createScopeForErrors: true);

var expected = Encoding.UTF8.GetBytes(adminPassword);
app.Use(async (ctx, next) =>
{
    // Anfragen fremder Webseiten ablehnen (CSRF, auch für die Blazor-WebSocket-Verbindung)
    var origin = ctx.Request.Headers.Origin.ToString();
    if (origin != "" && (!Uri.TryCreate(origin, UriKind.Absolute, out var o) || o.Authority != ctx.Request.Host.Value))
    {
        ctx.Response.StatusCode = 403;
        return;
    }
    // Login per HTTP Basic Auth, Benutzername beliebig
    var auth = ctx.Request.Headers.Authorization.ToString();
    if (auth.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
    {
        try
        {
            var password = Encoding.UTF8.GetString(Convert.FromBase64String(auth[6..])).Split(':', 2).ElementAtOrDefault(1) ?? "";
            if (CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(password), expected))
            {
                await next();
                return;
            }
        }
        catch (FormatException) { }
    }
    ctx.Response.Headers.WWWAuthenticate = "Basic realm=\"SpamSharp\", charset=\"UTF-8\"";
    ctx.Response.StatusCode = 401;
});

app.UseAntiforgery();
app.MapStaticAssets();
app.MapRazorComponents<App>().AddInteractiveServerRenderMode();
app.Run();
return 0;
