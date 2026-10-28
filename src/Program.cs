using System.Security.Cryptography;
using System.Net;
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
Users.AdminPassword = adminPassword;
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
    o.LoginPath = "/login";
    o.AccessDeniedPath = "/";  // Nicht-Admin ruft Regeln/Einstellungen direkt auf
    o.Events.OnValidatePrincipal = async c =>
    {
        if (c.Principal?.FindFirst("stamp")?.Value != Users.Stamp(c.Principal?.Identity?.Name))
        {
            c.RejectPrincipal();
            await c.HttpContext.SignOutAsync();
        }
    };
});
builder.Services.AddAuthorization();
builder.Services.AddCascadingAuthenticationState();
builder.Services.AddSingleton<Scanner>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<Scanner>());
builder.Services.AddHostedService<Daemons>();

var app = builder.Build();
ImapPassword.Protector = app.Services.GetDataProtector("imap-password");
ImapPassword.Migrate();
Users.ResetProtector = app.Services.GetDataProtector("password-reset").ToTimeLimitedDataProtector();
app.UseExceptionHandler("/Error", createScopeForErrors: true);

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
app.UseAuthorization();
app.Use(async (ctx, next) =>
{
    if (ctx.User.Identity?.IsAuthenticated == true || ctx.Request.Path.Value is "/login" or "/forgot" or "/reset" or "/app.css")
        await next();
    else
        ctx.Response.Redirect("/login");
});

app.MapGet("/login", () => LoginPage("", null));
app.MapGet("/forgot", () => Mailer.Enabled ? ForgotPage(null) : Results.Redirect("/login"));
app.MapPost("/forgot", async (HttpContext ctx) =>
{
    if (!Mailer.Enabled) return Results.Redirect("/login");
    var email = (await ctx.Request.ReadFormAsync())["user"].ToString().Trim();
    if (Users.IsEmail(email) && Users.Exists(email))
    {
        var link = $"{Mailer.PublicUrl}/reset?t={Uri.EscapeDataString(Users.ResetToken(email))}";
        // im Hintergrund: Antwortzeit verrät nicht, ob es die Adresse gibt
        _ = Task.Run(async () =>
        {
            try { await Mailer.Send(email, "SpamSharp: Passwort zurücksetzen", $"Neues Passwort festlegen (1 Stunde gültig):\n{link}\n\nNicht angefordert? Dann einfach ignorieren."); }
            catch (Exception e) { Console.Error.WriteLine($"Mailversand an {email} fehlgeschlagen: {e.Message}"); }
        });
    }
    // ponytail: keine Mengenbegrenzung pro Adresse, nachrüsten falls jemand damit Mails flutet
    return ForgotPage("Falls es ein Konto mit dieser Adresse gibt, ist ein Link unterwegs.");
}).DisableAntiforgery();
app.MapGet("/reset", (string t) => Users.ResetUser(t) is null ? ForgotPage(null, "Der Link ist abgelaufen oder wurde schon benutzt.") : ResetPage(t, null));
app.MapPost("/reset", async (HttpContext ctx) =>
{
    var form = await ctx.Request.ReadFormAsync();
    var t = form["t"].ToString();
    if (Users.ResetUser(t) is not { } name) return ForgotPage(null, "Der Link ist abgelaufen oder wurde schon benutzt.");
    var pw = form["password"].ToString();
    if (pw.Length < 8) return ResetPage(t, "Das Passwort braucht mindestens 8 Zeichen.");
    Users.Save(name, pw);
    return LoginPage(name, null, "Passwort geändert, bitte anmelden.");
}).DisableAntiforgery();
app.MapPost("/login", async (HttpContext ctx) =>
{
    var form = await ctx.Request.ReadFormAsync();
    var entered = form["user"].ToString().Trim();
    if (Users.Login(entered, form["password"].ToString()) is not { } name)
    {
        await Task.Delay(1000); // bremst Durchprobieren
        return LoginPage(entered, "Benutzername oder Passwort falsch.");
    }
    List<Claim> claims = [new(ClaimTypes.Name, name), new("stamp", Users.Stamp(name)!)];
    if (name == Users.Admin) claims.Add(new(ClaimTypes.Role, Users.Admin));
    var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
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

static IResult LoginPage(string user, string? error, string? info = null) => Page("Anmelden", $$"""
    <form method="post" action="/login" class="form card">
        <h1>📬 SpamSharp</h1>
        <label>E-Mail-Adresse <input name="user" value="{{WebUtility.HtmlEncode(user)}}" autocomplete="username" autocapitalize="none" required {{(user == "" ? "autofocus" : "")}} /></label>
        <label>Passwort <input type="password" name="password" autocomplete="current-password" required {{(user == "" ? "" : "autofocus")}} /></label>
        {{Note(error, info)}}
        <button class="primary">Anmelden</button>
        {{(Mailer.Enabled ? "<a href=\"/forgot\">Passwort vergessen?</a>" : "")}}
    </form>
    """);

static IResult ForgotPage(string? info, string? error = null) => Page("Passwort vergessen", $$"""
    <form method="post" action="/forgot" class="form card">
        <h1>Passwort vergessen</h1>
        <label>E-Mail-Adresse <input type="email" name="user" autocomplete="username" required autofocus /></label>
        {{Note(error, info)}}
        <button class="primary">Link schicken</button>
        <a href="/login">Zur Anmeldung</a>
    </form>
    """);

static IResult ResetPage(string token, string? error) => Page("Neues Passwort", $$"""
    <form method="post" action="/reset" class="form card">
        <h1>Neues Passwort</h1>
        <input type="hidden" name="t" value="{{WebUtility.HtmlEncode(token)}}" />
        <label>Neues Passwort <small>mind. 8 Zeichen</small> <input type="password" name="password" autocomplete="new-password" minlength="8" required autofocus /></label>
        {{Note(error, null)}}
        <button class="primary">Speichern</button>
    </form>
    """);

static string Note(string? error, string? info) =>
    error is not null ? $"<p class=\"err\" role=\"alert\">{error}</p>" : info is not null ? $"<p class=\"ok\" role=\"status\">{info}</p>" : "";

static IResult Page(string title, string body) => Results.Content($$"""
    <!DOCTYPE html>
    <html lang="de">
    <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <title>{{title}} – SpamSharp</title>
        <link rel="stylesheet" href="/app.css" />
        <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>📬</text></svg>" />
    </head>
    <body class="login">
        {{body}}
    </body>
    </html>
    """, "text/html; charset=utf-8");
