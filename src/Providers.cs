namespace SpamSharp;

// Vorauswahl für verbreitete Anbieter. Host null = per Passwort nicht nutzbar.
public record Provider(string Name, string? Host, int Port, string[] Domains, string? Hint);

public static class Providers
{
    public static readonly Provider[] All =
    [
        new("Gmail", "imap.gmail.com", 993, ["gmail.com", "googlemail.com"],
            "Benötigt ein App-Passwort: Google-Konto → Sicherheit → 2-Schritt-Bestätigung → App-Passwörter."),
        new("GMX", "imap.gmx.net", 993, ["gmx.de", "gmx.net", "gmx.at", "gmx.ch"],
            "IMAP im Webmail einschalten: Einstellungen → POP3 & IMAP. Mit Zwei-Faktor-Anmeldung ein App-Passwort verwenden."),
        new("WEB.DE", "imap.web.de", 993, ["web.de"],
            "IMAP im Webmail einschalten: Einstellungen → POP3 & IMAP. Mit Zwei-Faktor-Anmeldung ein App-Passwort verwenden."),
        new("T-Online", "secureimap.t-online.de", 993, ["t-online.de", "magenta.de"],
            "Benötigt das separate E-Mail-Passwort (Telekom Login → E-Mail-Passwort), nicht das Login-Passwort."),
        new("Strato", "imap.strato.de", 993, [], "Benutzer ist die vollständige E-Mail-Adresse."),
        new("IONOS (1&1)", "imap.ionos.de", 993, [], "Benutzer ist die vollständige E-Mail-Adresse."),
        new("Yahoo", "imap.mail.yahoo.com", 993, ["yahoo.com", "yahoo.de", "ymail.com"],
            "Benötigt ein App-Passwort: Kontosicherheit → App-Passwort generieren."),
        new("iCloud", "imap.mail.me.com", 993, ["icloud.com", "me.com", "mac.com"],
            "Benötigt ein app-spezifisches Passwort: account.apple.com → Anmeldung und Sicherheit."),
        new("Posteo", "posteo.de", 993, ["posteo.de", "posteo.net"], null),
        new("mailbox.org", "imap.mailbox.org", 993, ["mailbox.org"], null),
        new("Outlook / Microsoft 365", null, 993, ["outlook.com", "outlook.de", "hotmail.com", "hotmail.de", "live.com", "live.de", "msn.com"],
            "Microsoft (Outlook, Hotmail, Microsoft 365) erlaubt keine IMAP-Anmeldung per Passwort mehr – wird nicht unterstützt."),
    ];

    public static Provider? ByName(string? name) => All.FirstOrDefault(p => p.Name == name);

    public static Provider? ByAddress(string? address) =>
        address?.Split('@') is [_, var domain] ? All.FirstOrDefault(p => p.Domains.Contains(domain.Trim().ToLowerInvariant())) : null;

    public static Provider? ByHost(string? host)
    {
        host = host?.Trim().ToLowerInvariant();
        // Microsoft 365 / Exchange Online (auch eigene Domains): keine Passwort-Anmeldung per IMAP
        if (host is "outlook.office365.com" or "imap-mail.outlook.com") return ByName("Outlook / Microsoft 365");
        return All.FirstOrDefault(p => p.Host is not null && p.Host == host);
    }
}
