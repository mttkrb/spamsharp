using System.Xml;
using System.Xml.Linq;
using DnsClient;

namespace SpamSharp;

public record Discovered(string Host, int Port, string Username, string Source);

// Findet die IMAP-Einstellungen zur Domain einer E-Mail-Adresse, so wie Thunderbird
public static class Autodiscover
{
    static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(6), MaxResponseContentBufferSize = 1_000_000 };
    static readonly LookupClient Dns = new(new LookupClientOptions { Timeout = TimeSpan.FromSeconds(4) });
    const string Ispdb = "https://autoconfig.thunderbird.net/v1.1/";

    public static async Task<Discovered?> Find(string email)
    {
        email = email.Trim();
        if (email.Split('@') is not [{ Length: > 0 }, var d] || Uri.CheckHostName(d) != UriHostNameType.Dns || !d.Contains('.'))
            return null;
        var domain = d.ToLowerInvariant();

        // alle Quellen gleichzeitig starten, Ergebnis nach Priorität nehmen
        var tries = new[]
        {
            Config($"https://autoconfig.{domain}/mail/config-v1.1.xml?emailaddress={Uri.EscapeDataString(email)}", email, $"autoconfig.{domain}"),
            Config($"https://{domain}/.well-known/autoconfig/mail/config-v1.1.xml", email, domain),
            Config(Ispdb + domain, email, "Thunderbird-Datenbank"),
            Srv(domain, email),
            ViaMx(domain, email),
        };
        foreach (var t in tries)
            if (await t is { } found) return found;
        return null;
    }

    // Mozilla-autoconfig-XML (auch Format der Thunderbird-Datenbank)
    static async Task<Discovered?> Config(string url, string email, string source)
    {
        try
        {
            var xml = await Http.GetStringAsync(url);  // nur https; Weiterleitung auf http folgt .NET nicht
            using var reader = XmlReader.Create(new StringReader(xml), new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit });
            var server = XDocument.Load(reader).Descendants("incomingServer")
                .Where(s => (string?)s.Attribute("type") == "imap")
                .Select(s => (Host: (string?)s.Element("hostname"), Port: (int?)s.Element("port"),
                              Socket: (string?)s.Element("socketType"), User: (string?)s.Element("username")))
                .Where(s => s is { Host: not null, Port: not null } && Fits(s.Socket == "SSL", s.Port.Value) && s.Socket is "SSL" or "STARTTLS")
                .OrderBy(s => s.Socket == "SSL" ? 0 : 1)
                .FirstOrDefault();
            if (server.Host is null) return null;
            return new(Fill(server.Host, email), server.Port!.Value, Fill(server.User ?? "%EMAILADDRESS%", email), source);
        }
        catch
        {
            return null;
        }
    }

    // RFC 6186: _imaps._tcp bzw. _imap._tcp
    static async Task<Discovered?> Srv(string domain, string email)
    {
        try
        {
            foreach (var (name, ssl) in new[] { ($"_imaps._tcp.{domain}", true), ($"_imap._tcp.{domain}", false) })
            {
                var rec = (await Dns.QueryAsync(name, QueryType.SRV)).Answers.SrvRecords()
                    .Where(r => r.Target.Value != ".")  // "." = Dienst nicht angeboten
                    .OrderBy(r => r.Priority).FirstOrDefault();
                if (rec is not null && Fits(ssl, rec.Port))
                    return new(rec.Target.Value.TrimEnd('.'), rec.Port, email, "DNS-Eintrag (SRV)");
            }
        }
        catch { }
        return null;
    }

    // Eigene Domain bei einem Hoster: über den Mailserver (MX) den Anbieter in der Thunderbird-Datenbank suchen
    static async Task<Discovered?> ViaMx(string domain, string email)
    {
        try
        {
            var mx = (await Dns.QueryAsync(domain, QueryType.MX)).Answers.MxRecords()
                .OrderBy(m => m.Preference).FirstOrDefault()?.Exchange.Value.TrimEnd('.');
            if (mx is null) return null;
            // ponytail: Basis-Domain = letzte zwei Teile; bei co.uk o. Ä. gibt es dann einfach keinen Treffer
            var baseDomain = string.Join('.', mx.Split('.').TakeLast(2));
            return baseDomain == domain ? null : await Config(Ispdb + baseDomain, email, $"Thunderbird-Datenbank über Mailserver {mx}");
        }
        catch
        {
            return null;
        }
    }

    // Unsere Port-Regel: 143 = STARTTLS, sonst SSL/TLS
    static bool Fits(bool ssl, int port) => ssl ? port != 143 : port == 143;

    static string Fill(string template, string email)
    {
        var at = email.IndexOf('@');
        return template.Replace("%EMAILADDRESS%", email).Replace("%EMAILLOCALPART%", email[..at]).Replace("%EMAILDOMAIN%", email[(at + 1)..]);
    }
}
