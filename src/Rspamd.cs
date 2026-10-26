using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace SpamSharp;

public record Symbol(string Name, double Score, string? Description, string? Options);

public record Rule(string Name, string Group, string? Description, double Weight);

// rspamd läuft im selben Container und ist nur über 127.0.0.1 erreichbar
public static class Rspamd
{
    static readonly HttpClient Http = new() { Timeout = TimeSpan.FromMinutes(2) };
    const string Normal = "http://127.0.0.1:11333", Controller = "http://127.0.0.1:11334";

    public static async Task<(double Score, List<Symbol> Symbols)> Check(byte[] raw, CancellationToken ct)
    {
        var j = await Send(HttpMethod.Post, Normal + "/checkv2", new ByteArrayContent(raw), ct)
                ?? throw new InvalidOperationException("rspamd: leere Antwort");
        var symbols = (j["symbols"]?.AsObject() ?? [])
            .Select(kv => new Symbol(kv.Key,
                kv.Value?["score"]?.GetValue<double>() ?? 0,
                kv.Value?["description"]?.GetValue<string>(),
                kv.Value?["options"] is JsonArray o ? string.Join(", ", o) : null))
            .OrderByDescending(s => Math.Abs(s.Score))
            .ToList();
        return (j["score"]!.GetValue<double>(), symbols);
    }

    // true = gelernt; false = von rspamd übersprungen (schon bekannt oder zu wenig Text)
    public static async Task<bool> Learn(byte[] raw, bool spam, CancellationToken ct)
    {
        var j = await Send(HttpMethod.Post, Controller + (spam ? "/learnspam" : "/learnham"), new ByteArrayContent(raw), ct);
        return j?["success"]?.GetValue<bool>() == true;
    }

    public static Task<JsonNode?> Stat() => Send(HttpMethod.Get, Controller + "/stat", null, default);

    public static async Task<List<Rule>> Rules()
    {
        var groups = (await Send(HttpMethod.Get, Controller + "/symbols", null, default))?.AsArray() ?? [];
        return groups
            .SelectMany(g => (g?["rules"]?.AsArray() ?? []).Select(r => new Rule(
                r!["symbol"]!.GetValue<string>(),
                g!["group"]?.GetValue<string>() ?? "",
                r["description"]?.GetValue<string>(),
                r["weight"]?.GetValue<double>() ?? 0)))
            .OrderBy(r => r.Name)
            .ToList();
    }

    public static Task SaveWeights(Dictionary<string, double> weights) =>
        Send(HttpMethod.Post, Controller + "/savesymbols", new StringContent(
            JsonSerializer.Serialize(weights.Select(w => new { name = w.Key, value = w.Value })), Encoding.UTF8, "application/json"), default);

    static async Task<JsonNode?> Send(HttpMethod method, string url, HttpContent? body, CancellationToken ct)
    {
        using var r = await Http.SendAsync(new HttpRequestMessage(method, url) { Content = body }, ct);
        var text = await r.Content.ReadAsStringAsync(ct);
        if (!r.IsSuccessStatusCode)
            throw new HttpRequestException($"rspamd {(int)r.StatusCode}: {text}");
        return text.Length == 0 ? null : JsonNode.Parse(text);  // 204 = übersprungen
    }
}
