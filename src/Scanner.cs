using System.Collections.Concurrent;
using System.Text.Json;
using MailKit;
using MailKit.Net.Imap;
using MailKit.Search;
using MailKit.Security;

namespace SpamSharp;

// Überwacht jedes aktive Postfach in einer eigenen Schleife: prüfen, dann per IMAP IDLE auf neue Mails warten
public class Scanner(ILogger<Scanner> log) : BackgroundService
{
    const int TrainMax = 1000;
    readonly ConcurrentDictionary<long, CancellationTokenSource> loops = new();
    CancellationToken stopping;

    protected override Task ExecuteAsync(CancellationToken ct)
    {
        stopping = ct;
        RestartAll();
        return Task.CompletedTask;
    }

    // (Neu-)Start eines Postfachs: nach dem Speichern, Löschen oder für „Jetzt prüfen“
    public void Restart(long id)
    {
        if (loops.TryRemove(id, out var old)) old.Cancel();
        if (Db.Account(id) is not { Enabled: true }) return;
        var cts = CancellationTokenSource.CreateLinkedTokenSource(stopping);
        loops[id] = cts;
        _ = Task.Run(() => Loop(id, cts.Token));
    }

    public void RestartAll()
    {
        foreach (var a in Db.Accounts()) Restart(a.Id);
    }

    async Task Loop(long id, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                using var imap = await Connect(Db.Account(id)!, ct);
                do Db.Status(id, await Process(imap, Db.Account(id)!, ct));
                while (await WaitForMail(imap, Db.Account(id)!, ct));
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                return;
            }
            catch (Exception e)
            {
                log.LogWarning("Postfach {Id}: {Message}", id, e.Message);
                Db.Status(id, $"Fehler: {e.Message} (neuer Versuch in 1 Minute)");
                try { await Task.Delay(TimeSpan.FromMinutes(1), ct); } catch (OperationCanceledException) { return; }
            }
        }
    }

    public static async Task<ImapClient> Connect(Account a, CancellationToken ct)
    {
        // Kette und Hostname werden geprüft; Sperrlisten nicht (wie Browser), sonst Abbruch wenn der CRL-Server hängt
        var imap = new ImapClient { Timeout = 120_000, CheckCertificateRevocation = false };
        try
        {
            await imap.ConnectAsync(a.Host, a.Port, a.Port == 143 ? SecureSocketOptions.StartTls : SecureSocketOptions.SslOnConnect, ct);
            await imap.AuthenticateAsync(a.Username, a.Password, ct);
            return imap;
        }
        catch
        {
            imap.Dispose();
            throw;
        }
    }

    // true = Verbindung bleibt offen (IDLE), false = Server kann kein IDLE, neu verbinden
    static async Task<bool> WaitForMail(ImapClient imap, Account acc, CancellationToken ct)
    {
        var interval = TimeSpan.FromSeconds(Settings.Int("interval"));
        if (!imap.Capabilities.HasFlag(ImapCapabilities.Idle))
        {
            await imap.DisconnectAsync(true, ct);
            await Task.Delay(interval, ct);
            return false;
        }
        var inbox = await imap.GetFolderAsync(acc.Folder, ct);
        await inbox.OpenAsync(FolderAccess.ReadOnly, ct);
        using var done = new CancellationTokenSource(interval);
        void OnChange(object? s, EventArgs e) => done.Cancel();
        inbox.CountChanged += OnChange;
        try { await imap.IdleAsync(done.Token, ct); }
        finally { inbox.CountChanged -= OnChange; }
        return true;
    }

    static async Task<string> Process(ImapClient imap, Account acc, CancellationToken ct)
    {
        var inbox = await imap.GetFolderAsync(acc.Folder, ct);
        var spamFolder = await SpamFolder(imap, acc, ct);
        var learned = await LearnFolder(imap, acc, Settings.Get("learn_spam"), true, spamFolder, ct)
                    + await LearnFolder(imap, acc, Settings.Get("learn_ham"), false, inbox, ct);

        await inbox.OpenAsync(FolderAccess.ReadWrite, ct);
        var uv = inbox.UidValidity;
        List<UniqueId> uids;
        if (uv != acc.UidValidity)
        {
            var all = await inbox.SearchAsync(SearchQuery.All, ct);
            uids = all.Skip(Math.Max(0, all.Count - Settings.Int("first_scan"))).ToList();
        }
        else
        {
            var range = new UniqueIdRange(new UniqueId(uv, (uint)acc.LastUid + 1), UniqueId.MaxValue);
            uids = (await inbox.SearchAsync(SearchQuery.Uids(range), ct)).Where(u => u.Id > acc.LastUid).ToList();
        }

        var spam = new List<UniqueId>();
        var spamIds = new List<string?>();
        if (uids.Count > 0)
        {
            var maxSize = Settings.Int("max_size");
            var items = await inbox.FetchAsync(uids, MessageSummaryItems.UniqueId | MessageSummaryItems.Size | MessageSummaryItems.Envelope, ct);
            foreach (var m in items)
            {
                var (mid, from, subject) = (m.Envelope?.MessageId, Sender(m.Envelope), m.Envelope?.Subject);
                var known = mid is null ? null : Db.Known(acc.Id, mid);
                if (known == "ham") continue;  // vom Nutzer bestätigt
                if (known == "spam")
                {
                    // Nutzer hat die Mail aus dem Spam-Ordner zurückgeholt: nicht erneut verschieben, sondern daraus lernen
                    var ok = await Rspamd.Learn(await Raw(inbox, m.UniqueId, ct), false, ct);
                    Db.SetKnown(acc.Id, mid, "ham");
                    Db.Log(acc, from, subject, null, "zurückgeholt → " + (ok ? "als kein Spam gelernt" : "bleibt im Posteingang (rspamd: zu kurz oder schon gelernt)"));
                    continue;
                }
                if (m.Size > maxSize)
                {
                    Db.Log(acc, from, subject, null, "übersprungen (zu groß)");
                    continue;
                }
                var (score, symbols) = await Rspamd.Check(await Raw(inbox, m.UniqueId, ct), ct);
                var isSpam = score >= acc.Threshold;
                if (isSpam)
                {
                    spam.Add(m.UniqueId);
                    spamIds.Add(mid);
                }
                Db.Log(acc, from, subject, score, isSpam ? "Spam → " + spamFolder.FullName : "ok", JsonSerializer.Serialize(symbols));
                Db.Count("stat_checked");
            }
            if (spam.Count > 0)
            {
                await inbox.MoveToAsync(spam, spamFolder, ct);
                foreach (var mid in spamIds) Db.SetKnown(acc.Id, mid, "spam");  // erst nach erfolgreichem Verschieben
                for (var i = 0; i < spam.Count; i++) Db.Count("stat_spam");
            }
        }

        var last = uids.Count > 0 ? uids.Max(u => u.Id) : uv == acc.UidValidity ? acc.LastUid : 0;
        Db.Exec("update accounts set uidvalidity=@uv, lastuid=@last where id=@Id", new { uv = (long)uv, last, acc.Id });

        var idle = imap.Capabilities.HasFlag(ImapCapabilities.Idle) ? " · wartet auf neue Mails" : "";
        var fromLearn = learned > 0 ? $", {learned} aus Lernordnern gelernt" : "";
        return $"OK: {uids.Count} geprüft, {spam.Count} Spam{fromLearn}{idle}";
    }

    // Mails aus einem Lernordner trainieren und danach in den Zielordner verschieben
    static async Task<int> LearnFolder(ImapClient imap, Account acc, string name, bool spam, IMailFolder target, CancellationToken ct)
    {
        var f = await Folder(imap, name, ct);
        await f.OpenAsync(FolderAccess.ReadWrite, ct);
        if (f.Count == 0) return 0;
        var items = await f.FetchAsync(0, -1, MessageSummaryItems.UniqueId | MessageSummaryItems.Envelope, ct);
        foreach (var m in items)
        {
            var ok = await Rspamd.Learn(await Raw(f, m.UniqueId, ct), spam, ct);
            Db.SetKnown(acc.Id, m.Envelope?.MessageId, spam ? "spam" : "ham");
            Db.Log(acc, Sender(m.Envelope), m.Envelope?.Subject, null,
                $"aus „{name}“ als {(spam ? "Spam" : "kein Spam")} " + (ok ? "gelernt" : "markiert (rspamd: zu kurz oder schon gelernt)"));
        }
        await f.MoveToAsync(items.Select(m => m.UniqueId).ToList(), target, ct);
        return items.Count;
    }

    // Spam-Ordner: eingetragener Name, sonst der vom Server gemeldete (SPECIAL-USE \Junk), sonst übliche Namen
    static async Task<IMailFolder> SpamFolder(ImapClient imap, Account acc, CancellationToken ct) =>
        acc.SpamFolder != "" ? await Folder(imap, acc.SpamFolder, ct)
                             : await DetectSpam(imap, ct) ?? await Folder(imap, "Junk", ct);

    static async Task<IMailFolder?> DetectSpam(ImapClient imap, CancellationToken ct)
    {
        if (imap.Capabilities.HasFlag(ImapCapabilities.SpecialUse) || imap.Capabilities.HasFlag(ImapCapabilities.XList))
            if (imap.GetFolder(SpecialFolder.Junk) is { } junk) return junk;
        foreach (var name in new[] { "Spam", "Junk", "Spamverdacht", "Junk-E-Mail", "Junk E-mail", "[Gmail]/Spam" })
            if (await Find(imap, name, ct) is { } f) return f;
        return null;
    }

    // Ordner suchen (auch unterhalb von "INBOX." bei solchen Servern)
    static async Task<IMailFolder?> Find(ImapClient imap, string path, CancellationToken ct)
    {
        var ns = imap.PersonalNamespaces[0];
        var candidates = new[] { path, ns.Path == "" ? path : ns.Path + ns.DirectorySeparator + path };
        foreach (var p in candidates.Distinct())
        {
            try { return await imap.GetFolderAsync(p, ct); }
            catch (FolderNotFoundException) { }
        }
        return null;
    }

    // Ordner suchen, sonst anlegen und abonnieren
    static async Task<IMailFolder> Folder(ImapClient imap, string path, CancellationToken ct)
    {
        if (await Find(imap, path, ct) is { } found) return found;
        var ns = imap.PersonalNamespaces[0];
        // ponytail: legt nur Ordner direkt unter der Wurzel an; verschachtelte Namen vorher im Mailprogramm anlegen
        var created = await imap.GetFolder(ns).CreateAsync(path, true, ct)
                      ?? throw new InvalidOperationException($"Ordner „{path}“ konnte nicht angelegt werden");
        await created.SubscribeAsync(ct);
        return created;
    }

    static string? Sender(Envelope? e) =>
        e?.From.Mailboxes.FirstOrDefault() is { } f ? (string.IsNullOrEmpty(f.Name) ? f.Address : $"{f.Name} <{f.Address}>") : null;

    static async Task<byte[]> Raw(IMailFolder f, UniqueId uid, CancellationToken ct)
    {
        using var s = await f.GetStreamAsync(uid, "", ct);  // BODY.PEEK: Mail bleibt ungelesen
        using var ms = new MemoryStream();
        await s.CopyToAsync(ms, ct);
        return ms.ToArray();
    }

    // Für „Verbindung testen“: alle Ordner und der Spam-Ordner, den der Scanner verwenden würde
    public static async Task<(List<string> Folders, string Spam)> Folders(Account a)
    {
        using var imap = await Connect(a, default);
        var list = await imap.GetFoldersAsync(imap.PersonalNamespaces[0]);
        var spam = a.SpamFolder != "" ? a.SpamFolder : (await DetectSpam(imap, default))?.FullName ?? "Junk (wird angelegt)";
        return (list.Select(f => f.FullName).Order().ToList(), spam);
    }

    // Einmaliges Anlernen mit vorhandenen Mails (verschiebt nichts)
    public void Train(long id, bool spam) => _ = Task.Run(async () =>
    {
        var acc = Db.Account(id)!;
        Db.Status(id, spam ? "Training Spam läuft …" : "Training kein Spam läuft …");
        try
        {
            using var imap = await Connect(acc, stopping);
            var f = spam ? await SpamFolder(imap, acc, stopping) : await Folder(imap, acc.Folder, stopping);
            await f.OpenAsync(FolderAccess.ReadOnly, stopping);
            // kein Spam: nur Mails älter als 7 Tage, die hat der Nutzer schon gesehen
            var uids = await f.SearchAsync(spam ? SearchQuery.All : SearchQuery.DeliveredBefore(DateTime.Now.AddDays(-7)), stopping);
            var take = uids.Skip(Math.Max(0, uids.Count - TrainMax)).ToList();
            var ok = 0;
            foreach (var u in take)
                if (await Rspamd.Learn(await Raw(f, u, stopping), spam, stopping)) ok++;
            Db.Status(id, $"Training: {ok} von {take.Count} Mails aus „{f.FullName}“ als {(spam ? "Spam" : "kein Spam")} gelernt (Rest war bekannt oder zu kurz)");
        }
        catch (Exception e)
        {
            Db.Status(id, "Training fehlgeschlagen: " + e.Message);
        }
    });
}
