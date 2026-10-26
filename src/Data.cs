using Dapper;
using Microsoft.Data.Sqlite;

namespace SpamSharp;

public static class Paths
{
    public static readonly string Data = Environment.GetEnvironmentVariable("DATA_DIR") ?? "/data";
}

public class Account
{
    public long Id { get; set; }
    public string Name { get; set; } = "";
    public string Host { get; set; } = "";
    public int Port { get; set; } = 993;
    public string Username { get; set; } = "";
    // ponytail: Klartext in der sqlite-Datei, Schutz über Dateirechte von /data
    public string Password { get; set; } = "";
    public string Folder { get; set; } = "INBOX";
    public string SpamFolder { get; set; } = "Junk";
    public double Threshold { get; set; } = 6;
    public bool Enabled { get; set; } = true;
    public long? UidValidity { get; set; }
    public long LastUid { get; set; }
    public string? LastRun { get; set; }
    public string? Status { get; set; }
}

public class LogEntry
{
    public long Id { get; set; }
    public string Ts { get; set; } = "";
    public string? Account { get; set; }
    public string? Sender { get; set; }
    public string? Subject { get; set; }
    public double? Score { get; set; }
    public string Action { get; set; } = "";
    public string? Symbols { get; set; }
}

public static class Db
{
    const int LogKeep = 5000;
    static string cs = "";

    public static void Init(string path)
    {
        cs = new SqliteConnectionStringBuilder { DataSource = path }.ToString();
        Exec("""
            pragma journal_mode=wal;
            create table if not exists accounts(id integer primary key, name text not null, host text not null,
              port integer not null, username text not null, password text not null, folder text not null,
              spamfolder text not null, threshold real not null, enabled integer not null, uidvalidity integer,
              lastuid integer not null default 0, lastrun text, status text);
            create table if not exists log(id integer primary key, ts text not null, accountid integer, account text,
              sender text, subject text, score real, action text not null, symbols text);
            -- Message-IDs, die wir als Spam verschoben bzw. als Ham gelernt haben (erkennt zurückgeholte Mails)
            create table if not exists known(accountid integer, messageid text, kind text, primary key(accountid, messageid));
            create table if not exists settings(key text primary key, value text);
            """);
    }

    static SqliteConnection Open()
    {
        var c = new SqliteConnection(cs);
        c.Open();
        return c;
    }

    public static List<T> Query<T>(string sql, object? p = null)
    {
        using var c = Open();
        return c.Query<T>(sql, p).ToList();
    }

    public static int Exec(string sql, object? p = null)
    {
        using var c = Open();
        return c.Execute(sql, p);
    }

    public static string Now => DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");

    public static Account? Account(long id) => Query<Account>("select * from accounts where id=@id", new { id }).FirstOrDefault();

    public static List<Account> Accounts() => Query<Account>("select * from accounts order by name");

    public static void Status(long id, string status) =>
        Exec("update accounts set lastrun=@Now, status=@status where id=@id", new { id, status, Now });

    public static void Log(Account a, string? sender, string? subject, double? score, string action, string? symbols = null)
    {
        Exec("insert into log(ts,accountid,account,sender,subject,score,action,symbols) values(@Now,@Id,@Name,@sender,@subject,@score,@action,@symbols)",
            new { Now, a.Id, a.Name, sender, subject, score, action, symbols });
        Exec("delete from log where id <= (select max(id) from log) - @LogKeep", new { LogKeep });
    }

    public static string? Known(long acc, string mid) =>
        Query<string>("select kind from known where accountid=@acc and messageid=@mid", new { acc, mid }).FirstOrDefault();

    public static void SetKnown(long acc, string? mid, string kind)
    {
        if (mid is not null)
            Exec("insert or replace into known values(@acc,@mid,@kind)", new { acc, mid, kind });
    }

    public static void Count(string key) =>
        Exec("insert into settings values(@key,1) on conflict(key) do update set value=value+1", new { key });
}

public static class Settings
{
    public record Def(string Label, string Default, bool Numeric);

    public static readonly Dictionary<string, Def> All = new()
    {
        ["interval"] = new("Spätestens alle … Sekunden prüfen (neue Mails meldet der Server sofort per IDLE)", "300", true),
        ["learn_spam"] = new("Lernordner „ist Spam“", "Spam-lernen", false),
        ["learn_ham"] = new("Lernordner „kein Spam“", "Kein-Spam", false),
        ["max_size"] = new("Größere Mails nicht prüfen (Bytes)", "2000000", true),
        ["first_scan"] = new("Beim ersten Lauf die letzten … Mails prüfen", "50", true),
    };

    public static string Get(string key) =>
        Db.Query<string>("select value from settings where key=@key", new { key }).FirstOrDefault() ?? All[key].Default;

    public static int Int(string key) => int.Parse(Get(key));

    public static void Set(string key, string value) =>
        Db.Exec("insert or replace into settings values(@key,@value)", new { key, value });
}
