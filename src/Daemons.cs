using System.Diagnostics;
using System.Runtime.InteropServices;

namespace SpamSharp;

// Startet redis und rspamd im selben Container und startet sie nach einem Absturz neu
public class Daemons(ILogger<Daemons> log) : BackgroundService
{
    [DllImport("libc", EntryPoint = "kill")]
    static extern int Kill(int pid, int signal);

    protected override Task ExecuteAsync(CancellationToken ct) => Task.WhenAll(
        Run("redis", "redis-server", $"--bind 127.0.0.1 --port 6379 --dir {Paths.Data}/redis --save 60 1 --appendonly no", ct),
        Run("rspamd", "rspamd", "-f", ct));

    async Task Run(string name, string file, string args, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                using var p = Process.Start(new ProcessStartInfo(file, args) { RedirectStandardOutput = true, RedirectStandardError = true })!;
                p.OutputDataReceived += (_, e) => { if (e.Data is { Length: > 0 }) log.LogInformation("[{Name}] {Line}", name, e.Data); };
                p.ErrorDataReceived += (_, e) => { if (e.Data is { Length: > 0 }) log.LogWarning("[{Name}] {Line}", name, e.Data); };
                p.BeginOutputReadLine();
                p.BeginErrorReadLine();
                try
                {
                    await p.WaitForExitAsync(ct);
                }
                catch (OperationCanceledException)
                {
                    Kill(p.Id, 15);  // SIGTERM: sauber beenden, redis speichert dabei
                    p.WaitForExit(10_000);
                    return;
                }
                log.LogWarning("{Name} beendet (Code {Code}), Neustart in 5 s", name, p.ExitCode);
            }
            catch (Exception e)
            {
                log.LogError("{Name} startet nicht: {Message}", name, e.Message);
            }
            try { await Task.Delay(5000, ct); } catch (OperationCanceledException) { return; }
        }
    }
}
