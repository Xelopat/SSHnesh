using System.Collections.Concurrent;
using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;

if (OperatingSystem.IsWindows() && args.Length == 3 && args[0] == "--secret" &&
    nint.TryParse(args[2], out var owner))
    return SecretDialog.Ask(args[1], owner);

if (!OperatingSystem.IsWindows() || args.Length != 1 ||
    !System.Text.RegularExpressions.Regex.IsMatch(args[0], "^sshash-[a-f0-9]{32}$"))
    return 2;
Console.InputEncoding = new UTF8Encoding(false);
Console.OutputEncoding = new UTF8Encoding(false);
await Run(args[0]);
return 0;

[SupportedOSPlatform("windows")]
static async Task Run(string name)
{
    using var identity = WindowsIdentity.GetCurrent();
    var owner = identity.User!;
    var security = new PipeSecurity();
    security.SetAccessRuleProtection(true, false);
    security.AddAccessRule(new PipeAccessRule(
        new SecurityIdentifier(WellKnownSidType.NetworkSid, null),
        PipeAccessRights.FullControl, AccessControlType.Deny));
    security.AddAccessRule(new PipeAccessRule(owner, PipeAccessRights.FullControl, AccessControlType.Allow));
    security.SetOwner(owner);

    using var stop = new CancellationTokenSource();
    using var slots = new SemaphoreSlim(12);
    var clients = new ConcurrentDictionary<int, NamedPipeServerStream>();
    int sequence = 0;
    void Emit(int id, string kind, byte[]? bytes = null) =>
        Console.WriteLine(JsonSerializer.Serialize(new { id, kind, bytes }));

    async Task Pump(int id, NamedPipeServerStream pipe)
    {
        try
        {
            var buffer = new byte[8192];
            while (!stop.IsCancellationRequested)
            {
                int read = await pipe.ReadAsync(buffer, stop.Token);
                if (read == 0) break;
                Emit(id, "data", buffer[..read]);
            }
        }
        catch (IOException) { }
        catch (ObjectDisposedException) { }
        catch (OperationCanceledException) { }
        finally
        {
            clients.TryRemove(id, out _);
            pipe.Dispose();
            slots.Release();
            Emit(id, "close");
        }
    }

    async Task Accept()
    {
        while (!stop.IsCancellationRequested)
        {
            await slots.WaitAsync(stop.Token);
            var pipe = NamedPipeServerStreamAcl.Create(name, PipeDirection.InOut,
                13, PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 8192, 8192, security);
            try { await pipe.WaitForConnectionAsync(stop.Token); }
            catch { pipe.Dispose(); throw; }
            var id = ++sequence;
            clients[id] = pipe;
            Emit(id, "open");
            _ = Pump(id, pipe);
        }
    }

    async Task Relay()
    {
        while (await Console.In.ReadLineAsync(stop.Token) is { } line)
        {
            using var document = JsonDocument.Parse(line);
            var packet = document.RootElement;
            if (!clients.TryGetValue(packet.GetProperty("id").GetInt32(), out var pipe)) continue;
            if (packet.GetProperty("kind").GetString() == "close")
            {
                pipe.Dispose();
                continue;
            }
            try
            {
                using var writeDeadline = CancellationTokenSource.CreateLinkedTokenSource(stop.Token);
                writeDeadline.CancelAfter(TimeSpan.FromSeconds(2));
                await pipe.WriteAsync(packet.GetProperty("bytes").GetBytesFromBase64(), writeDeadline.Token);
            }
            catch (IOException) { pipe.Dispose(); }
            catch (ObjectDisposedException) { }
            catch (OperationCanceledException) { pipe.Dispose(); }
        }
    }

    var accept = Accept();
    var relay = Relay();
    var ended = await Task.WhenAny(accept, relay);
    stop.Cancel();
    foreach (var pipe in clients.Values) pipe.Dispose();
    await ended;
}
