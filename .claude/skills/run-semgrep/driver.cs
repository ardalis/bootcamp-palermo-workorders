// driver.cs
// Runs SemGrep against this codebase and prints a severity-organized summary.
// .NET 10 file-based app equivalent of driver.ps1.
//
// Runs natively on Windows: SemGrep ships win_amd64 wheels (1.170.0 verified),
// executed via uvx (uv's tool runner, installed per-user via winget — no admin,
// no Python install needed). If semgrep itself is already on PATH (Linux/CI),
// it is used directly.
//
// Usage (from repo root):
//   dotnet .claude/skills/run-semgrep/driver.cs
//   dotnet .claude/skills/run-semgrep/driver.cs -- -ScanPath src/UI -Config p/csharp
//   dotnet .claude/skills/run-semgrep/driver.cs -- -FailOnFindings   # exit 1 if any ERROR
// The leading "--" is optional; it stops the dotnet CLI from claiming options such as -h.

#:property PublishAot=false

using System.Diagnostics;
using System.Globalization;
using System.Text;
using System.Text.Json;

const string Usage = """
Usage: dotnet driver.cs -- [options]

  -Config <a,b,...>         SemGrep registry rulesets (default p/csharp,p/security-audit,p/secrets)
  -ScanPath <path>          File or directory to scan, relative to the current directory (default .)
  -OutFile <file>           Where the raw SemGrep JSON is written (default <temp>/semgrep-results.json)
  -FailOnFindings           Exit 1 when any ERROR/CRITICAL finding exists
  -ShowParseErrors          List every file SemGrep could not fully parse
  -SemgrepVersion <ver>     Pinned version for the uvx path (default 1.170.0)
""";

ArgParser opts;
try
{
    opts = new ArgParser(args,
        valueNames: ["Config", "ScanPath", "OutFile", "SemgrepVersion"],
        flagNames: ["FailOnFindings", "ShowParseErrors"]);
}
catch (ArgumentException ex)
{
    Console.Error.WriteLine(ex.Message);
    Console.Error.WriteLine(Usage);
    return 1;
}
if (opts.HelpRequested) { Console.WriteLine(Usage); return 0; }

var config = opts.GetList("Config") is { Length: > 0 } c ? c : ["p/csharp", "p/security-audit", "p/secrets"];
var scanPath = opts.Get("ScanPath") ?? ".";
var outFile = Path.GetFullPath(opts.Get("OutFile") ?? Path.Combine(Path.GetTempPath(), "semgrep-results.json"));
var failOnFindings = opts.Has("FailOnFindings");
var showParseErrors = opts.Has("ShowParseErrors");
var semgrepVersion = opts.Get("SemgrepVersion") ?? "1.170.0";

var absScanPath = Path.GetFullPath(scanPath);
if (!File.Exists(absScanPath) && !Directory.Exists(absScanPath))
{
    Console.Error.WriteLine($"Cannot find path '{scanPath}' because it does not exist.");
    return 1;
}
// Scan with a path relative to the current directory when possible, so result
// paths in the summary are repo-relative and clickable.
var relScan = Path.GetRelativePath(Directory.GetCurrentDirectory(), absScanPath);
var target = relScan.StartsWith("..", StringComparison.Ordinal) ? absScanPath : relScan;
var configArgs = config.SelectMany(cfg => new[] { "--config", cfg }).ToArray();
string[] commonArgs = ["scan", .. configArgs, "--metrics=off", "--quiet", "--json", "--output", outFile, target];

try
{
    var native = Proc.Which("semgrep");
    if (native is not null)
    {
        Console.WriteLine($"Using native semgrep: {native}");
        var code = Proc.RunInherit(native, commonArgs);
        if (code != 0) throw new InvalidOperationException($"semgrep exited with code {code}");
    }
    else
    {
        var uvx = GetUvx();
        Console.WriteLine($"Running semgrep {semgrepVersion} via uvx (rulesets: {string.Join(", ", config)})... full repo scan takes ~1-2 min.");
        var code = Proc.RunInherit(uvx, [$"semgrep=={semgrepVersion}", .. commonArgs]);
        if (code != 0) throw new InvalidOperationException($"semgrep (uvx) exited with code {code}");
    }
}
catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception)
{
    Console.Error.WriteLine(ex.Message);
    return 1;
}

using var report = JsonDocument.Parse(File.ReadAllText(outFile));
var root = report.RootElement;
var results = root.TryGetProperty("results", out var r) && r.ValueKind == JsonValueKind.Array
    ? r.EnumerateArray().Select(Finding.From).ToList()
    : [];
var parseErrors = root.TryGetProperty("errors", out var errs) && errs.ValueKind == JsonValueKind.Array
    ? errs.EnumerateArray()
        .Where(e => e.TryGetProperty("type", out var t) && t.ValueKind != JsonValueKind.Null && t.GetRawText().Contains("Parsing", StringComparison.Ordinal))
        .ToList()
    : [];
var scannedCount = root.TryGetProperty("paths", out var paths) && paths.TryGetProperty("scanned", out var scanned) && scanned.ValueKind == JsonValueKind.Array
    ? scanned.GetArrayLength().ToString(CultureInfo.InvariantCulture)
    : "?";

var sevRank = new Dictionary<string, int> { ["CRITICAL"] = 0, ["ERROR"] = 1, ["HIGH"] = 2, ["WARNING"] = 3, ["MEDIUM"] = 4, ["LOW"] = 5, ["INFO"] = 6 };
var groups = results
    .GroupBy(f => f.Severity)
    .OrderBy(g => sevRank.GetValueOrDefault(g.Key, 99))
    .ToList();

Console.WriteLine();
Console.WriteLine("================ SemGrep Summary ================");
Console.WriteLine($"Scanned files : {scannedCount}");
Console.WriteLine($"Rulesets      : {string.Join(", ", config)}");
Console.WriteLine($"Raw JSON      : {outFile}");
var counts = string.Join("  ", groups.Select(g => $"{g.Key}: {g.Count()}"));
if (counts.Length == 0) counts = "none";
Console.WriteLine($"Findings      : {results.Count} total  ({counts})");
Console.WriteLine($"Parse errors  : {parseErrors.Count} files partially parsed (findings in those files may be missed)");
Console.WriteLine("=================================================");

foreach (var group in groups)
{
    Console.WriteLine();
    Console.WriteLine($"---- {group.Key} ({group.Count()}) ----");
    foreach (var f in group.OrderBy(x => x.CheckId, StringComparer.OrdinalIgnoreCase).ThenBy(x => x.Path, StringComparer.OrdinalIgnoreCase))
    {
        var msg = f.Message.Split('\n')[0];
        if (msg.Length > 220) msg = msg[..220] + "...";
        var cweText = f.Cwe is null ? "" : $" [{f.Cwe}]";
        Console.WriteLine($"{f.Path}:{f.Line}  ({f.CheckId}){cweText}");
        Console.WriteLine($"    {msg}");
    }
}

if (showParseErrors && parseErrors.Count > 0)
{
    Console.WriteLine();
    Console.WriteLine("---- Partially parsed files ----");
    foreach (var p in parseErrors
                 .Select(e => e.TryGetProperty("path", out var pe) ? pe.GetString() : null)
                 .Where(p => !string.IsNullOrEmpty(p))
                 .Distinct(StringComparer.OrdinalIgnoreCase)
                 .Order(StringComparer.OrdinalIgnoreCase))
    {
        Console.WriteLine($"  {p}");
    }
}

if (failOnFindings && results.Any(f => f.Severity is "ERROR" or "CRITICAL"))
{
    Console.WriteLine();
    Console.WriteLine("FailOnFindings: ERROR-severity findings present -> exit 1");
    return 1;
}
return 0;

static string? FindUvx()
{
    var uvx = Proc.Which("uvx");
    if (uvx is not null) return uvx;
    if (OperatingSystem.IsWindows())
    {
        // The current shell may predate uv's PATH update - re-read PATH from the registry.
        var freshPath = Environment.GetEnvironmentVariable("Path", EnvironmentVariableTarget.User) + ";" +
                        Environment.GetEnvironmentVariable("Path", EnvironmentVariableTarget.Machine);
        uvx = Proc.Which("uvx", freshPath);
        if (uvx is not null) return uvx;
        // winget installs uv into its per-user Packages directory.
        var packages = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Microsoft", "WinGet", "Packages");
        if (Directory.Exists(packages))
        {
            uvx = Directory.EnumerateDirectories(packages, "astral-sh.uv*")
                .Select(d => Path.Combine(d, "uvx.exe"))
                .FirstOrDefault(File.Exists);
            if (uvx is not null) return uvx;
        }
    }
    return null;
}

static string GetUvx()
{
    var found = FindUvx();
    if (found is not null) return found;
    var winget = Proc.Which("winget") ?? throw new InvalidOperationException("uvx not found and winget unavailable. Install uv: https://docs.astral.sh/uv/");
    Console.WriteLine("uv not found - installing via winget (per-user, no admin)...");
    Proc.Run(winget, ["install", "--id", "astral-sh.uv", "-e", "--accept-source-agreements", "--accept-package-agreements"]);
    return FindUvx() ?? throw new InvalidOperationException("uvx not found after winget install. Install manually: winget install astral-sh.uv");
}

/// <summary>A single SemGrep result, flattened for reporting.</summary>
record Finding(string Severity, string CheckId, string Path, int Line, string Message, string? Cwe)
{
    public static Finding From(JsonElement e)
    {
        var extra = e.TryGetProperty("extra", out var x) ? x : default;
        string? cwe = null;
        if (extra.ValueKind == JsonValueKind.Object && extra.TryGetProperty("metadata", out var md) && md.ValueKind == JsonValueKind.Object && md.TryGetProperty("cwe", out var cweEl))
        {
            cwe = cweEl.ValueKind switch
            {
                JsonValueKind.Array when cweEl.GetArrayLength() > 0 => cweEl[0].ToString(),
                JsonValueKind.String => cweEl.GetString(),
                _ => null,
            };
        }
        return new Finding(
            Severity: Str(extra, "severity") ?? "",
            CheckId: Str(e, "check_id") ?? "",
            Path: Str(e, "path") ?? "",
            Line: e.TryGetProperty("start", out var s) && s.TryGetProperty("line", out var l) ? l.GetInt32() : 0,
            Message: Str(extra, "message") ?? "",
            Cwe: string.IsNullOrEmpty(cwe) ? null : cwe);
    }

    static string? Str(JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
}

/// <summary>PowerShell-style argument parser: -Name value, --name value, -Name:value, -Switch, -Switch:false. Names are case- and dash-insensitive.</summary>
sealed class ArgParser
{
    readonly Dictionary<string, List<string>> _values = new();
    readonly HashSet<string> _flags = new();

    public bool HelpRequested { get; }

    public ArgParser(string[] args, IEnumerable<string> valueNames, IEnumerable<string> flagNames)
    {
        var valueSet = valueNames.Select(Normalize).ToHashSet();
        var flagSet = flagNames.Select(Normalize).ToHashSet();
        for (var i = 0; i < args.Length; i++)
        {
            var arg = args[i];
            if (arg == "--") continue;
            if (arg is "-?" or "/?" or "-h" or "--help" or "-help" or "-Help") { HelpRequested = true; continue; }
            if (arg.Length < 2 || arg[0] != '-') throw new ArgumentException($"Unexpected argument '{arg}'.");

            var body = arg.TrimStart('-');
            string? inline = null;
            var sep = body.IndexOfAny([':', '=']);
            if (sep >= 0) { inline = body[(sep + 1)..]; body = body[..sep]; }
            var key = Normalize(body);

            if (flagSet.Contains(key))
            {
                if (inline is null || !IsFalse(inline)) _flags.Add(key); else _flags.Remove(key);
                continue;
            }
            if (!valueSet.Contains(key)) throw new ArgumentException($"Unknown parameter '{arg}'.");
            var value = inline ?? (i + 1 < args.Length ? args[++i] : throw new ArgumentException($"Missing value for '{arg}'."));
            if (!_values.TryGetValue(key, out var list)) _values[key] = list = [];
            list.Add(value);
        }
    }

    public string? Get(string name) => _values.TryGetValue(Normalize(name), out var list) ? list[^1] : null;

    public string[] GetList(string name) => _values.TryGetValue(Normalize(name), out var list)
        ? list.SelectMany(v => v.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)).ToArray()
        : [];

    public bool Has(string name) => _flags.Contains(Normalize(name));

    static bool IsFalse(string s) => s.Equals("false", StringComparison.OrdinalIgnoreCase) || s.Equals("$false", StringComparison.OrdinalIgnoreCase) || s == "0";

    static string Normalize(string s) => s.Replace("-", "").Replace("_", "").ToLowerInvariant();
}

/// <summary>Process helpers.</summary>
static class Proc
{
    /// <summary>Resolves an executable on PATH (honouring PATHEXT on Windows). Returns null when not found.</summary>
    public static string? Which(string name, string? pathOverride = null)
    {
        var exts = OperatingSystem.IsWindows()
            ? (Environment.GetEnvironmentVariable("PATHEXT") ?? ".EXE;.CMD;.BAT").Split(';', StringSplitOptions.RemoveEmptyEntries).Prepend("")
            : [""];
        var dirs = (pathOverride ?? Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries);
        foreach (var dir in dirs)
        {
            foreach (var ext in exts)
            {
                if (OperatingSystem.IsWindows() && ext == "" && !Path.HasExtension(name)) continue;
                var candidate = Path.Combine(dir.Trim('"'), name + ext);
                if (File.Exists(candidate)) return candidate;
            }
        }
        return null;
    }

    /// <summary>Runs a process with stdio inherited from this console. Returns the exit code.</summary>
    public static int RunInherit(string file, IEnumerable<string> arguments)
    {
        var psi = new ProcessStartInfo(file) { UseShellExecute = false };
        foreach (var a in arguments) psi.ArgumentList.Add(a);
        using var p = Process.Start(psi) ?? throw new InvalidOperationException($"Could not start {file}");
        p.WaitForExit();
        return p.ExitCode;
    }

    /// <summary>Runs a process, capturing stdout and stderr separately.</summary>
    public static (int ExitCode, string StdOut, string StdErr) Run(string file, IEnumerable<string> arguments)
    {
        var psi = new ProcessStartInfo(file)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
        };
        foreach (var a in arguments) psi.ArgumentList.Add(a);
        using var p = Process.Start(psi) ?? throw new InvalidOperationException($"Could not start {file}");
        var stdout = p.StandardOutput.ReadToEndAsync();
        var stderr = p.StandardError.ReadToEndAsync();
        p.WaitForExit();
        return (p.ExitCode, stdout.Result, stderr.Result);
    }
}
