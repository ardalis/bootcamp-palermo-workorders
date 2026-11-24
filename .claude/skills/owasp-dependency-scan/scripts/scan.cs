// scan.cs
// Scan .NET and npm supply-chain dependencies for known vulnerabilities using OWASP
// Dependency-Check plus the native scanners, and write a consolidated report.
// .NET 10 file-based app equivalent of scan.ps1.
//
// Detects which ecosystems are present under -Path, runs the best available OWASP
// Dependency-Check runner (Docker image preferred, installed CLI as fallback), and
// always runs the fast native cross-checks (`dotnet list package --vulnerable` and
// `npm audit`). Merges all findings into <OutDir>/summary.md and leaves the raw
// OWASP DC reports (HTML/JSON/SARIF/etc.) alongside it.
//
// Usage:
//   dotnet scan.cs -- -Path .
//   dotnet scan.cs -- -Path . -FailOnCvss 7.0 -Format "HTML,JSON,SARIF,JUNIT"
//   dotnet scan.cs -- -Path . -SkipOwaspDc
// The leading "--" is optional; it stops the dotnet CLI from claiming options such as -h.

#:property PublishAot=false

using System.Diagnostics;
using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

const string Usage = """
Usage: dotnet scan.cs -- [options]

  -Path <dir>           Repository root to scan (default: current directory)
  -OutDir <dir>         Directory for reports (default: <Path>/.security/dependency-scan)
  -FailOnCvss <score>   Exit 1 when any finding has CVSS >= score (0-11; omit for local triage)
  -Format <list>        OWASP DC report formats: HTML,JSON,SARIF,JUNIT,CSV,XML,ALL (default HTML,JSON)
  -NvdApiKey <key>      NVD API key (default: $NVD_API_KEY)
  -Runner <mode>        OWASP DC runner: auto | docker | cli (default auto)
  -DataDir <dir>        OWASP DC NVD database cache (default ~/.owasp-dc-data)
  -SkipOwaspDc          Run only the native scanners (fast, no NVD download)
""";

ArgParser opts;
try
{
    opts = new ArgParser(args,
        valueNames: ["Path", "OutDir", "FailOnCvss", "Format", "NvdApiKey", "Runner", "DataDir"],
        flagNames: ["SkipOwaspDc"]);
}
catch (ArgumentException ex)
{
    Console.Error.WriteLine(ex.Message);
    Console.Error.WriteLine(Usage);
    return 1;
}
if (opts.HelpRequested) { Console.WriteLine(Usage); return 0; }

var scanRoot = opts.Get("Path") ?? ".";
if (!Directory.Exists(scanRoot))
{
    Console.Error.WriteLine($"Cannot find path '{scanRoot}' because it does not exist.");
    return 1;
}
scanRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(scanRoot));
var outDir = Path.GetFullPath(opts.Get("OutDir") ?? Path.Combine(scanRoot, ".security", "dependency-scan"));
var failOnCvssRaw = opts.Get("FailOnCvss");
var failOnCvss = -1d;
if (failOnCvssRaw is not null && !double.TryParse(failOnCvssRaw, NumberStyles.Float, CultureInfo.InvariantCulture, out failOnCvss))
{
    Console.Error.WriteLine($"-FailOnCvss expects a number, got '{failOnCvssRaw}'.");
    return 1;
}
var format = opts.Get("Format") ?? "HTML,JSON";
var nvdApiKey = opts.Get("NvdApiKey") ?? Environment.GetEnvironmentVariable("NVD_API_KEY");
var runner = (opts.Get("Runner") ?? "auto").ToLowerInvariant();
if (runner is not ("auto" or "docker" or "cli"))
{
    Console.Error.WriteLine($"-Runner must be one of auto, docker, cli (got '{runner}').");
    return 1;
}
var dataDir = Path.GetFullPath(opts.Get("DataDir") ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".owasp-dc-data"));
var skipOwaspDc = opts.Has("SkipOwaspDc");

Directory.CreateDirectory(outDir);
Directory.CreateDirectory(dataDir);

var findings = new List<Finding>();
var projectName = Path.GetFileName(scanRoot);

// ---------------------------------------------------------------------------
// Detect ecosystems
// ---------------------------------------------------------------------------
WriteStep($"Scanning {scanRoot}");
string[] excludedDirs = ["bin", "obj", "node_modules"];
var allFiles = FindFiles(scanRoot, excludedDirs).ToList();
var solutions = allFiles.Where(f => HasExtension(f, ".sln")).ToList();
var csprojs = allFiles.Where(f => HasExtension(f, ".csproj")).ToList();
var lockfiles = allFiles.Where(f => Path.GetFileName(f).Equals("package-lock.json", StringComparison.OrdinalIgnoreCase)).ToList();
var packageJsons = allFiles.Where(f => Path.GetFileName(f).Equals("package.json", StringComparison.OrdinalIgnoreCase)).ToList();
Console.WriteLine($"    .NET: {solutions.Count} sln, {csprojs.Count} csproj | npm: {lockfiles.Count} lockfile, {packageJsons.Count} package.json");

// ---------------------------------------------------------------------------
// Run
// ---------------------------------------------------------------------------
var owaspExit = 0;
InvokeDotnetScan();
InvokeNpmScan();
if (!skipOwaspDc)
{
    owaspExit = InvokeOwaspDc(ResolveRunner());
    ReadOwaspDcJson();
}
else
{
    WriteWarn("SkipOwaspDc set; ran native scanners only.");
}

// ---------------------------------------------------------------------------
// Consolidate -> summary.md
// ---------------------------------------------------------------------------
WriteStep("Writing summary");
int critical = 0, high = 0, moderate = 0, low = 0, other = 0;
foreach (var f in findings)
{
    switch (SeverityRank(f.Severity))
    {
        case 4: critical++; break;
        case 3: high++; break;
        case 2: moderate++; break;
        case 1: low++; break;
        default: other++; break;
    }
}
var sorted = findings
    .OrderByDescending(f => SeverityRank(f.Severity))
    .ThenBy(f => f.Package, StringComparer.OrdinalIgnoreCase)
    .ToList();

var sb = new StringBuilder();
sb.AppendLine($"# Dependency scan — {projectName}");
sb.AppendLine();
sb.AppendLine($"**Critical: {critical} · High: {high} · Moderate: {moderate} · Low: {low} · Other: {other}**");
sb.AppendLine();
sb.AppendLine("Sources: OWASP Dependency-Check, dotnet list --vulnerable, npm audit");
sb.AppendLine();
if (findings.Count == 0)
{
    sb.AppendLine("No known vulnerabilities found. ✅");
}
else
{
    sb.AppendLine("| Severity | Package | Installed | Fixed | Advisory/CVE | CVSS | Source |");
    sb.AppendLine("|----------|---------|-----------|-------|--------------|------|--------|");
    foreach (var f in sorted)
    {
        sb.AppendLine($"| {f.Severity} | {f.Package} | {f.Installed} | {f.Fixed} | {f.Id} | {f.Cvss} | {f.Source} |");
    }
}
var summaryPath = Path.Combine(outDir, "summary.md");
File.WriteAllText(summaryPath, sb.ToString());
File.WriteAllText(Path.Combine(outDir, "findings.json"), JsonSerializer.Serialize(findings, new JsonSerializerOptions
{
    WriteIndented = true,
    Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
}));

Console.WriteLine();
WriteColor($"Report: {summaryPath}", ConsoleColor.Green);
WriteColor($"Findings — Critical: {critical}  High: {high}  Moderate: {moderate}  Low: {low}", ConsoleColor.Green);

// Exit code: honor OWASP DC's own gate, and also gate on native findings if -FailOnCvss set.
if (owaspExit != 0) return owaspExit;
if (failOnCvss >= 0 && critical + high > 0)
{
    // Native scanners don't emit CVSS; treat High/Critical severity as a gate failure.
    WriteWarn("FailOnCvss set and High/Critical findings present in native scans.");
    return 1;
}
return 0;

// ---------------------------------------------------------------------------
// Native scanner: .NET
// ---------------------------------------------------------------------------
void InvokeDotnetScan()
{
    var dotnet = Proc.Which("dotnet");
    if (dotnet is null) { WriteWarn("dotnet not found; skipping .NET native scan."); return; }
    WriteStep(".NET: dotnet list package --vulnerable --include-transitive");
    var targets = solutions.Count > 0 ? solutions : csprojs;
    foreach (var t in targets)
    {
        Console.WriteLine($"    {Path.GetFileName(t)}");
        // Restore is required for the vulnerability data to resolve; ignore restore noise.
        Proc.Run(dotnet, ["restore", t, "--verbosity", "quiet"]);
        var raw = Proc.Run(dotnet, ["list", t, "package", "--vulnerable", "--include-transitive", "--format", "json"]).StdOut;
        if (string.IsNullOrWhiteSpace(raw)) continue;
        JsonDocument doc;
        try { doc = JsonDocument.Parse(raw); }
        catch (JsonException) { WriteWarn($"Could not parse dotnet output for {Path.GetFileName(t)}"); continue; }
        using (doc)
        {
            foreach (var proj in Arr(doc.RootElement, "projects"))
            foreach (var fw in Arr(proj, "frameworks"))
            foreach (var p in Arr(fw, "topLevelPackages").Concat(Arr(fw, "transitivePackages")))
            foreach (var v in Arr(p, "vulnerabilities"))
            {
                findings.Add(new(Str(p, "id"), Str(p, "resolvedVersion"), "", Str(v, "advisoryurl"), "", Str(v, "severity"), "dotnet"));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Native scanner: npm
// ---------------------------------------------------------------------------
void InvokeNpmScan()
{
    var npm = Proc.Which("npm");
    if (npm is null) { WriteWarn("npm not found; skipping npm native scan."); return; }
    WriteStep("npm audit");
    var dirs = lockfiles.Concat(packageJsons)
        .Select(f => Path.GetDirectoryName(f)!)
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .Order(StringComparer.OrdinalIgnoreCase);
    foreach (var d in dirs)
    {
        Console.WriteLine($"    {d}");
        var raw = Proc.Run(npm, ["audit", "--json"], workingDirectory: d).StdOut;
        if (string.IsNullOrWhiteSpace(raw)) continue;
        JsonDocument audit;
        try { audit = JsonDocument.Parse(raw); }
        catch (JsonException) { WriteWarn($"Could not parse npm audit output for {d}"); continue; }
        using (audit)
        {
            if (!audit.RootElement.TryGetProperty("vulnerabilities", out var vulns) || vulns.ValueKind != JsonValueKind.Object) continue;
            foreach (var entry in vulns.EnumerateObject())
            {
                var v = entry.Value;
                var fixedVersion = v.TryGetProperty("fixAvailable", out var fa) && fa.ValueKind == JsonValueKind.Object ? Str(fa, "version") : "";
                var id = Arr(v, "via").FirstOrDefault(x => x.ValueKind == JsonValueKind.Object) is { ValueKind: JsonValueKind.Object } via ? Str(via, "url") : "";
                findings.Add(new(entry.Name, Str(v, "range"), fixedVersion, id, "", Str(v, "severity"), "npm"));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// OWASP Dependency-Check
// ---------------------------------------------------------------------------
string ResolveRunner()
{
    if (runner == "docker") return "docker";
    if (runner == "cli") return "cli";
    var docker = Proc.Which("docker");
    if (docker is not null)
    {
        // Confirm the daemon is reachable, not just the client.
        if (Proc.Run(docker, ["info"]).ExitCode == 0) return "docker";
        WriteWarn("Docker client found but daemon not reachable; trying CLI.");
    }
    return Proc.Which("dependency-check") is not null || Proc.Which("dependency-check.bat") is not null ? "cli" : "none";
}

bool TestJavaVersion()
{
    var java = Proc.Which("java");
    if (java is null) return false;
    var (_, stdout, stderr) = Proc.Run(java, ["-version"]);
    var m = Regex.Match(stdout + " " + stderr, @"version ""?(\d+)(?:\.(\d+))?");
    if (!m.Success) return false;
    var major = int.Parse(m.Groups[1].Value, CultureInfo.InvariantCulture);
    if (major == 1 && m.Groups[2].Success) major = int.Parse(m.Groups[2].Value, CultureInfo.InvariantCulture); // "1.8" style
    if (major < 11)
    {
        WriteWarn($"Java {major} detected; OWASP DC 12.x needs Java 11+. Use the Docker runner.");
        return false;
    }
    return true;
}

int InvokeOwaspDc(string resolved)
{
    List<string> keyArgs = [];
    if (!string.IsNullOrEmpty(nvdApiKey))
    {
        keyArgs = ["--nvdApiKey", nvdApiKey];
    }
    else
    {
        WriteWarn("No NVD_API_KEY set. First NVD update will be slow (10+ min). Get a free key: https://nvd.nist.gov/developers/request-an-api-key");
    }
    var formatArgs = format.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
        .SelectMany(f => new[] { "--format", f });
    List<string> failArgs = failOnCvss >= 0 ? ["--failOnCVSS", failOnCvss.ToString(CultureInfo.InvariantCulture)] : [];

    switch (resolved)
    {
        case "docker":
        {
            WriteStep("OWASP Dependency-Check (Docker: owasp/dependency-check)");
            List<string> dockerArgs =
            [
                "run", "--rm",
                "-v", $"{scanRoot}:/src:ro",
                "-v", $"{outDir}:/report",
                "-v", $"{dataDir}:/usr/share/dependency-check/data",
                "owasp/dependency-check:latest",
                "--scan", "/src",
                "--project", projectName,
                "--out", "/report",
                "--enableExperimental",
                "--disableAssembly", // assembly analyzer needs a bundled dotnet not in the image
                .. formatArgs, .. keyArgs, .. failArgs,
            ];
            return Proc.RunInherit(Proc.Which("docker") ?? "docker", dockerArgs);
        }
        case "cli":
        {
            if (!TestJavaVersion())
            {
                WriteWarn("Skipping OWASP DC CLI run due to Java version. See references/install.md.");
                return 0;
            }
            WriteStep("OWASP Dependency-Check (installed CLI)");
            var dc = Proc.Which("dependency-check") ?? Proc.Which("dependency-check.bat") ?? "dependency-check";
            List<string> dcArgs =
            [
                "--scan", scanRoot,
                "--project", projectName,
                "--out", outDir,
                "--data", dataDir,
                "--enableExperimental",
                .. formatArgs, .. keyArgs, .. failArgs,
            ];
            return Proc.RunInherit(dc, dcArgs);
        }
        default:
            WriteWarn("No OWASP DC runner available (no Docker daemon, no installed CLI). See references/install.md. Ran native scanners only.");
            return 0;
    }
}

void ReadOwaspDcJson()
{
    var jsonReport = Path.Combine(outDir, "dependency-check-report.json");
    if (!File.Exists(jsonReport)) return;
    JsonDocument report;
    try { report = JsonDocument.Parse(File.ReadAllText(jsonReport)); }
    catch (JsonException) { WriteWarn("Could not parse OWASP DC JSON report."); return; }
    using (report)
    {
        foreach (var dep in Arr(report.RootElement, "dependencies"))
        {
            var vulns = Arr(dep, "vulnerabilities").ToList();
            if (vulns.Count == 0) continue;
            var pkg = Arr(dep, "packages").FirstOrDefault() is { ValueKind: JsonValueKind.Object } first ? Str(first, "id") : Str(dep, "fileName");
            foreach (var v in vulns)
            {
                var cvss = "";
                if (v.TryGetProperty("cvssv3", out var c3) && c3.ValueKind == JsonValueKind.Object) cvss = Str(c3, "baseScore");
                else if (v.TryGetProperty("cvssv2", out var c2) && c2.ValueKind == JsonValueKind.Object) cvss = Str(c2, "score");
                findings.Add(new(pkg, "", "", Str(v, "name"), cvss, Str(v, "severity"), "owasp-dc"));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
static int SeverityRank(string? sev)
{
    sev ??= "";
    if (Regex.IsMatch(sev, "critical", RegexOptions.IgnoreCase)) return 4;
    if (Regex.IsMatch(sev, "high", RegexOptions.IgnoreCase)) return 3;
    if (Regex.IsMatch(sev, "moderate|medium", RegexOptions.IgnoreCase)) return 2;
    if (Regex.IsMatch(sev, "low", RegexOptions.IgnoreCase)) return 1;
    return 0;
}

static IEnumerable<JsonElement> Arr(JsonElement e, string name) =>
    e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Array ? v.EnumerateArray() : [];

// Returns a property as text: strings verbatim, numbers as written, anything else empty.
static string Str(JsonElement e, string name)
{
    if (e.ValueKind != JsonValueKind.Object || !e.TryGetProperty(name, out var v)) return "";
    return v.ValueKind switch
    {
        JsonValueKind.String => v.GetString() ?? "",
        JsonValueKind.Number => v.GetRawText(),
        _ => "",
    };
}

static bool HasExtension(string file, string ext) => Path.GetExtension(file).Equals(ext, StringComparison.OrdinalIgnoreCase);

// Recursive file search that skips the excluded directory names and hidden directories
// (matches Get-ChildItem -Recurse without -Force plus the bin/obj/node_modules filter).
static IEnumerable<string> FindFiles(string root, string[] excludedDirNames)
{
    var pending = new Stack<string>([root]);
    while (pending.Count > 0)
    {
        var dir = pending.Pop();
        List<string> files, subdirs;
        try
        {
            files = Directory.EnumerateFiles(dir).ToList();
            subdirs = Directory.EnumerateDirectories(dir).ToList();
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
        {
            continue;
        }
        foreach (var f in files) yield return f;
        foreach (var d in Enumerable.Reverse(subdirs))
        {
            if (excludedDirNames.Contains(Path.GetFileName(d), StringComparer.OrdinalIgnoreCase)) continue;
            if ((new DirectoryInfo(d).Attributes & FileAttributes.Hidden) != 0) continue;
            pending.Push(d);
        }
    }
}

static void WriteStep(string msg) => WriteColor($"==> {msg}", ConsoleColor.Cyan);

static void WriteWarn(string msg) => WriteColor($"!!  {msg}", ConsoleColor.Yellow);

static void WriteColor(string msg, ConsoleColor color)
{
    var previous = Console.ForegroundColor;
    Console.ForegroundColor = color;
    Console.WriteLine(msg);
    Console.ForegroundColor = previous;
}

/// <summary>A single vulnerability finding from any scanner.</summary>
record Finding(string Package, string Installed, string Fixed, string Id, string Cvss, string Severity, string Source);

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

    public bool Has(string name) => _flags.Contains(Normalize(name));

    static bool IsFalse(string s) => s.Equals("false", StringComparison.OrdinalIgnoreCase) || s.Equals("$false", StringComparison.OrdinalIgnoreCase) || s == "0";

    static string Normalize(string s) => s.Replace("-", "").Replace("_", "").ToLowerInvariant();
}

/// <summary>Process helpers.</summary>
static class Proc
{
    /// <summary>Resolves an executable on PATH (honouring PATHEXT on Windows). Returns null when not found.</summary>
    public static string? Which(string name)
    {
        var exts = OperatingSystem.IsWindows()
            ? (Environment.GetEnvironmentVariable("PATHEXT") ?? ".EXE;.CMD;.BAT").Split(';', StringSplitOptions.RemoveEmptyEntries).Prepend("")
            : [""];
        var dirs = (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries);
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
    public static (int ExitCode, string StdOut, string StdErr) Run(string file, IEnumerable<string> arguments, string? workingDirectory = null)
    {
        var psi = new ProcessStartInfo(file)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
        };
        if (workingDirectory is not null) psi.WorkingDirectory = workingDirectory;
        foreach (var a in arguments) psi.ArgumentList.Add(a);
        using var p = Process.Start(psi) ?? throw new InvalidOperationException($"Could not start {file}");
        var stdout = p.StandardOutput.ReadToEndAsync();
        var stderr = p.StandardError.ReadToEndAsync();
        p.WaitForExit();
        return (p.ExitCode, stdout.Result, stderr.Result);
    }
}
