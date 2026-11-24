// analyze.cs
// Runs Roslynator `analyze` against a .NET solution and prints a parsed summary.
// .NET 10 file-based app equivalent of analyze.ps1.
//
// Deterministic wrapper for the roslynator-analysis skill. Handles:
//   * preflight: verifies the Roslynator CLI is installed
//   * self-healing: detects the SDK-10 MSBuild `FileUtilities` TypeLoadException and
//     neutralizes the bundled Microsoft.Build.Framework.dll, then retries once
//     (see resources/TROUBLESHOOTING.md for the underlying cause)
//   * running `analyze` to a timestamped XML report under the OS temp directory
//   * parsing the report: severity breakdown, compiler (CS*) vs analyzer split, top rules
//
// Non-interactive by design. If -Solution is omitted it uses the sole discovered
// solution, or exits 3 listing candidates so the caller can pick one and re-invoke.
//
// Usage:
//   dotnet analyze.cs -- [-Solution <path.sln|.slnx>] [-SeverityLevel hidden|info|warning|error] [-Output <dir>] [-TopRules 20]
// The leading "--" is optional; it stops the dotnet CLI from claiming options such as -h.
//
// Exit codes: 0 success (report produced, diagnostics allowed) · 1 bad arguments · 2 tool not installed ·
// 3 solution resolution failed · 4 analysis failed for another reason.

#:property PublishAot=false

using System.Diagnostics;
using System.Globalization;
using System.Text;
using System.Xml.Linq;

const string Usage = """
Usage: dotnet analyze.cs -- [options]

  -Solution <path>          .sln/.slnx to analyze (default: the sole solution under the current directory)
  -SeverityLevel <level>    Minimum severity: hidden | info | warning | error (default info)
  -Output <dir>             Directory for the XML report (default <temp>/roslynator-analysis)
  -TopRules <n>             Number of analyzer rules to list in the summary (default 20)

Exit codes: 0 success · 2 tool not installed · 3 solution resolution failed · 4 analysis failed.
""";

ArgParser opts;
try
{
    opts = new ArgParser(args,
        valueNames: ["Solution", "SeverityLevel", "Output", "TopRules"],
        flagNames: []);
}
catch (ArgumentException ex)
{
    Console.Error.WriteLine(ex.Message);
    Console.Error.WriteLine(Usage);
    return 1;
}
if (opts.HelpRequested) { Console.WriteLine(Usage); return 0; }

var solution = opts.Get("Solution");
var severityLevel = (opts.Get("SeverityLevel") ?? "info").ToLowerInvariant();
if (severityLevel is not ("hidden" or "info" or "warning" or "error"))
{
    Console.Error.WriteLine($"-SeverityLevel must be one of hidden, info, warning, error (got '{severityLevel}').");
    return 1;
}
var output = opts.Get("Output");
var topRulesRaw = opts.Get("TopRules");
var topRules = 20;
if (topRulesRaw is not null && !int.TryParse(topRulesRaw, NumberStyles.Integer, CultureInfo.InvariantCulture, out topRules))
{
    Console.Error.WriteLine($"-TopRules expects an integer, got '{topRulesRaw}'.");
    return 1;
}

// --- 1. Preflight: Roslynator installed? ---------------------------------------
var roslynator = Proc.Which("roslynator");
string? version = null;
if (roslynator is not null)
{
    try
    {
        var v = Proc.Run(roslynator, ["--version"]);
        if (v.ExitCode == 0) version = v.StdOut.Trim();
    }
    catch (System.ComponentModel.Win32Exception) { }
}
if (string.IsNullOrEmpty(version) || roslynator is null)
{
    return Fail("Roslynator CLI not found. Install with: dotnet tool install -g roslynator.dotnet.cli", 2);
}
Console.WriteLine($"Roslynator {version}");

// --- 2. Resolve the solution ---------------------------------------------------
if (string.IsNullOrEmpty(solution))
{
    var cwd = Directory.GetCurrentDirectory();
    var found = FindFiles(cwd, f => f.EndsWith(".sln", StringComparison.OrdinalIgnoreCase) || f.EndsWith(".slnx", StringComparison.OrdinalIgnoreCase)).ToList();
    if (found.Count == 0)
    {
        return Fail($"No .sln/.slnx found under {cwd}. Pass -Solution explicitly.", 3);
    }
    if (found.Count > 1)
    {
        Console.WriteLine("Multiple solutions found - pass one via -Solution:");
        foreach (var f in found) Console.WriteLine($"  {f}");
        return 3;
    }
    solution = found[0];
}
if (!File.Exists(solution))
{
    return Fail($"Solution not found: {solution}", 3);
}
solution = Path.GetFullPath(solution);
Console.WriteLine($"Solution: {solution}");

// --- 3. Output path (temp-directory default, timestamped filename) -------------
output ??= Path.Combine(Path.GetTempPath(), "roslynator-analysis");
Directory.CreateDirectory(output);
var report = Path.Combine(output, $"analysis-{DateTime.Now:yyyyMMdd-HHmmssfff}.xml");

// --- 4. Run analysis (self-healing retry on the SDK-10 MSBuild conflict) --------
WriteSection("Analyzing");
var result = InvokeAnalyze();
// roslynator: exit 0 = clean, 1 = diagnostics found (both success). >=2 = failure.
if (result.ExitCode >= 2 && System.Text.RegularExpressions.Regex.IsMatch(result.Output, @"FileUtilities|Microsoft\.Build\.Framework"))
{
    Console.WriteLine("Detected SDK/MSBuild assembly conflict - applying workaround (see resources/TROUBLESHOOTING.md):");
    if (RepairBundledMSBuild() > 0)
    {
        Console.WriteLine("Retrying analysis...");
        result = InvokeAnalyze();
    }
}

if (!File.Exists(report) || result.ExitCode >= 2)
{
    Console.WriteLine(result.Output);
    return Fail($"Roslynator analysis failed (exit {result.ExitCode}). See resources/TROUBLESHOOTING.md.", 4);
}

// --- 5. Parse and summarize ----------------------------------------------------
XDocument xml;
try
{
    xml = XDocument.Load(report);
}
catch (Exception ex) when (ex is System.Xml.XmlException or IOException)
{
    return Fail($"Failed to read/parse Roslynator report XML: {report}. {ex.Message}", 4);
}

var summary = xml.Root?.Element("CodeAnalysis")?.Element("Summary")?.Elements("Diagnostic")
    .Select(d => new RuleCount(
        (string?)d.Attribute("Id") ?? "",
        (string?)d.Attribute("Title") ?? "",
        int.TryParse((string?)d.Attribute("Count"), NumberStyles.Integer, CultureInfo.InvariantCulture, out var n) ? n : 0))
    .ToList() ?? [];
var total = summary.Sum(s => s.Count);

WriteSection("Summary");
Console.WriteLine($"Total diagnostics: {total}  (distinct rules: {summary.Count})");

if (total > 0)
{
    // Detail nodes carry Severity as a child element: <Diagnostic Id="..."><Severity>Info</Severity>...
    var detail = xml.Descendants("Projects").Descendants("Diagnostic").ToList();
    if (detail.Count > 0)
    {
        Console.WriteLine();
        Console.WriteLine("By severity:");
        foreach (var g in detail.GroupBy(d => (string?)d.Element("Severity") ?? "").OrderByDescending(g => g.Count()))
        {
            Console.WriteLine(string.Format(CultureInfo.InvariantCulture, "  {0,-9} {1}", g.Key, g.Count()));
        }
    }

    var compiler = summary.Where(s => s.Id.StartsWith("CS", StringComparison.OrdinalIgnoreCase)).ToList();
    var analyzer = summary.Where(s => !s.Id.StartsWith("CS", StringComparison.OrdinalIgnoreCase)).ToList();

    Console.WriteLine();
    Console.WriteLine($"Compiler (CS*): {compiler.Sum(s => s.Count)} across {compiler.Count} rules  <- usually workspace-resolution noise, not defects.");
    Console.WriteLine("   If a normal build is green, ignore these. `dotnet restore` first reduces them.");
    Console.WriteLine($"Analyzer:       {analyzer.Sum(s => s.Count)} across {analyzer.Count} rules  <- the actionable findings.");

    if (analyzer.Count > 0)
    {
        WriteSection($"Top analyzer rules (max {topRules})");
        foreach (var rule in analyzer.OrderByDescending(s => s.Count).Take(topRules))
        {
            Console.WriteLine(string.Format(CultureInfo.InvariantCulture, "  {0,-11} {1,4}  {2}", rule.Id, rule.Count, rule.Title));
        }
    }
}

WriteSection("Report");
var fullReportPath = Path.GetFullPath(report);
Console.WriteLine($"  {fullReportPath}");
Console.WriteLine($"  {new Uri(fullReportPath).AbsoluteUri}");
return 0;

(int ExitCode, string Output) InvokeAnalyze()
{
    var r = Proc.RunMerged(roslynator, ["analyze", solution, "--output", report, "--severity-level", severityLevel, "--verbosity", "minimal"]);
    return (r.ExitCode, r.Output);
}

// Neutralize the bundled MSBuild framework DLL (SDK-10 workaround).
static int RepairBundledMSBuild()
{
    var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
    var roots = new[] { Environment.GetEnvironmentVariable("HOME"), home }
        .Where(h => !string.IsNullOrEmpty(h))
        .Select(h => Path.Combine(h!, ".dotnet", "tools", ".store"))
        .Where(Directory.Exists)
        .Distinct(StringComparer.OrdinalIgnoreCase);
    var renamed = 0;
    foreach (var root in roots)
    {
        foreach (var dll in Directory.EnumerateFiles(root, "Microsoft.Build.Framework.dll", SearchOption.AllDirectories)
                     .Where(p => p.Contains("roslynator.dotnet.cli", StringComparison.OrdinalIgnoreCase)))
        {
            try
            {
                File.Move(dll, dll + ".bak", overwrite: true);
                Console.WriteLine($"  neutralized {dll}");
                renamed++;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                Console.WriteLine($"  failed to neutralize {dll}: {ex.Message}");
            }
        }
    }
    return renamed;
}

// Recursive file search that skips hidden directories (matches Get-ChildItem -Recurse without -Force).
static IEnumerable<string> FindFiles(string root, Func<string, bool> match)
{
    var pending = new Stack<string>([root]);
    while (pending.Count > 0)
    {
        var dir = pending.Pop();
        IEnumerable<string> files, subdirs;
        try
        {
            files = Directory.EnumerateFiles(dir).ToList();
            subdirs = Directory.EnumerateDirectories(dir).ToList();
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
        {
            continue;
        }
        foreach (var f in files.Where(match)) yield return f;
        foreach (var d in subdirs.Reverse())
        {
            if ((new DirectoryInfo(d).Attributes & FileAttributes.Hidden) == 0) pending.Push(d);
        }
    }
}

static void WriteSection(string text)
{
    Console.WriteLine();
    Console.WriteLine($"=== {text} ===");
}

static int Fail(string message, int code)
{
    Console.Error.WriteLine(message);
    return code;
}

/// <summary>One row of the Roslynator report summary.</summary>
record RuleCount(string Id, string Title, int Count);

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

    /// <summary>Runs a process, capturing stdout and stderr separately.</summary>
    public static (int ExitCode, string StdOut, string StdErr) Run(string file, IEnumerable<string> arguments)
    {
        var psi = NewStartInfo(file, arguments);
        using var p = Process.Start(psi) ?? throw new InvalidOperationException($"Could not start {file}");
        var stdout = p.StandardOutput.ReadToEndAsync();
        var stderr = p.StandardError.ReadToEndAsync();
        p.WaitForExit();
        return (p.ExitCode, stdout.Result, stderr.Result);
    }

    /// <summary>Runs a process, capturing stdout and stderr interleaved into one string (like 2&gt;&amp;1).</summary>
    public static (int ExitCode, string Output) RunMerged(string file, IEnumerable<string> arguments)
    {
        var psi = NewStartInfo(file, arguments);
        var sb = new StringBuilder();
        var gate = new object();
        using var p = new Process { StartInfo = psi };
        p.OutputDataReceived += (_, e) => { if (e.Data is not null) lock (gate) sb.AppendLine(e.Data); };
        p.ErrorDataReceived += (_, e) => { if (e.Data is not null) lock (gate) sb.AppendLine(e.Data); };
        p.Start();
        p.BeginOutputReadLine();
        p.BeginErrorReadLine();
        p.WaitForExit();
        return (p.ExitCode, sb.ToString().TrimEnd());
    }

    static ProcessStartInfo NewStartInfo(string file, IEnumerable<string> arguments)
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
        return psi;
    }
}
