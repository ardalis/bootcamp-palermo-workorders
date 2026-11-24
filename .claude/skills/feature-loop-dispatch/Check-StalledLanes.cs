// Check-StalledLanes.cs
// Feature-loop stall watchdog. Detects lanes that stopped making progress without anyone noticing.
// Safe: read-only against GitHub (REST only). Exit code 0 = no stalls, 2 = stalls found.
// .NET 10 file-based app equivalent of Check-StalledLanes.ps1.
//
// Usage (from this folder):
//   dotnet Check-StalledLanes.cs -- -Repo ClearMeasureLabs/bootcamp-palermo-workorders [-StaleMinutes 15] [-Json]
//   dotnet Check-StalledLanes.cs -- -Repo <owner/repo> -TasksDir <dir> -ActiveIds id1,id2 [-LocalStaleMinutes 25]
// The leading "--" is optional; it stops the dotnet CLI from claiming options such as -h.
//
// Detects, per open PR:
//   GREEN_UNMERGED  - every check-run 'success' for > StaleMinutes, PR still open (stalled at merge step)
//   DIRTY           - PR has merge conflicts (needs master re-merged into branch)
//   CI_FAILED       - one or more check-runs concluded failure/cancelled/timed_out (needs fix+repush)
//   CI_STUCK        - newest check-run started > 60 min ago and still not completed
// And per recently-merged PR (last 30):
//   MERGED_ISSUE_OPEN - PR body says "Closes #N" (or branch names issue N) but issue N is still open
//                       > StaleMinutes after merge (missing closing keyword / stalled closeout)
// And, when -TasksDir and -ActiveIds are given:
//   LOCAL_STALL     - an active lane's <id>.output file is missing or untouched for > LocalStaleMinutes

#:property PublishAot=false

using System.Diagnostics;
using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

const string Usage = """
Usage: dotnet Check-StalledLanes.cs -- -Repo <owner/repo> [options]

  -Repo <owner/repo>        (required) GitHub repository to inspect
  -StaleMinutes <n>         Minutes green/merged before flagging (default 15)
  -TasksDir <dir>           Directory holding subagent task <id>.output files
  -ActiveIds <id,id,...>    Currently active task/agent IDs to check for LOCAL_STALL
  -LocalStaleMinutes <n>    Minutes without output-file writes before LOCAL_STALL (default 25)
  -Json                     Emit stalls as JSON instead of text

Exit codes: 0 = no stalls, 2 = stalls found, 1 = error.
""";

ArgParser opts;
try
{
    opts = new ArgParser(args,
        valueNames: ["Repo", "StaleMinutes", "TasksDir", "ActiveIds", "LocalStaleMinutes"],
        flagNames: ["Json"]);
}
catch (ArgumentException ex)
{
    Console.Error.WriteLine(ex.Message);
    Console.Error.WriteLine(Usage);
    return 1;
}
if (opts.HelpRequested) { Console.WriteLine(Usage); return 0; }

var repo = opts.Get("Repo");
if (string.IsNullOrWhiteSpace(repo))
{
    Console.Error.WriteLine("-Repo is required.");
    Console.Error.WriteLine(Usage);
    return 1;
}
var staleMinutes = opts.GetInt("StaleMinutes", 15);
var tasksDir = opts.Get("TasksDir");
var activeIds = opts.GetList("ActiveIds");
var localStaleMinutes = opts.GetInt("LocalStaleMinutes", 25);
var asJson = opts.Has("Json");

var gh = Proc.Which("gh") ?? "gh";
var now = DateTimeOffset.UtcNow;
var stalls = new List<Stall>();

try
{
    // ---- Open PRs ----
    using (var openPrs = GhJson("pr", "list", "-R", repo, "--state", "open", "--limit", "50",
               "--json", "number,headRefName,headRefOid,mergeStateStatus,updatedAt,title"))
    {
        foreach (var pr in openPrs.RootElement.EnumerateArray())
        {
            var number = pr.GetProperty("number").GetInt32();
            var branch = pr.GetProperty("headRefName").GetString() ?? "";
            var ci = GetCheckSummary(pr.GetProperty("headRefOid").GetString() ?? "");
            if (ci is null)
            {
                stalls.Add(new("CI_STUCK", number, branch, "No check-runs found on head commit (push may not have triggered CI)."));
                continue;
            }
            if (ci.Failed > 0)
            {
                stalls.Add(new("CI_FAILED", number, branch, $"Failed jobs: {string.Join(", ", ci.FailedNames)}. Needs fix + re-push."));
                continue;
            }
            if (ci.Incomplete > 0)
            {
                if (ci.FirstStartedAt is { } started && (now - started).TotalMinutes > 60)
                {
                    stalls.Add(new("CI_STUCK", number, branch, $"CI running > 60 min ({ci.Incomplete} job(s) incomplete)."));
                }
                continue; // CI still running within tolerance — not a stall
            }
            if (ci.Success == ci.Total && ci.Total > 0)
            {
                var greenAge = ci.LastCompletedAt is { } done ? (now - done).TotalMinutes : double.MaxValue;
                var mergeState = pr.TryGetProperty("mergeStateStatus", out var ms) ? ms.GetString() : null;
                if (string.Equals(mergeState, "DIRTY", StringComparison.OrdinalIgnoreCase))
                {
                    stalls.Add(new("DIRTY", number, branch, "Merge conflicts with base. Re-merge master into branch, rebuild, re-push."));
                }
                else if (greenAge > staleMinutes)
                {
                    stalls.Add(new("GREEN_UNMERGED", number, branch,
                        string.Format(CultureInfo.InvariantCulture, "All {0} checks green for {1:n0} min but PR not merged. Lane stalled at merge/triage step.", ci.Total, greenAge)));
                }
            }
        }
    }

    // ---- Recently merged PRs whose linked issue is still open ----
    var closingKeyword = new Regex(@"(?i)\b(?:close[sd]?|fix(?:e[sd])?|resolve[sd]?)\s+#(\d+)");
    var branchIssue = new Regex(@"(?i)(?:issue|fix)[/\-](\d+)");
    using (var mergedPrs = GhJson("pr", "list", "-R", repo, "--state", "merged", "--limit", "30",
               "--json", "number,body,headRefName,mergedAt"))
    {
        foreach (var pr in mergedPrs.RootElement.EnumerateArray())
        {
            var number = pr.GetProperty("number").GetInt32();
            var branch = pr.GetProperty("headRefName").GetString() ?? "";
            if (!DateTimeOffset.TryParse(pr.GetProperty("mergedAt").GetString(), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var mergedAt))
            {
                continue;
            }
            var mergedAge = (now - mergedAt).TotalMinutes;
            if (mergedAge <= staleMinutes) continue;

            var issueNums = new List<string>();
            var body = pr.TryGetProperty("body", out var b) ? b.GetString() : null;
            if (!string.IsNullOrEmpty(body))
            {
                issueNums.AddRange(closingKeyword.Matches(body).Select(m => m.Groups[1].Value));
            }
            var branchMatch = branchIssue.Match(branch);
            if (branchMatch.Success) issueNums.Add(branchMatch.Groups[1].Value);

            foreach (var n in issueNums.Distinct())
            {
                var stateResult = Proc.Run(gh, ["api", $"repos/{repo}/issues/{n}", "--jq", ".state"]);
                if (stateResult.ExitCode != 0) continue;
                if (stateResult.StdOut.Trim() != "open") continue;

                var subsResult = Proc.Run(gh, ["api", $"repos/{repo}/issues/{n}/sub_issues", "--jq", "[.[] | select(.state == \"open\")] | length"]);
                if (int.TryParse(subsResult.StdOut.Trim(), out var openSubs) && openSubs > 0) continue; // deliberately open: clamped behind open children

                stalls.Add(new("MERGED_ISSUE_OPEN", number, branch,
                    string.Format(CultureInfo.InvariantCulture, "PR merged {0:n0} min ago but issue #{1} is still open with no open children (missing closing keyword or stalled closeout).", mergedAge, n)));
            }
        }
    }
}
catch (Exception ex) when (ex is InvalidOperationException or JsonException or System.ComponentModel.Win32Exception)
{
    Console.Error.WriteLine(ex.Message);
    return 1;
}

// ---- Local lane liveness (pre-PR phase, invisible to GitHub) ----
if (!string.IsNullOrEmpty(tasksDir) && Directory.Exists(tasksDir) && activeIds.Length > 0)
{
    var cutoff = DateTime.Now.AddMinutes(-localStaleMinutes);
    foreach (var id in activeIds)
    {
        var file = new FileInfo(Path.Combine(tasksDir, $"{id}.output"));
        if (!file.Exists)
        {
            stalls.Add(new("LOCAL_STALL", 0, id, "Active lane has no task output file at all."));
        }
        else if (file.LastWriteTime < cutoff)
        {
            stalls.Add(new("LOCAL_STALL", 0, id,
                $"ACTIVE lane output untouched since {file.LastWriteTime:HH:mm:ss} (> {localStaleMinutes} min) - stalled pre-PR."));
        }
    }
}

if (asJson)
{
    Console.WriteLine(JsonSerializer.Serialize(stalls, new JsonSerializerOptions
    {
        WriteIndented = true,
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    }));
}
else
{
    var stamp = DateTimeOffset.Now.ToString("yyyy-MM-dd HH:mm:ss zzz", CultureInfo.InvariantCulture);
    if (stalls.Count == 0)
    {
        Console.WriteLine($"[{stamp}] OK - no stalled lanes detected in {repo}.");
    }
    else
    {
        Console.WriteLine($"[{stamp}] {stalls.Count} STALL(S) detected in {repo}:");
        foreach (var s in stalls)
        {
            Console.WriteLine($"  [{s.Kind}] PR #{s.PR} ({s.Branch}) - {s.Detail}");
        }
    }
}
return stalls.Count > 0 ? 2 : 0;

JsonDocument GhJson(params string[] ghArgs)
{
    var result = Proc.Run(gh, ghArgs);
    if (result.ExitCode != 0)
    {
        throw new InvalidOperationException($"gh {string.Join(' ', ghArgs)} failed (exit {result.ExitCode}): {result.StdErr.Trim()}");
    }
    return JsonDocument.Parse(result.StdOut);
}

CheckSummary? GetCheckSummary(string sha)
{
    // One JSON object per line across all pages.
    var result = Proc.Run(gh, ["api", $"repos/{repo}/commits/{sha}/check-runs", "--paginate",
        "--jq", ".check_runs[] | {name, status, conclusion, completed_at, started_at}"]);
    if (result.ExitCode != 0)
    {
        throw new InvalidOperationException($"gh api check-runs for {sha} failed (exit {result.ExitCode}): {result.StdErr.Trim()}");
    }

    var runs = new List<CheckRun>();
    foreach (var line in result.StdOut.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
    {
        using var doc = JsonDocument.Parse(line);
        var r = doc.RootElement;
        runs.Add(new CheckRun(
            r.GetProperty("name").GetString() ?? "",
            r.GetProperty("status").GetString() ?? "",
            GetStringOrNull(r, "conclusion"),
            ParseDate(GetStringOrNull(r, "completed_at")),
            ParseDate(GetStringOrNull(r, "started_at"))));
    }
    if (runs.Count == 0) return null;

    string[] failedConclusions = ["failure", "cancelled", "timed_out", "action_required"];
    var failed = runs.Where(r => r.Conclusion is not null && failedConclusions.Contains(r.Conclusion)).ToList();
    return new CheckSummary(
        Total: runs.Count,
        Success: runs.Count(r => r.Conclusion == "success"),
        Failed: failed.Count,
        Incomplete: runs.Count(r => r.Status != "completed"),
        LastCompletedAt: runs.Where(r => r.CompletedAt is not null).Max(r => r.CompletedAt),
        FirstStartedAt: runs.Where(r => r.StartedAt is not null).Min(r => r.StartedAt),
        FailedNames: failed.Select(r => r.Name).ToArray());
}

static string? GetStringOrNull(JsonElement e, string name) =>
    e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

static DateTimeOffset? ParseDate(string? s) =>
    DateTimeOffset.TryParse(s, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var d) ? d : null;

/// <summary>A detected stalled lane.</summary>
record Stall(string Kind, int PR, string Branch, string Detail);

/// <summary>One GitHub check-run on a commit.</summary>
record CheckRun(string Name, string Status, string? Conclusion, DateTimeOffset? CompletedAt, DateTimeOffset? StartedAt);

/// <summary>Aggregate of all check-runs on a commit.</summary>
record CheckSummary(int Total, int Success, int Failed, int Incomplete, DateTimeOffset? LastCompletedAt, DateTimeOffset? FirstStartedAt, string[] FailedNames);

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

    public int GetInt(string name, int fallback)
    {
        var raw = Get(name);
        if (raw is null) return fallback;
        return int.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out var v) ? v : throw new ArgumentException($"-{name} expects an integer, got '{raw}'.");
    }

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
