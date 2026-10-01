using System.Collections.Immutable;
using Microsoft.Build.Locator;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.MSBuild;
using Microsoft.CodeAnalysis.Text;
using Dotnetarium.Analyzers;
using Dotnetarium.Config;

namespace Dotnetarium.Tool;

internal static class Program
{
    private static async Task<int> Main(string[] args)
    {
        if (args.Length == 0 || args.Any(arg => arg is "--help" or "-h" or "-?"))
        {
            PrintUsage();
            return args.Length == 0 ? 2 : 0;
        }

        Options options;
        try { options = Options.Parse(args); }
        catch (ArgumentException error)
        {
            Console.Error.WriteLine(error.Message);
            PrintUsage();
            return 2;
        }

        try
        {
            if (options.ConfigPath != null)
                new ConfigurationReader().GetProjectConfiguration(
                    ImmutableArray.Create<AdditionalText>(new FileAdditionalText(options.ConfigPath)));

            if (options.SdkPath != null)
            {
                var sdkPath = Path.GetFullPath(options.SdkPath);
                var dotnetRoot = Directory.GetParent(Directory.GetParent(sdkPath)!.FullName)!.FullName;
                if (!File.Exists(Path.Combine(sdkPath, "MSBuild.dll")) ||
                    !File.Exists(Path.Combine(dotnetRoot, "dotnet.exe")))
                    throw new ArgumentException("--sdk-path must name a versioned .NET SDK directory.");
                Environment.SetEnvironmentVariable("DOTNET_ROOT", dotnetRoot);
                Environment.SetEnvironmentVariable("PATH", dotnetRoot + Path.PathSeparator +
                    Environment.GetEnvironmentVariable("PATH"));
                MSBuildLocator.RegisterMSBuildPath(sdkPath);
            }
            else
                MSBuildLocator.RegisterDefaults();

            var target = Path.GetFullPath(options.Target);
            if (!File.Exists(target))
                throw new FileNotFoundException("Project or solution was not found.", target);

            using var workspace = MSBuildWorkspace.Create();
            var workspaceErrors = new List<string>();
            bool workspaceFailure = false;
            workspace.RegisterWorkspaceFailedHandler(diagnostic =>
            {
                workspaceErrors.Add(diagnostic.Diagnostic.Message);
                workspaceFailure |= diagnostic.Diagnostic.Kind == WorkspaceDiagnosticKind.Failure;
            });

            var projects = Path.GetExtension(target).ToLowerInvariant() switch
            {
                ".csproj" => new[] { await workspace.OpenProjectAsync(target) },
                ".sln" or ".slnx" => (await workspace.OpenSolutionAsync(target)).Projects.ToArray(),
                _ => throw new ArgumentException("Expected a .csproj, .sln, or .slnx path.")
            };
            if (!projects.Any(project => project.Language == LanguageNames.CSharp))
                throw new ArgumentException("The target contains no C# projects.");

            var analyzerTypes = typeof(DnaRuleCatalog).Assembly.GetTypes()
                .Where(type => !type.IsAbstract && typeof(DiagnosticAnalyzer).IsAssignableFrom(type) &&
                               type.GetCustomAttributes(typeof(DiagnosticAnalyzerAttribute), false).Length > 0)
                .OrderBy(type => type.FullName, StringComparer.Ordinal)
                .ToArray();
            var analyzers = analyzerTypes.Select(type => (DiagnosticAnalyzer)Activator.CreateInstance(type)!).ToImmutableArray();
            var diagnostics = new List<Diagnostic>();
            bool compilerErrors = false;

            foreach (var project in projects.Where(project => project.Language == LanguageNames.CSharp))
            {
                var compilation = await project.GetCompilationAsync();
                if (compilation == null)
                {
                    Console.Error.WriteLine($"Unable to compile {project.Name}.");
                    compilerErrors = true;
                    continue;
                }

                var additionalFiles = project.AnalyzerOptions.AdditionalFiles;
                if (options.ConfigPath != null)
                    additionalFiles = additionalFiles
                        .Where(file => !string.Equals(Path.GetFileName(file.Path), "Dotnetarium.json", StringComparison.OrdinalIgnoreCase))
                        .Append(new FileAdditionalText(options.ConfigPath))
                        .ToImmutableArray();
                var analyzerOptions = new AnalyzerOptions(additionalFiles, project.AnalyzerOptions.AnalyzerConfigOptionsProvider);
                var result = await compilation.WithAnalyzers(analyzers, analyzerOptions).GetAllDiagnosticsAsync();
                compilerErrors |= result.Any(diagnostic => diagnostic.Severity == DiagnosticSeverity.Error &&
                                                           !diagnostic.Id.StartsWith("DNA", StringComparison.Ordinal));
                compilerErrors |= result.Any(diagnostic => diagnostic.Id == "AD0001");
                diagnostics.AddRange(result.Where(diagnostic => diagnostic.Id.StartsWith("DNA", StringComparison.Ordinal)));
                foreach (var error in result.Where(diagnostic => diagnostic.Id == "AD0001"))
                    Console.Error.WriteLine(error);
            }

            foreach (var error in workspaceErrors.Distinct(StringComparer.Ordinal))
                Console.Error.WriteLine("Workspace: " + error);
            compilerErrors |= workspaceFailure;

            var root = Path.GetDirectoryName(target)!;
            var findings = diagnostics
                .GroupBy(diagnostic => new
                {
                    diagnostic.Id,
                    Path = diagnostic.Location.SourceTree?.FilePath,
                    diagnostic.Location.SourceSpan.Start,
                    Message = diagnostic.GetMessage()
                })
                .Select(group => group.First())
                .OrderBy(diagnostic => diagnostic.Location.SourceTree?.FilePath, StringComparer.OrdinalIgnoreCase)
                .ThenBy(diagnostic => diagnostic.Location.SourceSpan.Start)
                .ThenBy(diagnostic => diagnostic.Id, StringComparer.Ordinal)
                .ToArray();

            foreach (var diagnostic in findings)
            {
                var line = diagnostic.Location.GetLineSpan();
                var path = line.Path;
                if (!string.IsNullOrEmpty(path))
                    path = Path.GetRelativePath(root, path);
                var cwe = options.ShowCwe && DnaRuleCatalog.TryGetCwe(diagnostic.Id, out var id)
                    ? $" [CWE-{id}]" : string.Empty;
                Console.WriteLine($"{path}({line.StartLinePosition.Line + 1},{line.StartLinePosition.Character + 1}): {diagnostic.Id}{cwe}: {diagnostic.GetMessage()}");
            }

            if (options.SarifPath != null)
                await SarifWriter.WriteAsync(options.SarifPath, target, findings, options.AbsolutePaths);

            Console.WriteLine($"{findings.Length} security finding(s).");
            if (compilerErrors) return 2;
            return options.FailOnFindings && findings.Length > 0 ? 1 : 0;
        }
        catch (System.Text.Json.JsonException error)
        {
            Console.Error.WriteLine("Invalid Dotnetarium.json: " + error.Message);
            return 2;
        }
        catch (Exception error)
        {
            Console.Error.WriteLine(error);
            return 2;
        }
    }

    private static void PrintUsage() => Console.WriteLine(
        "Usage: dotnetarium-scs <solution.sln|project.csproj> [options]\n" +
        "  -x, --sarif <path>          Write SARIF 2.1.0\n" +
        "  -c, --config <path>         Load Dotnetarium.json (version 2.0)\n" +
        "  --sdk-path <path>          Use a specific .NET SDK MSBuild directory\n" +
        "  --sarif-absolute-paths     Keep absolute source paths in SARIF\n" +
        "  --cwe                      Show CWE groups in console output\n" +
        "  -f, --fail-any-warn        Return 1 when findings are present\n" +
        "  -h, --help                 Show this help");

    private sealed class FileAdditionalText(string path) : AdditionalText
    {
        private readonly string sourcePath = System.IO.Path.GetFullPath(path);
        public override string Path { get; } = System.IO.Path.Combine(
            System.IO.Path.GetDirectoryName(System.IO.Path.GetFullPath(path))!, "Dotnetarium.json");
        public override SourceText GetText(CancellationToken cancellationToken = default) =>
            SourceText.From(File.ReadAllText(sourcePath));
    }

    private sealed record Options(string Target, string? SarifPath, string? ConfigPath,
        string? SdkPath, bool AbsolutePaths, bool FailOnFindings, bool ShowCwe)
    {
        internal static Options Parse(string[] args)
        {
            string? target = null, sarif = null, config = null, sdk = null;
            bool absolute = false, fail = false, cwe = false;
            for (int index = 0; index < args.Length; index++)
            {
                var arg = args[index];
                string NextValue() => ++index < args.Length
                    ? args[index] : throw new ArgumentException($"Missing value after {arg}.");
                switch (arg)
                {
                    case "scan": break;
                    case "-x": case "--sarif": case "--export": sarif = NextValue(); break;
                    case "-c": case "--config": config = NextValue(); break;
                    case "--sdk-path": sdk = NextValue(); break;
                    case "--sarif-absolute-paths": absolute = true; break;
                    case "-f": case "--fail-any-warn": fail = true; break;
                    case "--cwe": cwe = true; break;
                    default:
                        if (arg.StartsWith("-", StringComparison.Ordinal))
                            throw new ArgumentException($"Unknown option {arg}.");
                        if (target != null)
                            throw new ArgumentException("Specify one project or solution.");
                        target = arg;
                        break;
                }
            }
            if (target == null) throw new ArgumentException("A project or solution path is required.");
            if (config != null && !File.Exists(config)) throw new ArgumentException($"Configuration not found: {config}");
            return new Options(target, sarif, config, sdk, absolute, fail, cwe);
        }
    }
}
