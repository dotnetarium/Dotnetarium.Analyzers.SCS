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

            var target = Path.GetFullPath(options.Target);
            if (!File.Exists(target))
                throw new FileNotFoundException("Project or solution was not found.", target);
            var root = Path.GetDirectoryName(target)!;
            var defaultConfig = Path.Combine(root, "dotnetarium.json");
            var sdkQuery = VisualStudioInstanceQueryOptions.Default;
            sdkQuery.WorkingDirectory = root;
            var sdk = MSBuildLocator.QueryVisualStudioInstances(sdkQuery).FirstOrDefault() ??
                throw new InvalidOperationException("No compatible .NET SDK was found.");
            MSBuildLocator.RegisterInstance(sdk);

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
                        .Where(file => !IsConfigurationFile(file.Path))
                        .Append(new FileAdditionalText(options.ConfigPath))
                        .ToImmutableArray();
                else if (File.Exists(defaultConfig) && !additionalFiles.Any(file => IsConfigurationFile(file.Path)))
                    additionalFiles = additionalFiles.Add(new FileAdditionalText(defaultConfig));
                var analyzerOptions = new AnalyzerOptions(additionalFiles, project.AnalyzerOptions.AnalyzerConfigOptionsProvider);
                var result = await compilation.WithAnalyzers(analyzers, analyzerOptions).GetAllDiagnosticsAsync();
                var projectErrors = result.Where(diagnostic =>
                    diagnostic.Id == "AD0001" ||
                    (diagnostic.Severity == DiagnosticSeverity.Error &&
                     !diagnostic.Id.StartsWith("DNA", StringComparison.Ordinal))).ToArray();
                compilerErrors |= projectErrors.Length > 0;
                diagnostics.AddRange(result.Where(diagnostic => diagnostic.Id.StartsWith("DNA", StringComparison.Ordinal)));
                foreach (var error in projectErrors)
                    Console.Error.WriteLine($"{project.Name}: {error}");
            }

            foreach (var error in workspaceErrors.Distinct(StringComparer.Ordinal))
                Console.Error.WriteLine("Workspace: " + error);
            compilerErrors |= workspaceFailure;

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
                var cwe = DnaRuleCatalog.TryGetCwe(diagnostic.Id, out var id)
                    ? $" [CWE-{id}]" : string.Empty;
                Console.WriteLine($"{path}({line.StartLinePosition.Line + 1},{line.StartLinePosition.Character + 1}): {diagnostic.Id}{cwe}: {diagnostic.GetMessage()}");
            }

            Console.WriteLine($"{findings.Length} security finding(s){(compilerErrors ? " (partial scan)" : string.Empty)}.");
            if (compilerErrors)
            {
                Console.Error.WriteLine("Scan incomplete: project or workspace errors occurred.");
                return 2;
            }
            if (options.SarifPath != null)
                await SarifWriter.WriteAsync(options.SarifPath, target, findings);
            return options.Fail && findings.Length > 0 ? 1 : 0;
        }
        catch (System.Text.Json.JsonException error)
        {
            Console.Error.WriteLine("Invalid dotnetarium.json: " + error.Message);
            return 2;
        }
        catch (Exception error)
        {
            Console.Error.WriteLine(error);
            return 2;
        }
    }

    private static void PrintUsage() => Console.WriteLine(
        "Usage: dotnetarium <project.csproj|solution.sln|solution.slnx> [options]\n" +
        "  --sarif <path>             Write SARIF 2.1.0\n" +
        "  --config <path>            Override dotnetarium.json (version 2.0)\n" +
        "  --fail                     Return 1 when findings are present\n" +
        "  -h, --help                 Show this help");

    private sealed class FileAdditionalText(string path) : AdditionalText
    {
        private readonly string sourcePath = System.IO.Path.GetFullPath(path);
        public override string Path { get; } = System.IO.Path.Combine(
            System.IO.Path.GetDirectoryName(System.IO.Path.GetFullPath(path))!, "dotnetarium.json");
        public override SourceText GetText(CancellationToken cancellationToken = default) =>
            SourceText.From(File.ReadAllText(sourcePath));
    }

    private static bool IsConfigurationFile(string path) =>
        string.Equals(Path.GetFileName(path), "dotnetarium.json", StringComparison.OrdinalIgnoreCase);

    private sealed record Options(string Target, string? SarifPath, string? ConfigPath,
        bool Fail)
    {
        internal static Options Parse(string[] args)
        {
            string? target = null, sarif = null, config = null;
            bool fail = false;
            for (int index = 0; index < args.Length; index++)
            {
                var arg = args[index];
                string NextValue() => ++index < args.Length
                    ? args[index] : throw new ArgumentException($"Missing value after {arg}.");
                switch (arg)
                {
                    case "--sarif": sarif = NextValue(); break;
                    case "--config": config = NextValue(); break;
                    case "--fail": fail = true; break;
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
            return new Options(target, sarif, config, fail);
        }
    }
}
