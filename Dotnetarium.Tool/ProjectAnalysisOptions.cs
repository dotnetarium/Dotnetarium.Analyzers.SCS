using System.Diagnostics;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;

namespace Dotnetarium.Tool;

internal sealed class ProjectAnalysisOptions(AnalyzerConfigOptionsProvider original, string isTestProject) : AnalyzerConfigOptionsProvider
{
    // CLI targets need not reference our analyzer package, whose props normally
    // expose this property. Query evaluated MSBuild metadata, including imports;
    // project names and test-library dependencies are not evidence of a test project.
    internal static async Task<AnalyzerConfigOptionsProvider> WithTestProjectMetadataAsync(
        AnalyzerConfigOptionsProvider original, string projectPath, string msbuildPath)
    {
        var start = new ProcessStartInfo("dotnet")
        {
            WorkingDirectory = Path.GetDirectoryName(projectPath)!,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        foreach (var argument in new[] { "exec", Path.Combine(msbuildPath, "MSBuild.dll"), projectPath,
                     "-getProperty:IsTestProject", "-nologo", "-verbosity:quiet" }) start.ArgumentList.Add(argument);
        using var process = Process.Start(start) ?? throw new InvalidOperationException("Could not read project metadata.");
        var output = process.StandardOutput.ReadToEndAsync();
        var error = process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync();
        if (process.ExitCode != 0)
            throw new InvalidOperationException($"Could not read test-project metadata for {projectPath}: {await error}");
        return new ProjectAnalysisOptions(original, (await output).Trim());
    }

    public override AnalyzerConfigOptions GlobalOptions { get; } = new GlobalProjectOptions(original.GlobalOptions, isTestProject);
    public override AnalyzerConfigOptions GetOptions(SyntaxTree tree) => original.GetOptions(tree);
    public override AnalyzerConfigOptions GetOptions(AdditionalText textFile) => original.GetOptions(textFile);

    private sealed class GlobalProjectOptions(AnalyzerConfigOptions original, string isTestProject) : AnalyzerConfigOptions
    {
        public override bool TryGetValue(string key, out string value)
        {
            if (key.Equals("build_property.IsTestProject", StringComparison.OrdinalIgnoreCase))
            {
                value = isTestProject;
                return true;
            }
            return original.TryGetValue(key, out value!);
        }
    }
}
