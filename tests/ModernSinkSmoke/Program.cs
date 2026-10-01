using System;
using System.Collections.Immutable;
using System.IO;
using System.Linq;
using System.Reflection.PortableExecutable;
using System.Threading.Tasks;
using Dotnetarium.Analyzers.Taint;
using Microsoft.AspNetCore.Mvc;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Diagnostics;

var cases = new (string Name, string Statement, string Rule, bool ShouldWarn)[]
{
    ("directory enumeration", "System.IO.Directory.EnumerateFiles(path);", "DNA0004", true),
    ("directory enumeration of directories", "System.IO.Directory.EnumerateDirectories(path);", "DNA0004", true),
    ("directory enumeration of entries", "System.IO.Directory.EnumerateFileSystemEntries(path);", "DNA0004", true),
    ("directory listing of directories", "System.IO.Directory.GetDirectories(path);", "DNA0004", true),
    ("directory listing of entries", "System.IO.Directory.GetFileSystemEntries(path);", "DNA0004", true),
    ("directory creation", "System.IO.Directory.CreateDirectory(path);", "DNA0004", true),
    ("directory symlink target", "System.IO.Directory.CreateSymbolicLink(\"link\", path);", "DNA0004", true),
    ("file handle", "System.IO.File.OpenHandle(path);", "DNA0004", true),
    ("file symlink target", "System.IO.File.CreateSymbolicLink(\"link\", path);", "DNA0004", true),
    ("file symlink path", "System.IO.File.CreateSymbolicLink(path, \"target\");", "DNA0004", true),
    ("constant directory", "System.IO.Directory.EnumerateFiles(\"fixed\");", "DNA0004", false),
    ("constant file handle", "System.IO.File.OpenHandle(\"fixed\");", "DNA0004", false),
    ("lookalike method", "FakeFile.OpenHandle(path);", "DNA0004", false),
    ("EF Core scalar raw SQL", "context.Database.SqlQueryRaw<int>(path);", "DNA0001", true),
    ("EF Core constant raw SQL", "context.Database.SqlQueryRaw<int>(\"SELECT 1\");", "DNA0001", false),
    ("EF Core parameterized SQL", "context.Database.SqlQuery<int>($\"SELECT {path}\");", "DNA0001", false),
};

var references = ((string)AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES")!)
    .Split(Path.PathSeparator)
    .Concat(Directory.GetFiles(Path.GetDirectoryName(typeof(ControllerBase).Assembly.Location)!, "*.dll"))
    .Distinct(StringComparer.OrdinalIgnoreCase)
    .Where(path =>
    {
        using var reader = new PEReader(File.OpenRead(path));
        return reader.HasMetadata;
    })
    .Select(path => MetadataReference.CreateFromFile(path))
    .ToArray();

foreach (var test in cases)
{
    var source = $@"
using Microsoft.EntityFrameworkCore;
public class TestController : Microsoft.AspNetCore.Mvc.ControllerBase
{{
    public void Run(string path, DbContext context)
    {{
        {test.Statement}
    }}
}}
public static class FakeFile
{{
    public static void OpenHandle(string path) {{ }}
}}";
    var compilation = CSharpCompilation.Create(
        "ModernSinkSmoke",
        new[] { CSharpSyntaxTree.ParseText(source) },
        references,
        new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));
    var errors = compilation.GetDiagnostics().Where(d => d.Severity == DiagnosticSeverity.Error).ToArray();
    if (errors.Length != 0)
        throw new Exception($"{test.Name}: source did not compile: {string.Join("; ", errors.Select(d => d.ToString()))}");

    DiagnosticAnalyzer analyzer = test.Rule == "DNA0001" ? new SqlInjectionTaintAnalyzer() : new PathTraversalTaintAnalyzer();
    var diagnostics = await compilation.WithAnalyzers(
        ImmutableArray.Create(analyzer)).GetAnalyzerDiagnosticsAsync();
    var warned = diagnostics.Any(d => d.Id == test.Rule);
    if (warned != test.ShouldWarn)
        throw new Exception($"{test.Name}: expected warning={test.ShouldWarn}, got {string.Join("; ", diagnostics.Select(d => d.ToString()))}");
    Console.WriteLine($"PASS {test.Name}");
}
