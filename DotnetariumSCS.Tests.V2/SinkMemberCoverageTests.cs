using Dotnetarium.Config;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Diagnostics;

namespace DotnetariumSCS.Tests.V2;

public sealed partial class SinkCoverageTests
{
    private sealed record MemberProbe(string Type, string Rule, string Kind, string Member, string Statement);

    private static readonly MemberProbe[] MemberProbes = CreateMemberProbes().ToArray();

    [Fact]
    public void Every_built_in_sink_member_has_a_compiled_witness()
    {
        var expected = new ConfigurationReader().GetBuiltinConfiguration().Sinks
            .SelectMany(sink => (sink.Methods ?? []).Select(method =>
                (sink.Type, Rule: RuleFor(sink.TaintTypes.Single()), Kind: "M", Member: method.Name))
                .Concat((sink.Properties ?? []).Select(property =>
                    (sink.Type, Rule: RuleFor(sink.TaintTypes.Single()), Kind: "P", Member: property)))
                .Concat(sink.IsAnyStringParameterInConstructorASink == true
                    ? [(sink.Type, Rule: RuleFor(sink.TaintTypes.Single()), Kind: "C", Member: ".ctor")]
                    : Array.Empty<(string Type, string Rule, string Kind, string Member)>()));
        var actual = MemberProbes.Select(probe => (probe.Type, probe.Rule, probe.Kind, probe.Member));
        Assert.Equal(expected.OrderBy(item => item.ToString(), StringComparer.Ordinal),
            actual.OrderBy(item => item.ToString(), StringComparer.Ordinal));
    }

    public static IEnumerable<object[]> MemberCases => MemberProbes.Select((_, index) => new object[] { index });

    private sealed record ExtraArgumentProbe(string Type, string Method, string Argument, string Statement);
    private static readonly ExtraArgumentProbe[] ExtraArgumentProbes =
    [
        new("System.Diagnostics.Process", "Start", "arguments", "_ = System.Diagnostics.Process.Start(\"fixed\", input);"),
        new("System.IO.Directory", "CreateSymbolicLink", "pathToTarget", "_ = System.IO.Directory.CreateSymbolicLink(\"fixed\", input);"),
        new("System.IO.Directory", "Move", "destDirName", "System.IO.Directory.Move(\"fixed\", input);"),
        new("System.IO.File", "Copy", "destFileName", "System.IO.File.Copy(\"fixed\", input);"),
        new("System.IO.File", "CreateSymbolicLink", "pathToTarget", "_ = System.IO.File.CreateSymbolicLink(\"fixed\", input);"),
        new("System.IO.File", "Move", "destFileName", "System.IO.File.Move(\"fixed\", input);"),
        new("System.IO.File", "Replace", "destinationFileName", "System.IO.File.Replace(\"fixed\", input, \"backup\");"),
        new("System.IO.File", "Replace", "destinationBackupFileName", "System.IO.File.Replace(\"fixed\", \"destination\", input);"),
        new("System.IO.FileInfo", "Replace", "destinationBackupFileName", "_ = new System.IO.FileInfo(\"fixed\").Replace(\"destination\", input);")
    ];

    [Fact]
    public void Every_additional_sink_argument_has_a_compiled_witness()
    {
        var expected = new ConfigurationReader().GetBuiltinConfiguration().Sinks
            .SelectMany(sink => (sink.Methods ?? []).SelectMany(method =>
                (method.Arguments ?? []).Skip(1).Select(argument => (sink.Type, Method: method.Name, Argument: argument))));
        var actual = ExtraArgumentProbes.Select(probe => (probe.Type, probe.Method, probe.Argument));
        Assert.Equal(expected.OrderBy(item => item.ToString(), StringComparer.Ordinal),
            actual.OrderBy(item => item.ToString(), StringComparer.Ordinal));
    }

    public static IEnumerable<object[]> ExtraArgumentCases =>
        ExtraArgumentProbes.Select((_, index) => new object[] { index });

    [Theory]
    [MemberData(nameof(ExtraArgumentCases))]
    public async Task Additional_sink_argument_is_reached(int index)
    {
        var probe = ExtraArgumentProbes[index];
        var rule = RuleFor(new ConfigurationReader().GetBuiltinConfiguration().Sinks
            .Single(sink => sink.Type == probe.Type).TaintTypes.Single());
        await AssertWitness(probe.Type + "." + probe.Method + "(" + probe.Argument + ")", probe.Statement, rule);
    }

    [Theory]
    [MemberData(nameof(MemberCases))]
    public async Task Built_in_sink_member_is_reached_by_its_rule(int index)
    {
        var probe = MemberProbes[index];
        await AssertWitness(probe.Type + "." + probe.Member, probe.Statement, probe.Rule);
    }

    private static async Task AssertWitness(string name, string statement, string rule)
    {
        var tree = CSharpSyntaxTree.ParseText(SourceFor(statement),
            new CSharpParseOptions(LanguageVersion.Preview), "SinkMemberProbe.cs");
        var compilation = CSharpCompilation.Create("SinkMemberProbe", [tree], References,
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));
        Assert.True(!compilation.GetDiagnostics().Any(d => d.Severity == DiagnosticSeverity.Error),
            $"{name}: {string.Join("; ", compilation.GetDiagnostics().Where(d => d.Severity == DiagnosticSeverity.Error))}");
        var diagnostics = await compilation.WithAnalyzers([AnalyzerFor(rule)]).GetAnalyzerDiagnosticsAsync();
        Assert.True(diagnostics.Any(diagnostic => diagnostic.Id == rule),
            $"{name} did not report {rule}: {string.Join("; ", diagnostics.Select(d => d.ToString()))}");
    }

    private static IEnumerable<MemberProbe> CreateMemberProbes()
    {
        static MemberProbe M(string type, string rule, string member, string statement) =>
            new(type, rule, "M", member, statement);
        static MemberProbe P(string type, string rule, string member, string statement) =>
            new(type, rule, "P", member, statement);

        yield return M("System.Net.NetworkCredential", "DNA0009", ".ctor", "_ = new System.Net.NetworkCredential(\"user\", \"secret\");");
        yield return P("System.UriBuilder", "DNA0009", "Password", "new System.UriBuilder().Password = \"secret\";");
        foreach (var member in new[] { "IV", "Key" })
            yield return P("System.Security.Cryptography.SymmetricAlgorithm", "DNA0009", member,
                $"System.Security.Cryptography.Aes.Create().{member} = new byte[] {{ 1, 2, 3 }};");

        yield return M("System.Diagnostics.Process", "DNA0002", "Start", "_ = System.Diagnostics.Process.Start(input);");
        yield return new MemberProbe("System.Diagnostics.ProcessStartInfo", "DNA0002", "C", ".ctor", "_ = new System.Diagnostics.ProcessStartInfo(input);");
        foreach (var member in new[] { "Arguments", "FileName" })
            yield return P("System.Diagnostics.ProcessStartInfo", "DNA0002", member,
                $"new System.Diagnostics.ProcessStartInfo().{member} = input;");
        yield return M("System.DirectoryServices.DirectorySearcher", "DNA0006", ".ctor", "_ = new System.DirectoryServices.DirectorySearcher(input);");
        yield return P("System.DirectoryServices.DirectorySearcher", "DNA0006", "Filter", "new System.DirectoryServices.DirectorySearcher(\"fixed\").Filter = input;");
        yield return M("System.DirectoryServices.DirectoryEntry", "DNA0006", ".ctor", "_ = new System.DirectoryServices.DirectoryEntry(input);");
        yield return P("System.DirectoryServices.DirectoryEntry", "DNA0006", "Path", "new System.DirectoryServices.DirectoryEntry(\"fixed\").Path = input;");

        yield return M("Microsoft.AspNetCore.Http.HttpResponse", "DNA0005", "Redirect", "new Microsoft.AspNetCore.Http.DefaultHttpContext().Response.Redirect(input);");
        foreach (var member in new[] { "Redirect", "RedirectPermanent", "RedirectPreserveMethod", "RedirectPermanentPreserveMethod" })
        {
            yield return M("Microsoft.AspNetCore.Mvc.ControllerBase", "DNA0005", member, $"_ = {member}(input);");
            yield return M("Microsoft.AspNetCore.Mvc.RazorPages.PageModel", "DNA0005", member, $"_ = new TestPage().Do{member}(input);");
        }
        yield return M("Microsoft.AspNetCore.Mvc.RedirectResult", "DNA0005", ".ctor", "_ = new Microsoft.AspNetCore.Mvc.RedirectResult(input);");
        yield return P("Microsoft.AspNetCore.Mvc.RedirectResult", "DNA0005", "Url", "new Microsoft.AspNetCore.Mvc.RedirectResult(\"fixed\").Url = input;");

        var directory = "System.IO.Directory";
        foreach (var member in new[] { "CreateDirectory", "Delete", "EnumerateDirectories", "EnumerateFiles", "EnumerateFileSystemEntries", "GetDirectories", "GetFiles", "GetFileSystemEntries" })
            yield return M(directory, "DNA0004", member, $"{(member == "Delete" ? "" : "_ = ")}{directory}.{member}(input);");
        yield return M(directory, "DNA0004", "CreateSymbolicLink", "_ = System.IO.Directory.CreateSymbolicLink(input, \"fixed\");");
        yield return M(directory, "DNA0004", "Move", "System.IO.Directory.Move(input, \"fixed\");");

        var file = "System.IO.File";
        foreach (var member in new[] { "AppendText", "Create", "CreateText", "Delete", "OpenRead", "OpenText", "OpenWrite", "ReadAllBytes", "ReadAllBytesAsync", "ReadAllLines", "ReadAllLinesAsync", "ReadAllText", "ReadAllTextAsync", "ReadLines" })
            yield return M(file, "DNA0004", member, $"{(member == "Delete" ? "" : "_ = ")}{file}.{member}(input);");
        foreach (var member in new[] { "AppendAllLines", "AppendAllLinesAsync", "WriteAllLines", "WriteAllLinesAsync" })
            yield return M(file, "DNA0004", member, $"{(member.EndsWith("Async", StringComparison.Ordinal) ? "_ = " : "")}{file}.{member}(input, new[] {{ \"line\" }});");
        foreach (var member in new[] { "AppendAllText", "AppendAllTextAsync", "WriteAllText", "WriteAllTextAsync" })
            yield return M(file, "DNA0004", member, $"{(member.EndsWith("Async", StringComparison.Ordinal) ? "_ = " : "")}{file}.{member}(input, \"line\");");
        foreach (var member in new[] { "WriteAllBytes", "WriteAllBytesAsync" })
            yield return M(file, "DNA0004", member, $"{(member.EndsWith("Async", StringComparison.Ordinal) ? "_ = " : "")}{file}.{member}(input, new byte[] {{ 1 }});");
        yield return M(file, "DNA0004", "Copy", "System.IO.File.Copy(input, \"fixed\");");
        yield return M(file, "DNA0004", "CreateSymbolicLink", "_ = System.IO.File.CreateSymbolicLink(input, \"fixed\");");
        yield return M(file, "DNA0004", "Move", "System.IO.File.Move(input, \"fixed\");");
        yield return M(file, "DNA0004", "Open", "_ = System.IO.File.Open(input, System.IO.FileMode.OpenOrCreate);");
        yield return M(file, "DNA0004", "OpenHandle", "_ = System.IO.File.OpenHandle(input);");
        yield return M(file, "DNA0004", "Replace", "System.IO.File.Replace(input, \"fixed\", \"backup\");");

        yield return M("System.IO.FileInfo", "DNA0004", ".ctor", "_ = new System.IO.FileInfo(input);");
        foreach (var member in new[] { "CopyTo", "MoveTo" })
            yield return M("System.IO.FileInfo", "DNA0004", member, $"{(member == "MoveTo" ? "" : "_ = ")}new System.IO.FileInfo(\"fixed\").{member}(input);");
        yield return M("System.IO.FileInfo", "DNA0004", "Replace", "_ = new System.IO.FileInfo(\"fixed\").Replace(input, \"backup\");");
        foreach (var member in new[] { "LoadFile", "LoadFrom", "UnsafeLoadFrom" })
            yield return M("System.Reflection.Assembly", "DNA0004", member, $"_ = System.Reflection.Assembly.{member}(input);");
        yield return M("System.Xml.XmlReader", "DNA0004", "Create", "_ = System.Xml.XmlReader.Create(input);");
        yield return M("System.IO.StreamReader", "DNA0004", ".ctor", "_ = new System.IO.StreamReader(input);");
        yield return M("System.IO.StreamWriter", "DNA0004", ".ctor", "_ = new System.IO.StreamWriter(input);");
        yield return M("System.IO.FileStream", "DNA0004", ".ctor", "_ = new System.IO.FileStream(input, System.IO.FileMode.OpenOrCreate);");
        yield return M("Microsoft.AspNetCore.Mvc.PhysicalFileResult", "DNA0004", ".ctor", "_ = new Microsoft.AspNetCore.Mvc.PhysicalFileResult(input, \"text/plain\");");
        yield return P("Microsoft.AspNetCore.Mvc.PhysicalFileResult", "DNA0004", "FileName", "new Microsoft.AspNetCore.Mvc.PhysicalFileResult(\"fixed\", \"text/plain\").FileName = input;");
        yield return M("Microsoft.AspNetCore.Mvc.RazorPages.PageModel", "DNA0004", "PhysicalFile", "_ = new TestPage().PhysicalFile(input, \"text/plain\");");

        const string archive = "var zip = new System.IO.Compression.ZipArchive(new System.IO.MemoryStream(), System.IO.Compression.ZipArchiveMode.Create); ";
        yield return M("System.IO.Compression.ZipFileExtensions", "DNA0004", "CreateEntryFromFile", archive + "_ = System.IO.Compression.ZipFileExtensions.CreateEntryFromFile(zip, input, \"entry\");");
        yield return M("System.IO.Compression.ZipFileExtensions", "DNA0004", "ExtractToFile", archive + "System.IO.Compression.ZipFileExtensions.ExtractToFile(zip.CreateEntry(\"entry\"), input);");
        yield return M("System.IO.Compression.ZipFileExtensions", "DNA0004", "ExtractToDirectory", archive + "System.IO.Compression.ZipFileExtensions.ExtractToDirectory(zip, input);");

        yield return M("Microsoft.AspNetCore.Html.HtmlString", "DNA0003", ".ctor", "_ = new Microsoft.AspNetCore.Html.HtmlString(input);");
        yield return M("Microsoft.AspNetCore.Html.IHtmlContentBuilder", "DNA0003", "AppendHtml", "_ = ((Microsoft.AspNetCore.Html.IHtmlContentBuilder)new Microsoft.AspNetCore.Html.HtmlContentBuilder()).AppendHtml(input);");
        yield return M("Microsoft.AspNetCore.Components.Rendering.RenderTreeBuilder", "DNA0003", "AddContent", "new Microsoft.AspNetCore.Components.Rendering.RenderTreeBuilder().AddContent(0, new Microsoft.AspNetCore.Html.HtmlString(input));");
        yield return M("Microsoft.AspNetCore.Components.Rendering.RenderTreeBuilder", "DNA0003", "AddMarkupContent", "new Microsoft.AspNetCore.Components.Rendering.RenderTreeBuilder().AddMarkupContent(0, input);");
        yield return M("Microsoft.AspNetCore.Mvc.Rendering.IHtmlHelper", "DNA0003", "Raw", "_ = ((Microsoft.AspNetCore.Mvc.Rendering.IHtmlHelper)null!).Raw(input);");

        foreach (var member in new[] { "SelectNodes", "SelectSingleNode" })
            yield return M("System.Xml.XmlNode", "DNA0007", member, $"_ = new System.Xml.XmlDocument().{member}(input);");
        foreach (var member in new[] { "Compile", "Evaluate", "Matches", "Select", "SelectSingleNode" })
            yield return M("System.Xml.XPath.XPathNavigator", "DNA0007", member, $"_ = new System.Xml.XmlDocument().CreateNavigator()!.{member}(input);");
        yield return M("System.Xml.XPath.XPathExpression", "DNA0007", "Compile", "_ = System.Xml.XPath.XPathExpression.Compile(input);");
        foreach (var member in new[] { "XPathSelectElement", "XPathSelectElements", "XPathEvaluate" })
            yield return M("System.Xml.XPath.Extensions", "DNA0007", member, $"_ = System.Xml.XPath.Extensions.{member}(new System.Xml.Linq.XDocument(), input);");
        yield return P("System.Xml.Schema.XmlSchemaXPath", "DNA0007", "XPath", "new System.Xml.Schema.XmlSchemaXPath().XPath = input;");

        yield return P("System.Data.IDbCommand", "DNA0001", "CommandText", "((System.Data.IDbCommand)null!).CommandText = input;");
        foreach (var member in new[] { "ExecuteDataRow", "ExecuteDataRowAsync", "ExecuteDataset", "ExecuteDatasetAsync", "ExecuteNonQuery", "ExecuteNonQueryAsync", "ExecuteReader", "ExecuteReaderAsync", "ExecuteScalar", "ExecuteScalarAsync", "UpdateDataSet", "UpdateDataSetAsync" })
            yield return M("MySql.Data.MySqlClient.MySqlHelper", "DNA0001", member, $"_ = MySql.Data.MySqlClient.MySqlHelper.{member}(\"connection\", input);");
        yield return M("System.Data.SQLite.SQLiteCommand", "DNA0001", "Execute", "_ = System.Data.SQLite.SQLiteCommand.Execute(input);");
        foreach (var member in new[] { "SqlQueryRaw", "ExecuteSqlCommand", "ExecuteSqlCommandAsync", "ExecuteSqlRaw", "ExecuteSqlRawAsync" })
            yield return M("Microsoft.EntityFrameworkCore.RelationalDatabaseFacadeExtensions", "DNA0001", member, $"_ = Microsoft.EntityFrameworkCore.RelationalDatabaseFacadeExtensions.{member}(null!, input);");
        foreach (var member in new[] { "FromSqlRaw", "FromSql" })
            yield return M("Microsoft.EntityFrameworkCore.RelationalQueryableExtensions", "DNA0001", member, $"_ = Microsoft.EntityFrameworkCore.RelationalQueryableExtensions.{member}(null!, input);");

        foreach (var member in new[] { "GetAsync", "GetStringAsync", "GetStreamAsync", "GetByteArrayAsync", "DeleteAsync" })
            yield return M("System.Net.Http.HttpClient", "DNA0011", member, $"_ = new System.Net.Http.HttpClient().{member}(input);");
        foreach (var member in new[] { "PostAsync", "PutAsync", "PatchAsync" })
            yield return M("System.Net.Http.HttpClient", "DNA0011", member, $"_ = new System.Net.Http.HttpClient().{member}(input, new System.Net.Http.StringContent(\"body\"));");
        yield return M("System.Net.Http.HttpRequestMessage", "DNA0011", ".ctor", "_ = new System.Net.Http.HttpRequestMessage(System.Net.Http.HttpMethod.Get, input);");
        foreach (var member in new[] { "EvaluateAsync", "RunAsync" })
            yield return M("Microsoft.CodeAnalysis.CSharp.Scripting.CSharpScript", "DNA0012", member, $"_ = Microsoft.CodeAnalysis.CSharp.Scripting.CSharpScript.{member}(input);");
    }
}
