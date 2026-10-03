using Dotnetarium.Analyzers.Transport;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Diagnostics;

namespace Dotnetarium.Analyzers.Tests;

public sealed class CertificateValidationTests
{
    [Theory]
    [InlineData("new HttpClientHandler { ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator };", 1)]
    [InlineData("new HttpClientHandler { ServerCertificateCustomValidationCallback = (_, _, _, _) => true };", 1)]
    [InlineData("new HttpClientHandler { ServerCertificateCustomValidationCallback = delegate { return true; } };", 1)]
    [InlineData("new HttpClientHandler { ServerCertificateCustomValidationCallback = HttpAccept };", 1)]
    [InlineData("new HttpClientHandler { ServerCertificateCustomValidationCallback = (_, _, _, errors) => { if (errors == SslPolicyErrors.None) return true; return true; } };", 1)]
    [InlineData("var handler = new HttpClientHandler(); handler.ServerCertificateCustomValidationCallback = (_, _, _, _) => true;", 1)]
    [InlineData("var handler = new HttpClientHandler(); var callback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator; handler.ServerCertificateCustomValidationCallback = callback;", 1)]
    [InlineData("Func<HttpRequestMessage, X509Certificate2, X509Chain, SslPolicyErrors, bool> callback = (_, _, _, _) => true; new HttpClientHandler { ServerCertificateCustomValidationCallback = callback };", 1)]
    [InlineData("var socket = new ClientWebSocket(); socket.Options.RemoteCertificateValidationCallback = (_, _, _, _) => true;", 1)]
    [InlineData("new SslClientAuthenticationOptions { RemoteCertificateValidationCallback = (_, _, _, _) => true };", 1)]
    [InlineData("new SslServerAuthenticationOptions { ClientCertificateRequired = true, RemoteCertificateValidationCallback = (_, _, _, _) => true };", 1)]
    [InlineData("new SocketsHttpHandler { SslOptions = new SslClientAuthenticationOptions { RemoteCertificateValidationCallback = (_, _, _, _) => true } };", 1)]
    [InlineData("new SslStream(new MemoryStream(), false, (_, _, _, _) => true);", 1)]
    [InlineData("new SslStream(new MemoryStream(), false, RemoteAccept, null);", 1)]
    [InlineData("new SslStream(new MemoryStream(), false, RemoteAccept, null, EncryptionPolicy.RequireEncryption);", 1)]
    [InlineData("ServicePointManager.ServerCertificateValidationCallback = (_, _, _, _) => true;", 1)]
    [InlineData("bool LocalAccept(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors) => true; new SslStream(new MemoryStream(), false, LocalAccept);", 1)]
    [InlineData("new HttpClientHandler { ServerCertificateCustomValidationCallback = (_, _, _, errors) => errors == SslPolicyErrors.None };", 0)]
    [InlineData("new HttpClientHandler { ServerCertificateCustomValidationCallback = (_, certificate, _, _) => certificate != null && certificate.Thumbprint == expected };", 0)]
    [InlineData("new HttpClientHandler { ServerCertificateCustomValidationCallback = (_, _, _, _) => false };", 0)]
    [InlineData("new HttpClientHandler { ServerCertificateCustomValidationCallback = null };", 0)]
    [InlineData("new HttpClientHandler(); new SslStream(new MemoryStream());", 0)]
    [InlineData("var callback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator; Console.WriteLine(callback != null);", 0)]
    [InlineData("new HttpClientHandler { ServerCertificateCustomValidationCallback = (_, _, _, errors) => { if (errors != SslPolicyErrors.None) throw new AuthenticationException(); return true; } };", 0)]
    [InlineData("new HttpClientHandler { ServerCertificateCustomValidationCallback = (_, cert, chain, errors) => { ValidateOrThrow(cert, chain, errors); return true; } };", 0)]
    [InlineData("new HttpClientHandler { ServerCertificateCustomValidationCallback = (_, _, _, errors) => { if (errors != SslPolicyErrors.None) return false; return true; } };", 0)]
    [InlineData("new SslClientAuthenticationOptions { RemoteCertificateValidationCallback = (_, _, _, errors) => errors == SslPolicyErrors.None };", 0)]
    [InlineData("new SslStream(new MemoryStream(), false, RemoteValidate);", 0)]
    [InlineData("var callback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator; callback = (_, _, _, errors) => errors == SslPolicyErrors.None; new HttpClientHandler { ServerCertificateCustomValidationCallback = callback };", 0)]
    [InlineData("var callback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator; Change(ref callback); new HttpClientHandler { ServerCertificateCustomValidationCallback = callback };", 0)]
    [InlineData("new Lookalike { ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator };", 0)]
    [InlineData("new SslStream(new MemoryStream(), false, validator.Accept);", 0)]
    [InlineData("if (environment.IsDevelopment()) new HttpClientHandler { ServerCertificateCustomValidationCallback = (_, _, _, _) => true };", 0)]
    [InlineData("if (!environment.IsDevelopment()) new HttpClientHandler(); else new HttpClientHandler { ServerCertificateCustomValidationCallback = (_, _, _, _) => true };", 0)]
    [InlineData("if (environment.IsDevelopment() && enabled) new SslStream(new MemoryStream(), false, RemoteAccept);", 0)]
    [InlineData("if (!environment.IsDevelopment()) new SslStream(new MemoryStream(), false, RemoteAccept);", 1)]
    [InlineData("if (environment.IsDevelopment() || enabled) new SslStream(new MemoryStream(), false, RemoteAccept);", 1)]
    [InlineData("if (!environment.IsProduction()) new SslStream(new MemoryStream(), false, RemoteAccept);", 0)]
    [InlineData("if (environment.IsProduction()) new SslStream(new MemoryStream(), false, RemoteAccept);", 1)]
    [InlineData("if (environment.IsProduction()) new HttpClientHandler(); else new SslStream(new MemoryStream(), false, RemoteAccept);", 0)]
    [InlineData("if (!environment.IsProduction() && enabled) new SslStream(new MemoryStream(), false, RemoteAccept);", 0)]
    [InlineData("if (!environment.IsProduction() || enabled) new SslStream(new MemoryStream(), false, RemoteAccept);", 1)]
    [InlineData("if (environment.IsEnvironment(\"Testing\")) new SslStream(new MemoryStream(), false, RemoteAccept);", 1)]
    [InlineData("if (environment.IsEnvironment(\"Development\")) new SslStream(new MemoryStream(), false, RemoteAccept);", 1)]
    [InlineData("if (environment.IsStaging()) new SslStream(new MemoryStream(), false, RemoteAccept);", 1)]
    [InlineData("if (IsProduction()) new SslStream(new MemoryStream(), false, RemoteAccept);", 1)]
    [InlineData("var development = environment.IsDevelopment(); if (development) new SslStream(new MemoryStream(), false, RemoteAccept);", 0)]
    [InlineData("var production = environment.IsProduction(); if (!production) new SslStream(new MemoryStream(), false, RemoteAccept);", 0)]
    [InlineData("var development = environment.IsDevelopment(); development = enabled; if (development) new SslStream(new MemoryStream(), false, RemoteAccept);", 1)]
    [InlineData("var development = environment.IsDevelopment(); ChangeBool(ref development); if (development) new SslStream(new MemoryStream(), false, RemoteAccept);", 1)]
    [InlineData("var development = environment.IsDevelopment(); Action change = () => development = enabled; if (development) new SslStream(new MemoryStream(), false, RemoteAccept);", 1)]
    [InlineData("if (!environment.IsDevelopment()) return; new SslStream(new MemoryStream(), false, RemoteAccept);", 0)]
    [InlineData("if (environment.IsProduction()) return; new SslStream(new MemoryStream(), false, RemoteAccept);", 0)]
    [InlineData("if (!environment.IsDevelopment()) { return; } new SslStream(new MemoryStream(), false, RemoteAccept);", 0)]
    [InlineData("if (environment.IsProduction()) throw new Exception(); new SslStream(new MemoryStream(), false, RemoteAccept);", 0)]
    [InlineData("if (environment.IsDevelopment()) return; new SslStream(new MemoryStream(), false, RemoteAccept);", 1)]
    [InlineData("if (!environment.IsDevelopment()) { if (enabled) return; } new SslStream(new MemoryStream(), false, RemoteAccept);", 1)]
    [InlineData("if (environment.IsProduction() && enabled) return; new SslStream(new MemoryStream(), false, RemoteAccept);", 1)]
    [InlineData("if (!environment.IsDevelopment()) return; Action deferred = () => { new SslStream(new MemoryStream(), false, RemoteAccept); };", 1)]
    [InlineData("if (enabled) goto configure; if (environment.IsProduction()) return; configure: new SslStream(new MemoryStream(), false, RemoteAccept);", 1)]
    [InlineData("if (enabled) new HttpClientHandler { ServerCertificateCustomValidationCallback = (_, _, _, _) => true };", 1)]
    [InlineData("if (IsDevelopment()) new HttpClientHandler { ServerCertificateCustomValidationCallback = (_, _, _, _) => true };", 1)]
    [InlineData("new HttpClientHandler { ServerCertificateCustomValidationCallback = (request, _, _, errors) => request.RequestUri.IsLoopback || errors == SslPolicyErrors.None };", 0)]
    [InlineData("new HttpClientHandler { ServerCertificateCustomValidationCallback = (request, _, _, errors) => environment.IsDevelopment() && request.RequestUri.IsLoopback || errors == SslPolicyErrors.None };", 0)]
    [InlineData("var client = new HttpClient(new HttpClientHandler { ServerCertificateCustomValidationCallback = (_, _, _, _) => true }); client.GetAsync(\"https://localhost\");", 1)]
    [InlineData("ServicePointManager.ServerCertificateValidationCallback += (_, _, _, _) => true;", 0)]
    [InlineData("ServicePointManager.ServerCertificateValidationCallback -= RemoteAccept;", 0)]
    [InlineData("ServicePointManager.ServerCertificateValidationCallback += RemoteValidate;", 0)]
    [InlineData("if (environment.IsDevelopment()) ServicePointManager.ServerCertificateValidationCallback += RemoteAccept;", 0)]
    [InlineData("#pragma warning disable DNA0020\nnew HttpClientHandler { ServerCertificateCustomValidationCallback = (_, _, _, _) => true };\n#pragma warning restore DNA0020\n", 0)]
    [InlineData("ServicePointManager.ServerCertificateValidationCallback = (_, _, _, errors) => { if (errors != SslPolicyErrors.None) throw new AuthenticationException(); return true; }; ServicePointManager.ServerCertificateValidationCallback += RemoteAccept;", 0)]
    public Task Known_bypass_configuration_is_reported_and_validation_is_preserved(string statement, int expected) =>
        AssertDiagnostics(statement, expected);

    [Theory]
    [InlineData("#if DEBUG\nnew SslStream(new MemoryStream(), false, RemoteAccept);\n#endif", 0)]
    [InlineData("#if !DEBUG\nnew HttpClientHandler();\n#else\nnew SslStream(new MemoryStream(), false, RemoteAccept);\n#endif", 0)]
    [InlineData("#if DEBUG && TRACE\nnew SslStream(new MemoryStream(), false, RemoteAccept);\n#endif", 0)]
    [InlineData("#if DEBUG || TRACE\nnew SslStream(new MemoryStream(), false, RemoteAccept);\n#endif", 1)]
    [InlineData("#if TRACE\nnew SslStream(new MemoryStream(), false, RemoteAccept);\n#endif", 1)]
    [InlineData("new SslStream(new MemoryStream(), false, RemoteAccept);", 1)]
    [InlineData("#if DEBUG\nnew SslStream(new MemoryStream(), false, RemoteAccept);\n#endif\nnew SslStream(new MemoryStream(), false, RemoteAccept);", 1)]
    [InlineData("#if DEBUG\nnew HttpClientHandler { ServerCertificateCustomValidationCallback = (_, _, _, _) => true };\n#endif", 0)]
    [InlineData("#if DEBUG\nif (enabled) {\n#if TRACE\nnew SslStream(new MemoryStream(), false, RemoteAccept);\n#endif\n}\n#endif", 0)]
    public Task Debug_only_configuration_is_exempt_but_shared_code_is_not(string statement, int expected) =>
        AssertDiagnostics(statement, expected, ["DEBUG", "TRACE"]);

    [Fact]
    public Task Source_defined_debug_symbol_is_not_a_release_exclusion() =>
        AssertDiagnostics("#if DEBUG\nnew SslStream(new MemoryStream(), false, RemoteAccept);\n#endif", 1,
            ["DEBUG"], sourcePrefix: "#define DEBUG\n");

    [Theory]
    [InlineData("true", "", 0)]
    [InlineData("TRUE", "false", 0)]
    [InlineData("true", "true", 1)]
    [InlineData("false", "false", 1)]
    [InlineData("", "", 1)]
    [InlineData("unknown", "false", 1)]
    public Task Test_project_metadata_and_opt_in_control_only_this_rule(string isTestProject, string includeTests, int expected) =>
        AssertDiagnostics("new SslStream(new MemoryStream(), false, RemoteAccept);", expected, null,
            new Dictionary<string, string>
            {
                ["build_property.IsTestProject"] = isTestProject,
                ["dotnetarium_analyze_test_certificates"] = includeTests
            });

    private static async Task AssertDiagnostics(string statement, int expected, string[]? symbols = null,
        Dictionary<string, string>? settings = null, string sourcePrefix = "")
    {
        var source = """
            using System;
            using System.IO;
            using System.Net;
            using System.Net.Http;
            using System.Net.Security;
            using System.Net.WebSockets;
            using System.Security.Authentication;
            using Microsoft.Extensions.Hosting;
            using System.Security.Cryptography.X509Certificates;
            public sealed class Lookalike
            {
                public Func<HttpRequestMessage, X509Certificate2, X509Chain, SslPolicyErrors, bool> ServerCertificateCustomValidationCallback { get; set; }
            }
            public class Validator
            {
                public virtual bool Accept(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors) => true;
            }
            public static class Demo
            {
                public static void Run(string expected, Validator validator, IHostEnvironment environment, bool enabled)
                {
            """ + "\n" + statement + "\n" + """
                }
                private static bool IsDevelopment() => true;
                private static bool IsProduction() => true;
                private static void ChangeBool(ref bool value) { value = true; }
                private static bool HttpAccept(HttpRequestMessage request, X509Certificate2 certificate, X509Chain chain, SslPolicyErrors errors) => true;
                private static bool RemoteAccept(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors) { return true; }
                private static bool RemoteValidate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors) => errors == SslPolicyErrors.None;
                private static void ValidateOrThrow(X509Certificate certificate, X509Chain chain, SslPolicyErrors errors)
                { if (errors != SslPolicyErrors.None) throw new AuthenticationException(); }
                private static void Change(ref Func<HttpRequestMessage, X509Certificate2, X509Chain, SslPolicyErrors, bool> callback)
                { callback = (_, _, _, errors) => errors == SslPolicyErrors.None; }
            }
            """;
        var references = ((string)AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES")!).Split(Path.PathSeparator)
            .Select(path => MetadataReference.CreateFromFile(path));
        var compilation = CSharpCompilation.Create("TlsProbe",
            [CSharpSyntaxTree.ParseText(sourcePrefix + source, new CSharpParseOptions(LanguageVersion.Preview, preprocessorSymbols: symbols), "Tls.cs")], references,
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));
        Assert.Empty(compilation.GetDiagnostics().Where(diagnostic => diagnostic.Severity == DiagnosticSeverity.Error));
        var options = new AnalyzerOptions([], new TestOptionsProvider(settings ?? []));
        var diagnostics = await compilation.WithAnalyzers([new CertificateValidationAnalyzer()], options).GetAnalyzerDiagnosticsAsync();
        Assert.DoesNotContain(diagnostics, diagnostic => diagnostic.Id == "AD0001");
        Assert.Equal(expected, diagnostics.Count(diagnostic => diagnostic.Id == "DNA0020"));
        Assert.All(diagnostics, diagnostic => Assert.Equal("Tls.cs", diagnostic.Location.SourceTree!.FilePath));
    }

    private sealed class TestOptionsProvider(Dictionary<string, string> settings) : AnalyzerConfigOptionsProvider
    {
        public override AnalyzerConfigOptions GlobalOptions { get; } = new TestOptions(settings);
        public override AnalyzerConfigOptions GetOptions(SyntaxTree tree) => new TestOptions([]);
        public override AnalyzerConfigOptions GetOptions(AdditionalText textFile) => new TestOptions([]);
    }

    private sealed class TestOptions(Dictionary<string, string> settings) : AnalyzerConfigOptions
    {
        public override bool TryGetValue(string key, out string value) => settings.TryGetValue(key, out value!);
    }
}
