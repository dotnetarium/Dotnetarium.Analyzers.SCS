using Dotnetarium.Analyzers.Taint;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Diagnostics;

namespace Dotnetarium.Analyzers.Tests;

public sealed class MinimalApiBindingTests
{
    [Theory]
    [InlineData("app.MapPost(\"/run\", (Input input) => Process.Start(input.Value));", 1)]
    [InlineData("app.MapPut(\"/run\", (Input input) => Process.Start(input.Value));", 1)]
    [InlineData("app.MapPatch(\"/run\", (Input input) => Process.Start(input.Value));", 1)]
    [InlineData("app.MapGet(\"/run\", (Input input) => Process.Start(input.Value));", 0)]
    [InlineData("app.MapPost(\"/run\", ([FromServices] Input input) => Process.Start(input.Value));", 0)]
    [InlineData("app.MapPost(\"/run\", ([FromKeyedServices(\"key\")] Input input) => Process.Start(input.Value));", 0)]
    [InlineData("app.MapGet(\"/run\", ([FromBody] Input input) => Process.Start(input.Value));", 1)]
    [InlineData("app.MapPost(\"/run\", Run);", 1)]
    [InlineData("app.MapPost(\"/run\", Run); app.MapGet(\"/other\", Run);", 0)]
    public async Task Body_binding_follows_endpoint_and_service_rules(string mapping, int expected)
    {
        await AssertFindings(mapping, "", expected);
    }

    [Theory]
    [InlineData("services.AddScoped<Input>();")]
    [InlineData("services.AddSingleton<Input>(_ => new Input());")]
    [InlineData("if (enabled) services.AddTransient<Input>();")]
    public async Task Visible_registrations_prevent_implicit_body_taint(string registration)
    {
        await AssertFindings("app.MapPost(\"/run\", (Input input) => Process.Start(input.Value));", registration, 0);
    }

    [Theory]
    [InlineData("app.MapPost(\"/upload\", (IFormFile file) => Process.Start(file.FileName));")]
    [InlineData("app.MapPost(\"/upload\", (IFormFileCollection files) => Process.Start(files[0].FileName));")]
    [InlineData("app.MapPost(\"/raw\", async (Stream body) => Process.Start(await new StreamReader(body).ReadToEndAsync()));")]
    [InlineData("app.MapGet(\"/values\", (string[] values) => Process.Start(values[0]));")]
    [InlineData("app.MapPost(\"/values\", (IList<Input> values) => Process.Start(values[0].Value));")]
    [InlineData("app.MapGet(\"/parsed\", (ParsedInput input) => Process.Start(input.Value));")]
    public async Task Special_request_inputs_reach_sinks(string mapping)
    {
        await AssertFindings(mapping, "", 1);
    }

    [Theory]
    [InlineData("app.MapPost(\"/cancel\", (System.Threading.CancellationToken token) => Process.Start(token.ToString()));")]
    [InlineData("app.MapPost(\"/user\", (System.Security.Claims.ClaimsPrincipal user) => Process.Start(user.Identity.Name));")]
    [InlineData("app.MapGet(\"/bound\", (BoundInput input) => Process.Start(input.Value));")]
    public async Task Framework_context_and_custom_binding_are_not_request_payloads(string mapping)
    {
        await AssertFindings(mapping, "", 0);
    }

    [Fact]
    public async Task A_custom_binder_is_not_assumed_to_return_request_data()
    {
        await AssertFindings("app.MapPost(\"/bound\", (BoundInput input) => Process.Start(input.Value));", "", 0);
    }

    private static async Task AssertFindings(string mapping, string registration, int expected)
    {
        var source = """
            using System.Collections.Generic;
            using System.Diagnostics;
            using System.IO;
            using Microsoft.AspNetCore.Builder;
            using Microsoft.AspNetCore.Http;
            using Microsoft.AspNetCore.Mvc;
            using Microsoft.Extensions.DependencyInjection;
            public sealed class Input { public string Value { get; set; } = ""; }
            public sealed class ParsedInput
            {
                public string Value { get; set; } = "";
                public static bool TryParse(string value, out ParsedInput result)
                { result = new ParsedInput { Value = value }; return true; }
            }
            public sealed class BoundInput
            {
                public string Value => "fixed";
                public static bool TryParse(string value, out BoundInput result)
                { result = new BoundInput(); return true; }
                public static System.Threading.Tasks.ValueTask<BoundInput> BindAsync(HttpContext context) => new(new BoundInput());
            }
            public static class Endpoints
            {
                public static void Configure(WebApplication app, IServiceCollection services, bool enabled)
                {
            """ + registration + mapping + """
                }
                public static object? Run(Input input) => Process.Start(input.Value);
            }
            """;
        var references = ((string)AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES")!).Split(Path.PathSeparator)
            .Select(path => MetadataReference.CreateFromFile(path));
        var tree = CSharpSyntaxTree.ParseText(source, new CSharpParseOptions(LanguageVersion.Preview), "Endpoint.cs");
        var compilation = CSharpCompilation.Create("EndpointProbe", [tree], references,
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));
        Assert.Empty(compilation.GetDiagnostics().Where(diagnostic => diagnostic.Severity == DiagnosticSeverity.Error));
        var findings = await compilation.WithAnalyzers([new CommandInjectionTaintAnalyzer()]).GetAnalyzerDiagnosticsAsync();
        Assert.Equal(expected, findings.Count(finding => finding.Id == "DNA0002"));
    }
}
