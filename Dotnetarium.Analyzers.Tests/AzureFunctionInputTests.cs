using Dotnetarium.Analyzers.Taint;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Diagnostics;

namespace Dotnetarium.Analyzers.Tests;

public sealed class AzureFunctionInputTests
{
    [Theory]
    [InlineData("[Function(\"http\")] public void Run([HttpTrigger(AuthorizationLevel.Anonymous, \"post\")] Input body) { Process.Start(body.Value); }", 1)]
    [InlineData("[Function(\"http\")] public void Run([HttpTrigger] HttpRequestData request, [FromBody] Input body) { Process.Start(body.Value); }", 1)]
    [InlineData("[Function(\"http\")] public async Task Run([HttpTrigger] HttpRequestData request) { Process.Start(await request.ReadAsStringAsync()); }", 1)]
    [InlineData("[Function(\"http\")] public async Task Run([HttpTrigger] HttpRequestData request) { Process.Start((await request.ReadFromJsonAsync<Input>()).Value); }", 1)]
    [InlineData("[Function(\"http\")] public void Run([HttpTrigger] HttpRequestData request) { Process.Start(request.Query[\"command\"]); }", 1)]
    [InlineData("[Function(\"http\")] public void Run([HttpTrigger] HttpRequestData request) { Process.Start(request.Headers.GetValues(\"command\").First()); }", 1)]
    [InlineData("[Function(\"http\")] public async Task Run([HttpTrigger] HttpRequestData request) { Process.Start(await new StreamReader(request.Body).ReadToEndAsync()); }", 1)]
    [InlineData("[Function(\"http\")] public void Run([HttpTrigger] HttpRequest request) { Process.Start(request.Query[\"command\"]); }", 1)]
    [InlineData("[Function(\"bus\")] public void Run([ServiceBusTrigger(\"queue\")] string body) { Process.Start(body); }", 1)]
    [InlineData("[Function(\"bus\")] public void Run([ServiceBusTrigger(\"queue\")] Input body) { Process.Start(body.Value); }", 1)]
    [InlineData("[Function(\"bus\")] public void Run([ServiceBusTrigger(\"queue\")] ServiceBusReceivedMessage message) { Process.Start(message.Body.ToString()); }", 1)]
    [InlineData("[Function(\"bus\")] public void Run([ServiceBusTrigger(\"queue\", IsBatched = true)] ServiceBusReceivedMessage[] messages) { foreach (var message in messages) Process.Start(message.Body.ToString()); }", 1)]
    [InlineData("[Function(\"bus\")] public void Run([ServiceBusTrigger(\"queue\", IsBatched = true)] string[] messages) { Process.Start(messages[0]); }", 1)]
    [InlineData("[Function(\"bus\")] public void Run([ServiceBusTrigger(\"queue\")] ServiceBusReceivedMessage message) { Process.Start(Encoding.UTF8.GetString(message.Body.ToArray())); }", 1)]
    [InlineData("[Function(\"bus\")] public void Run([ServiceBusTrigger(\"queue\")] ServiceBusReceivedMessage message) { Process.Start(message.ApplicationProperties[\"command\"].ToString()); }", 1)]
    [InlineData("[Function(\"bus\")] public void Run([ServiceBusTrigger(\"queue\")] string body, FunctionContext context, ServiceBusMessageActions actions, Input service) { Process.Start(context.InvocationId); Process.Start(actions.ToString()); Process.Start(service.Value); }", 0)]
    [InlineData("[Function(\"http\")] public void Run([HttpTrigger] HttpRequestData request, Input service) { Process.Start(service.Value); Process.Start(request.FunctionContext.InvocationId); }", 0)]
    [InlineData("[Function(\"notHttp\")] public void Run([FromBody] Input body) { Process.Start(body.Value); }", 0)]
    [InlineData("public void Helper([ServiceBusTrigger(\"queue\")] Input body) { Process.Start(body.Value); }", 0)]
    [InlineData("public void Helper() { var message = ServiceBusModelFactory.ServiceBusReceivedMessage(body: BinaryData.FromString(\"fixed\")); Process.Start(message.Body.ToString()); }", 0)]
    public async Task Only_trigger_payloads_are_inputs(string method, int expected)
    {
        var source = """
            using System;
            using System.Diagnostics;
            using System.IO;
            using System.Linq;
            using System.Text;
            using System.Threading.Tasks;
            using Azure.Messaging.ServiceBus;
            using Microsoft.Azure.Functions.Worker;
            using Microsoft.Azure.Functions.Worker.Http;
            using Microsoft.AspNetCore.Http;
            public sealed class Input { public string Value { get; set; } = ""; }
            public sealed class Functions
            {
            """ + method + "}";
        var references = ((string)AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES")!).Split(Path.PathSeparator)
            .Select(path => MetadataReference.CreateFromFile(path));
        var tree = CSharpSyntaxTree.ParseText(source, new CSharpParseOptions(LanguageVersion.Preview), "Function.cs");
        var compilation = CSharpCompilation.Create("FunctionProbe", [tree], references,
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));
        Assert.Empty(compilation.GetDiagnostics().Where(diagnostic => diagnostic.Severity == DiagnosticSeverity.Error));
        var findings = await compilation.WithAnalyzers([new CommandInjectionTaintAnalyzer()]).GetAnalyzerDiagnosticsAsync();
        Assert.Equal(expected, findings.Count(finding => finding.Id == "DNA0002"));
    }
}
