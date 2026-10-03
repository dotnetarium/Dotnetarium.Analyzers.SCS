using System.Collections.Immutable;
using Dotnetarium.Analyzers.Taint;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Diagnostics;

namespace Dotnetarium.Analyzers.Tests;

public sealed class SignalRInputTests
{
    [Fact]
    public async Task Hub_calls_and_upload_streams_reach_existing_sinks()
    {
        var source = """
            using System;
            using System.Collections.Generic;
            using System.Diagnostics;
            using System.Threading.Channels;
            using System.Threading.Tasks;
            using Microsoft.AspNetCore.SignalR;
            public sealed class Payload { public string Value { get; set; } = ""; }
            public interface IClient { Task Send(string value); }
            public sealed class CommandsHub : Hub<IClient>
            {
                public void Run(string command, Payload payload)
                {
                    _ = Process.Start(command);
                    _ = Process.Start(payload.Value);
                }
                public async Task Upload(IAsyncEnumerable<string> stream)
                {
                    await foreach (var command in stream) _ = Process.Start(command);
                }
                public async Task UploadChannel(ChannelReader<string> stream)
                {
                    await foreach (var command in stream.ReadAllAsync()) _ = Process.Start(command);
                }
                public async Task Read(ChannelReader<string> stream) => _ = Process.Start(await stream.ReadAsync());
                public void TryRead(ChannelReader<string> stream)
                {
                    if (stream.TryRead(out var command)) _ = Process.Start(command);
                }
                private void Helper(string command) => _ = Process.Start(command);
                public static void StaticHelper(string command) => _ = Process.Start(command);
                public override Task OnDisconnectedAsync(Exception? exception)
                {
                    _ = Process.Start(exception!.Message);
                    return Task.CompletedTask;
                }
                public void LocalChannel()
                {
                    var channel = Channel.CreateUnbounded<string>();
                    if (channel.Reader.TryRead(out var localCommand)) _ = Process.Start(localCommand);
                }
            }
            """;
        var diagnostics = await AnalyzeAsync(source);
        var findings = diagnostics.Where(diagnostic => diagnostic.Id == "DNA0002").ToArray();
        Assert.Equal(6, findings.Length);
        var lines = findings.Select(finding => source.Split('\n')[finding.Location.GetLineSpan().StartLinePosition.Line]).ToArray();
        Assert.Contains(lines, line => line.Contains("payload.Value", StringComparison.Ordinal));
        Assert.Contains(lines, line => line.Contains("in stream)", StringComparison.Ordinal));
        Assert.Contains(lines, line => line.Contains("stream.ReadAllAsync()", StringComparison.Ordinal));
        Assert.Contains(lines, line => line.Contains("await stream.ReadAsync()", StringComparison.Ordinal));
        Assert.Contains(lines, line => line.Contains("stream.TryRead(", StringComparison.Ordinal));
        Assert.DoesNotContain(lines, line => line.Contains("Helper", StringComparison.Ordinal) ||
            line.Contains("exception", StringComparison.Ordinal) || line.Contains("localCommand", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Explicit_and_registered_services_are_excluded()
    {
        var diagnostics = await AnalyzeAsync("""
            using System.Diagnostics;
            using Microsoft.AspNetCore.SignalR;
            using Microsoft.AspNetCore.Mvc;
            using Microsoft.Extensions.DependencyInjection;
            public sealed class Service { public string Value => "fixed"; }
            public sealed class FactoryService { public string Value => "fixed"; }
            public sealed class ConditionalService { public string Value => "fixed"; }
            public sealed class DescriptorService { public string Value => "fixed"; }
            public sealed class GenericDescriptorService { public string Value => "fixed"; }
            public sealed class GenericService<T> { public string Value => "fixed"; }
            public sealed class Input { public string Value { get; set; } = ""; }
            public sealed class TestHub : Hub
            {
                public void Run(Service implicitService, FactoryService factoryService, ConditionalService conditionalService,
                    DescriptorService descriptorService, GenericDescriptorService genericDescriptorService,
                    GenericService<string> genericService,
                    [FromServices] Input explicitService, [FromKeyedServices("key")] Input keyedService,
                    Input request)
                {
                    _ = Process.Start(implicitService.Value);
                    _ = Process.Start(factoryService.Value);
                    _ = Process.Start(conditionalService.Value);
                    _ = Process.Start(descriptorService.Value);
                    _ = Process.Start(genericDescriptorService.Value);
                    _ = Process.Start(genericService.Value);
                    _ = Process.Start(explicitService.Value);
                    _ = Process.Start(keyedService.Value);
                    _ = Process.Start(request.Value);
                }
            }
            public static class Startup
            {
                public static void Configure(IServiceCollection services, bool enabled)
                {
                    services.AddScoped<Service>();
                    services.AddSingleton<FactoryService>(_ => new FactoryService());
                    if (enabled) services.AddTransient<ConditionalService>();
                    services.Add(new ServiceDescriptor(typeof(DescriptorService), typeof(DescriptorService), ServiceLifetime.Scoped));
                    services.Add(ServiceDescriptor.Singleton<GenericDescriptorService, GenericDescriptorService>());
                    services.AddScoped(typeof(GenericService<>));
                }
            }
            """);
        Assert.Single(diagnostics.Where(diagnostic => diagnostic.Id == "DNA0002"));
    }

    [Theory]
    [InlineData("services.AddSignalR(options => options.DisableImplicitFromServicesParameters = true);", 1)]
    [InlineData("services.AddSignalR(options => options.DisableImplicitFromServicesParameters = false);", 0)]
    [InlineData("services.AddSignalR().AddHubOptions<TestHub>(options => options.DisableImplicitFromServicesParameters = true);", 1)]
    [InlineData("if (enabled) services.AddSignalR(options => options.DisableImplicitFromServicesParameters = true);", 0)]
    [InlineData("services.AddSignalR(options => options.DisableImplicitFromServicesParameters = enabled);", 0)]
    [InlineData("services.AddSignalR(options => options.DisableImplicitFromServicesParameters = true).AddHubOptions<TestHub>(options => options.DisableImplicitFromServicesParameters = false);", 0)]
    public async Task Binding_option_controls_implicit_service_parameters(string registration, int expected)
    {
        var diagnostics = await AnalyzeAsync("""
            using System.Diagnostics;
            using Microsoft.AspNetCore.SignalR;
            using Microsoft.Extensions.DependencyInjection;
            public sealed class Input { public string Value { get; set; } = ""; }
            public sealed class TestHub : Hub
            {
                public void Run(Input input) => _ = Process.Start(input.Value);
            }
            public static class Startup
            {
                public static void Configure(IServiceCollection services, bool enabled)
                {
                    services.AddScoped<Input>();
            """ + registration + """
                }
            }
            """);
        Assert.Equal(expected, diagnostics.Count(diagnostic => diagnostic.Id == "DNA0002"));
    }

    private static async Task<ImmutableArray<Diagnostic>> AnalyzeAsync(string source)
    {
        var references = ((string)AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES")!).Split(Path.PathSeparator)
            .Select(path => MetadataReference.CreateFromFile(path));
        var tree = CSharpSyntaxTree.ParseText(source, new CSharpParseOptions(LanguageVersion.Preview), "Hub.cs");
        var compilation = CSharpCompilation.Create("HubProbe", [tree], references,
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));
        Assert.Empty(compilation.GetDiagnostics().Where(diagnostic => diagnostic.Severity == DiagnosticSeverity.Error));
        return await compilation.WithAnalyzers([new CommandInjectionTaintAnalyzer()]).GetAnalyzerDiagnosticsAsync();
    }
}
