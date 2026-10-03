using Dotnetarium.Analyzers.Taint;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Diagnostics;

namespace Dotnetarium.Analyzers.Tests;

public sealed class NetworkBufferInputTests
{
    [Theory]
    [InlineData("var socket = await context.WebSockets.AcceptWebSocketAsync(); var bytes = new byte[128]; await socket.ReceiveAsync(new ArraySegment<byte>(bytes), default); Process.Start(Encoding.UTF8.GetString(bytes));", 1)]
    [InlineData("var socket = await context.WebSockets.AcceptWebSocketAsync(); var bytes = new byte[128]; await socket.ReceiveAsync(bytes.AsMemory(), default); Process.Start(Encoding.UTF8.GetString(bytes));", 1)]
    [InlineData("var socket = await context.WebSockets.AcceptWebSocketAsync(); var bytes = Encoding.UTF8.GetBytes(\"fixed\"); await socket.SendAsync(new ArraySegment<byte>(bytes), WebSocketMessageType.Text, true, default); Process.Start(Encoding.UTF8.GetString(bytes));", 0)]
    [InlineData("var result = await context.Request.BodyReader.ReadAsync(); Process.Start(Encoding.UTF8.GetString(result.Buffer.ToArray()));", 1)]
    [InlineData("if (context.Request.BodyReader.TryRead(out var result)) Process.Start(Encoding.UTF8.GetString(result.Buffer.ToArray()));", 1)]
    [InlineData("var pipe = new Pipe(); var result = await pipe.Reader.ReadAsync(); Process.Start(Encoding.UTF8.GetString(result.Buffer.ToArray()));", 0)]
    [InlineData("var reader = PipeReader.Create(context.Request.Body); var result = await reader.ReadAsync(); Process.Start(Encoding.UTF8.GetString(result.Buffer.ToArray()));", 1)]
    [InlineData("var socket = await context.WebSockets.AcceptWebSocketAsync(); var bytes = new byte[128]; var memory = bytes.AsMemory(); await socket.ReceiveAsync(memory.Slice(0, 64), default); Process.Start(Encoding.UTF8.GetString(bytes));", 1)]
    [InlineData("var socket = await context.WebSockets.AcceptWebSocketAsync(); var bytes = new byte[128]; var segment = new ArraySegment<byte>(bytes); await socket.ReceiveAsync(segment, default); Process.Start(Encoding.UTF8.GetString(bytes));", 1)]
    [InlineData("var socket = await context.WebSockets.AcceptWebSocketAsync(); var bytes = new byte[128]; var copy = bytes.ToArray(); await socket.ReceiveAsync(copy.AsMemory(), default); Process.Start(Encoding.UTF8.GetString(bytes));", 0)]
    [InlineData("var bytes = new byte[128]; await context.Request.Body.ReadExactlyAsync(bytes); Process.Start(Encoding.UTF8.GetString(bytes));", 1)]
    [InlineData("var bytes = new byte[128]; context.Request.Body.ReadAtLeast(bytes.AsSpan(), 10); Process.Start(Encoding.UTF8.GetString(bytes));", 1)]
    [InlineData("var bytes = new byte[128]; await new MemoryStream(new byte[128]).ReadExactlyAsync(bytes); Process.Start(Encoding.UTF8.GetString(bytes));", 0)]
    [InlineData("var socket = await context.WebSockets.AcceptWebSocketAsync(); var first = new byte[128]; var second = new byte[128]; var view = first.AsMemory(); view = second.AsMemory(); await socket.ReceiveAsync(view, default); Process.Start(Encoding.UTF8.GetString(first));", 0)]
    [InlineData("var socket = await context.WebSockets.AcceptWebSocketAsync(); var bytes = new byte[128]; var memory = bytes.AsMemory(); bytes = new byte[128]; await socket.ReceiveAsync(memory, default); Process.Start(Encoding.UTF8.GetString(bytes));", 0)]
    [InlineData("var bytes = new byte[128]; var memory = bytes.AsMemory(); context.Request.Body.ReadExactly(memory.Span); Process.Start(Encoding.UTF8.GetString(bytes));", 1)]
    public async Task Received_buffers_flow_but_local_buffers_do_not(string body, int expected)
    {
        var source = """
            using System;
            using System.Buffers;
            using System.Diagnostics;
            using System.IO;
            using System.Linq;
            using System.IO.Pipelines;
            using System.Net.WebSockets;
            using System.Text;
            using System.Threading.Tasks;
            using Microsoft.AspNetCore.Http;
            public static class Handler
            {
                public static async Task Run(HttpContext context)
                {
            """ + body + "}}";
        var references = ((string)AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES")!).Split(Path.PathSeparator)
            .Select(path => MetadataReference.CreateFromFile(path));
        var tree = CSharpSyntaxTree.ParseText(source, new CSharpParseOptions(LanguageVersion.Preview), "Network.cs");
        var compilation = CSharpCompilation.Create("NetworkProbe", [tree], references,
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));
        Assert.Empty(compilation.GetDiagnostics().Where(diagnostic => diagnostic.Severity == DiagnosticSeverity.Error));
        var findings = await compilation.WithAnalyzers([new CommandInjectionTaintAnalyzer()]).GetAnalyzerDiagnosticsAsync();
        Assert.Equal(expected, findings.Count(finding => finding.Id == "DNA0002"));
    }
}
