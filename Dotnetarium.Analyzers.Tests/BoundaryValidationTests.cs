using Dotnetarium.Analyzers.Taint;

namespace Dotnetarium.Analyzers.Tests;

public sealed class BoundaryValidationTests
{
    [Theory]
    [InlineData("if (Url.IsLocalUrl(url)) { Log(); return Redirect(url); }", 0)]
    [InlineData("if (!Url.IsLocalUrl(url)) return NotFound(); Log(); return Redirect(url);", 0)]
    [InlineData("if (Url.IsLocalUrl(url) && enabled) return Redirect(url);", 0)]
    [InlineData("if (Url.IsLocalUrl(url) || enabled) return Redirect(url);", 1)]
    [InlineData("if (!Url.IsLocalUrl(url)) { return NotFound(); } else { return Redirect(url); }", 0)]
    [InlineData("Url.IsLocalUrl(url); return Redirect(url);", 1)]
    [InlineData("if (Url.IsLocalUrl(url)) { url = Request.Query[\"other\"]; return Redirect(url); }", 1)]
    [InlineData("if (Url.IsLocalUrl(url)) { Replace(ref url); return Redirect(url); }", 1)]
    [InlineData("if (Url.IsLocalUrl(url)) { System.Action later = () => Redirect(url); later(); }", 1)]
    public async Task Local_redirect_validation_requires_a_consuming_stable_branch(string body, int expected)
    {
        var findings = await FrameworkProbe.Analyze("""
            using Microsoft.AspNetCore.Mvc;
            public class Endpoints : Controller {
                public IActionResult Run(string url, bool enabled) {
            """ + body + """
                    return NotFound();
                }
                private void Log() { }
                private void Replace(ref string value) { value = Request.Query["other"]; }
            }
            """, new OpenRedirectTaintAnalyzer());
        Assert.Equal(expected, findings.Length);
    }

    [Theory]
    [InlineData("if (input == \"fixed\") Process.Start(input);", 0)]
    [InlineData("if (new[] { \"fixed\", \"other\" }.Contains(input)) Process.Start(input);", 0)]
    [InlineData("if (input != \"fixed\") return; Process.Start(input);", 0)]
    [InlineData("new[] { \"fixed\" }.Contains(input); Process.Start(input);", 1)]
    [InlineData("if (input == \"fixed\" || enabled) Process.Start(input);", 1)]
    [InlineData("if (new[] { input }.Contains(input)) Process.Start(input);", 1)]
    [InlineData("if (input == \"fixed\") { input = context.Request.Query[\"other\"]; Process.Start(input); }", 1)]
    public async Task Finite_constant_allowlists_are_branch_local(string body, int expected)
    {
        var findings = await FrameworkProbe.Analyze("""
            using System.Diagnostics;
            using System.Linq;
            using Microsoft.AspNetCore.Http;
            public static class Worker { public static void Run(HttpContext context, bool enabled) {
                string input = context.Request.Query["command"];
            """ + body + "}}", new CommandInjectionTaintAnalyzer());
        Assert.Equal(expected, findings.Length);
    }

    [Theory]
    [InlineData("var path = Path.GetFullPath(input); if (path.StartsWith(\"/safe/\", StringComparison.Ordinal)) File.ReadAllText(path);", 0)]
    [InlineData("var path = Path.GetFullPath(input); if (!path.StartsWith(\"/safe/\", StringComparison.Ordinal)) return; File.ReadAllText(path);", 0)]
    [InlineData("var path = Path.GetFullPath(input); if (path.StartsWith(\"/safe\", StringComparison.Ordinal)) File.ReadAllText(path);", 1)]
    [InlineData("var path = input; if (path.StartsWith(\"/safe/\", StringComparison.Ordinal)) File.ReadAllText(path);", 1)]
    [InlineData("var path = Path.GetFullPath(input); if (path.StartsWith(\"/safe/\")) File.ReadAllText(path);", 1)]
    [InlineData("var path = Path.GetFullPath(input); path.StartsWith(\"/safe/\", StringComparison.Ordinal); File.ReadAllText(path);", 1)]
    [InlineData("var path = Path.GetFullPath(input); if (path.StartsWith(\"/safe/\", StringComparison.Ordinal)) { path = input; File.ReadAllText(path); }", 1)]
    public async Task Path_containment_requires_canonicalization_and_separator_boundary(string body, int expected)
    {
        var findings = await FrameworkProbe.Analyze("""
            using System;
            using System.IO;
            using Microsoft.AspNetCore.Http;
            public static class Worker { public static void Run(HttpContext context) {
                string input = context.Request.Query["path"];
            """ + body + "}}", new PathTraversalTaintAnalyzer());
        Assert.Equal(expected, findings.Length);
    }

    [Theory]
    [InlineData("await client.GetStringAsync(\"https://example.com/items/\" + input);", 0)]
    [InlineData("await client.GetStringAsync($\"https://example.com/items/{input}\");", 0)]
    [InlineData("var uri = new Uri(\"https://example.com/items/\" + input); await client.GetStringAsync(uri);", 0)]
    [InlineData("await client.GetStringAsync(\"https://example.com\" + input);", 1)]
    [InlineData("await client.GetStringAsync(\"https://\" + input + \"/items\");", 1)]
    [InlineData("client.BaseAddress = new Uri(\"https://example.com/\"); await client.GetStringAsync(input);", 1)]
    [InlineData("var uri = \"https://example.com/items/\" + input; uri = input; await client.GetStringAsync(uri);", 1)]
    public async Task Fixed_authority_requires_a_complete_literal_origin(string body, int expected)
    {
        var findings = await FrameworkProbe.Analyze("""
            using System;
            using System.Net.Http;
            using System.Threading.Tasks;
            using Microsoft.AspNetCore.Http;
            public static class Worker { public static async Task Run(HttpContext context, HttpClient client) {
                string input = context.Request.Query["url"];
            """ + body + "}}", new ServerSideRequestForgeryTaintAnalyzer());
        Assert.Equal(expected, findings.Length);
    }
}
