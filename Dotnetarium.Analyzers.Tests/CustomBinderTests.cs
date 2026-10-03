using Dotnetarium.Analyzers.Taint;

namespace Dotnetarium.Analyzers.Tests;

public sealed class CustomBinderTests
{
    [Theory]
    [InlineData("public static async ValueTask<Bound> BindAsync(HttpContext context, ParameterInfo parameter) { await Task.Yield(); return new Bound { Value = context.Request.Query[\"command\"] }; }", 1)]
    [InlineData("public static ValueTask<Bound> BindAsync(HttpContext context, ParameterInfo parameter) => new(new Bound { Value = \"fixed\" });", 0)]
    [InlineData("static ValueTask<Bound> IBindableFromHttpContext<Bound>.BindAsync(HttpContext context, ParameterInfo parameter) => new(new Bound { Value = context.Request.Query[\"command\"] });", 1)]
    public async Task Modern_binder_signatures_preserve_field_provenance(string binder, int expected)
    {
        var findings = await FrameworkProbe.Analyze("""
            using System.Diagnostics;
            using System.Reflection;
            using System.Threading.Tasks;
            using Microsoft.AspNetCore.Builder;
            using Microsoft.AspNetCore.Http;
            public sealed class Bound : IBindableFromHttpContext<Bound> {
                public string Value = "fixed";
            """ + binder + """
            }
            public static class Endpoints { public static void Configure(WebApplication app) => app.MapGet("/run", (Bound input) => Process.Start(input.Value)); }
            """, new CommandInjectionTaintAnalyzer());
        Assert.Equal(expected, findings.Length);
    }

    [Theory]
    [InlineData("return new(new Bound { Value = context.Request.Query[\"command\"], Fixed = \"fixed\" });", "input.Value", 1)]
    [InlineData("return new(new Bound { Value = context.Request.Query[\"command\"], Fixed = \"fixed\" });", "input.Fixed", 0)]
    [InlineData("var value = context.Request.Headers[\"command\"].ToString(); return new(new Bound { Value = value });", "input.Value", 1)]
    [InlineData("var result = new Bound(); result.Value = context.Request.Query[\"command\"]; return new(result);", "input.Value", 1)]
    [InlineData("var result = new Bound { Value = context.Request.Query[\"command\"] }; result.Value = \"fixed\"; return new(result);", "input.Value", 0)]
    [InlineData("var discarded = new Bound { Value = context.Request.Query[\"command\"] }; return new(new Bound { Value = \"fixed\" });", "input.Value", 0)]
    [InlineData("return new(new Bound { Value = \"fixed\" });", "input.Value", 0)]
    [InlineData("return new(new Bound { Value = context.RequestServices.GetRequiredService<Service>().Value });", "input.Value", 0)]
    [InlineData("return new(new Bound { Value = Read(context) });", "input.Value", 1)]
    [InlineData("if (context.Request.Query.ContainsKey(\"command\")) return new(new Bound { Value = context.Request.Query[\"command\"] }); return new(new Bound { Value = \"fixed\" });", "input.Value", 1)]
    public async Task Binder_members_follow_returned_instances_and_actual_request_provenance(string binder, string sinkValue, int expected)
    {
        var findings = await FrameworkProbe.Analyze("""
            using System.Diagnostics;
            using System.Threading.Tasks;
            using Microsoft.AspNetCore.Builder;
            using Microsoft.AspNetCore.Http;
            using Microsoft.Extensions.DependencyInjection;
            public sealed class Service { public string Value => "fixed"; }
            public sealed class Bound
            {
                public string Value { get; set; } = "fixed";
                public string Fixed { get; set; } = "fixed";
                public static ValueTask<Bound> BindAsync(HttpContext context) {
            """ + binder + """
                }
                private static string Read(HttpContext context) => context.Request.Query["command"];
            }
            public static class Endpoints { public static void Configure(WebApplication app) {
            """ + "app.MapGet(\"/run\", (Bound input) => Process.Start(" + sinkValue + ")); }}", new CommandInjectionTaintAnalyzer());
        Assert.Equal(expected, findings.Length);
        Assert.All(findings, finding => Assert.NotEmpty(finding.AdditionalLocations));
    }
}
