using Dotnetarium.Analyzers.Taint;

namespace Dotnetarium.Analyzers.Tests;

public sealed class EndpointFilterTests
{
    [Theory]
    [InlineData("app.MapGet(\"/run\", (string command) => command).AddEndpointFilter(async (context, next) => { Process.Start(context.GetArgument<string>(0)); return await next(context); });", 1)]
    [InlineData("app.MapPost(\"/run\", (Input body) => body).AddEndpointFilter(async (context, next) => { Process.Start(context.GetArgument<Input>(0).Value); return await next(context); });", 1)]
    [InlineData("app.MapGet(\"/run\", ([FromServices] Input service) => service).AddEndpointFilter(async (context, next) => { Process.Start(context.GetArgument<Input>(0).Value); return await next(context); });", 0)]
    [InlineData("app.MapPost(\"/run\", (string command, [FromServices] Input service) => command).AddEndpointFilter(async (context, next) => { Process.Start(context.GetArgument<Input>(1).Value); return await next(context); });", 0)]
    [InlineData("app.MapGet(\"/run\", (string command) => command).AddEndpointFilter(async (context, next) => { Process.Start((string)context.Arguments[0]); return await next(context); });", 1)]
    [InlineData("app.MapGet(\"/run\", ([FromServices] Input service) => service).AddEndpointFilter(async (context, next) => { Process.Start(((Input)context.Arguments[0]).Value); return await next(context); });", 0)]
    [InlineData("app.MapGet(\"/run\", (string command) => command).AddEndpointFilter<Filter>();", 1)]
    [InlineData("app.MapGet(\"/run\", (string command) => command).AddEndpointFilterFactory((factory, next) => async context => { Process.Start(context.GetArgument<string>(0)); return await next(context); });", 1)]
    [InlineData("app.MapGet(\"/run\", (Bound input) => input).AddEndpointFilter(async (context, next) => { Process.Start(context.GetArgument<Bound>(0).Value); return await next(context); });", 1)]
    [InlineData("app.MapGet(\"/run\", (Bound input) => input).AddEndpointFilter(async (context, next) => { Process.Start(context.GetArgument<Bound>(0).Fixed); return await next(context); });", 0)]
    [InlineData("var context = new DefaultEndpointFilterInvocationContext(new DefaultHttpContext(), \"fixed\"); Process.Start(context.GetArgument<string>(0));", 0)]
    public async Task Filter_slots_follow_endpoint_binding_and_local_contexts_stay_clean(string registration, int expected)
    {
        var findings = await FrameworkProbe.Analyze("""
            using System.Diagnostics;
            using System.Threading.Tasks;
            using Microsoft.AspNetCore.Builder;
            using Microsoft.AspNetCore.Http;
            using Microsoft.AspNetCore.Mvc;
            public sealed class Input { public string Value { get; set; } = "fixed"; }
            public sealed class Bound
            {
                public string Value { get; set; } = "fixed";
                public string Fixed { get; set; } = "fixed";
                public static ValueTask<Bound> BindAsync(HttpContext context) =>
                    new(new Bound { Value = context.Request.Query["command"], Fixed = "fixed" });
            }
            public sealed class Filter : IEndpointFilter
            {
                public async ValueTask<object> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
                { Process.Start(context.GetArgument<string>(0)); return await next(context); }
            }
            public static class Endpoints { public static void Configure(WebApplication app) {
            """ + registration + "}}", new CommandInjectionTaintAnalyzer());
        Assert.True(expected == findings.Length, $"{registration}: expected {expected}, actual {findings.Length}");
    }
}
