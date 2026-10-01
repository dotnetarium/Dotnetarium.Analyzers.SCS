using System.Collections.Immutable;
using Dotnetarium.Analyzers.Cookies;
using Dotnetarium.Analyzers.Taint;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Diagnostics;

namespace DotnetariumSCS.Tests.V2;

public sealed class AnalyzerSmokeTests
{
    [Fact]
    public async Task Reports_command_flow_with_engine_witness()
    {
        var diagnostics = await AnalyzeAsync("""
            using System;
            using System.Diagnostics;
            class Demo
            {
                static void Run()
                {
                    var input = Console.ReadLine();
                    Process.Start(input!);
                }
            }
            """, new CommandInjectionTaintAnalyzer());

        var finding = Assert.Single(diagnostics.Where(diagnostic => diagnostic.Id == "DNA0002"));
        Assert.Equal("true", finding.Properties["dotnetarium.flow"]);
        Assert.True(finding.AdditionalLocations.Count >= 2);
        Assert.Equal(finding.Location, finding.AdditionalLocations[^1]);
    }

    [Fact]
    public async Task Api_controller_attribute_marks_nonstandard_controller_name_as_input()
    {
        var diagnostics = await AnalyzeAsync("""
            using Microsoft.AspNetCore.Mvc;
            [ApiController]
            public class Endpoint : ControllerBase
            {
                public IActionResult Go(string url) => Redirect(url);
            }
            """, new OpenRedirectTaintAnalyzer());

        Assert.Single(diagnostics.Where(diagnostic => diagnostic.Id == "DNA0005"));
    }

    [Fact]
    public async Task Follows_registered_interface_implementation_to_redirect_sink()
    {
        var diagnostics = await AnalyzeAsync("""
            using Microsoft.AspNetCore.Http;
            using Microsoft.AspNetCore.Mvc;
            using Microsoft.Extensions.DependencyInjection;
            public interface IRedirector { void Go(string url); }
            public class UnsafeRedirector : IRedirector
            {
                public void Go(string url) => Holder.Response.Redirect(url);
            }
            public class SafeRedirector : IRedirector
            {
                public void Go(string url) { }
            }
            public static class Holder { public static HttpResponse Response = null!; }
            [ApiController]
            public class Endpoint : ControllerBase
            {
                private readonly IRedirector redirector;
                public Endpoint(IRedirector redirector) => this.redirector = redirector;
                public void Go(string url) => redirector.Go(url);
            }
            static class Services
            {
                public static void Configure(IServiceCollection services) =>
                    services.AddScoped<IRedirector, UnsafeRedirector>();
            }
            """, new OpenRedirectTaintAnalyzer());

        Assert.Single(diagnostics.Where(diagnostic => diagnostic.Id == "DNA0005"));
    }

    [Fact]
    public async Task Reports_tainted_HttpClient_url()
    {
        var diagnostics = await AnalyzeAsync("""
            using System;
            using System.Net.Http;
            class Demo
            {
                static async System.Threading.Tasks.Task Run()
                {
                    var input = Console.ReadLine();
                    using var client = new HttpClient();
                    await client.GetStringAsync(input);
                }
            }
            """, new ServerSideRequestForgeryTaintAnalyzer());

        Assert.Single(diagnostics.Where(diagnostic => diagnostic.Id == "DNA0011"));
    }

    [Fact]
    public async Task Ldap_filter_and_distinguished_name_share_one_rule_but_keep_separate_escaping()
    {
        var diagnostics = await AnalyzeAsync("""
            using System;
            namespace Microsoft.Security.Application
            {
                public static class Encoder
                {
                    public static string LdapFilterEncode(string value) => value;
                }
            }
            namespace System.DirectoryServices
            {
                public class DirectorySearcher
                {
                    public DirectorySearcher(string filter) { }
                }
                public class DirectoryEntry
                {
                    public DirectoryEntry(string path) { }
                }
            }
            public class Demo
            {
                public void Run()
                {
                    var input = Console.ReadLine()!;
                    _ = new System.DirectoryServices.DirectorySearcher(input);
                    _ = new System.DirectoryServices.DirectoryEntry(input);
                    var escapedFilter = Microsoft.Security.Application.Encoder.LdapFilterEncode(input);
                    _ = new System.DirectoryServices.DirectorySearcher(escapedFilter);
                    _ = new System.DirectoryServices.DirectoryEntry(escapedFilter);
                }
            }
            """, new LdapFilterTaintAnalyzer());

        Assert.Equal(3, diagnostics.Count(diagnostic => diagnostic.Id == "DNA0006"));
    }

    [Fact]
    public async Task Reports_untrusted_xpath_expression()
    {
        var diagnostics = await AnalyzeAsync("""
            using System;
            using System.Xml;
            public class Demo
            {
                public void Run(XmlDocument document)
                {
                    var expression = Console.ReadLine()!;
                    _ = document.SelectSingleNode(expression);
                }
            }
            """, new XPathTaintAnalyzer());

        Assert.Single(diagnostics.Where(diagnostic => diagnostic.Id == "DNA0007"));
    }

    [Fact]
    public async Task Reports_untrusted_stream_in_unsafe_deserializer()
    {
        var diagnostics = await AnalyzeAsync("""
            using System.IO;
            using System.Net.Sockets;
            namespace System.Runtime.Serialization
            {
                public class NetDataContractSerializer
                {
                    public object Deserialize(Stream stream) => new object();
                }
            }
            public class Demo
            {
                public object Run(TcpClient client) =>
                    new System.Runtime.Serialization.NetDataContractSerializer()
                        .Deserialize(client.GetStream());
            }
            """, new DeserializationTaintAnalyzer());

        Assert.Single(diagnostics.Where(diagnostic => diagnostic.Id == "DNA0008"));
    }

    [Fact]
    public async Task Reports_untrusted_dynamic_csharp_code()
    {
        var diagnostics = await AnalyzeAsync("""
            using System;
            using System.Threading.Tasks;
            namespace Microsoft.CodeAnalysis.CSharp.Scripting
            {
                public static class CSharpScript
                {
                    public static Task<object> EvaluateAsync(string code) => Task.FromResult(new object());
                }
            }
            public class Demo
            {
                public Task<object> Run() =>
                    Microsoft.CodeAnalysis.CSharp.Scripting.CSharpScript.EvaluateAsync(Console.ReadLine()!);
            }
            """, new DynamicCodeExecutionTaintAnalyzer());

        Assert.Single(diagnostics.Where(diagnostic => diagnostic.Id == "DNA0012"));
    }

    [Fact]
    public async Task Reports_hardcoded_network_credential_after_adapter_rewrite()
    {
        var diagnostics = await AnalyzeAsync("""
            using System.Net;
            class Demo
            {
                static NetworkCredential Create() => new NetworkCredential("user", "secret");
            }
            """, new HardcodedPasswordAnalyzer());

        Assert.Single(diagnostics.Where(diagnostic => diagnostic.Id == "DNA0009"));
    }

    [Fact]
    public async Task Combines_cookie_settings_per_sensitive_cookie()
    {
        var diagnostics = await AnalyzeAsync("""
            using Microsoft.AspNetCore.Builder;
            using Microsoft.AspNetCore.Http;
            using Microsoft.Extensions.DependencyInjection;
            class Demo
            {
                static void Configure(WebApplicationBuilder builder)
                {
                    builder.Services.AddAuthentication().AddCookie(options =>
                    {
                        options.Cookie.HttpOnly = false;
                        options.Cookie.SecurePolicy = CookieSecurePolicy.None;
                        options.Cookie.SameSite = SameSiteMode.None;
                    });
                    builder.Services.AddSession(options => { options.Cookie.HttpOnly = false; });
                }
            }
            """, new CookieSettingsAnalyzer());

        var findings = diagnostics.Where(diagnostic => diagnostic.Id == "DNA0010").ToArray();
        Assert.Equal(2, findings.Length);
        Assert.Contains(findings, diagnostic => diagnostic.GetMessage().Contains("HttpOnly=false, SameSite=None", StringComparison.Ordinal));
        Assert.Contains(findings, diagnostic => diagnostic.GetMessage().Contains("session", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Does_not_flag_framework_cookie_defaults()
    {
        var diagnostics = await AnalyzeAsync("""
            using Microsoft.AspNetCore.Builder;
            using Microsoft.Extensions.DependencyInjection;
            class Demo
            {
                static void Configure(WebApplicationBuilder builder)
                {
                    builder.Services.AddAuthentication().AddCookie();
                    builder.Services.AddSession();
                }
            }
            """, new CookieSettingsAnalyzer());

        Assert.DoesNotContain(diagnostics, diagnostic => diagnostic.Id == "DNA0010");
    }

    [Fact]
    public async Task Cross_site_auth_cookie_with_secure_policy_is_allowed()
    {
        var diagnostics = await AnalyzeAsync("""
            using Microsoft.AspNetCore.Builder;
            using Microsoft.AspNetCore.Http;
            using Microsoft.Extensions.DependencyInjection;
            class Demo
            {
                static void Configure(WebApplicationBuilder builder)
                {
                    builder.Services.AddAuthentication().AddCookie(options =>
                    {
                        options.Cookie.SameSite = SameSiteMode.None;
                        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
                    });
                }
            }
            """, new CookieSettingsAnalyzer());

        Assert.DoesNotContain(diagnostics, diagnostic => diagnostic.Id == "DNA0010");
    }

    [Fact]
    public async Task Reports_cookie_builder_initializer_and_insecure_custom_cookie()
    {
        var diagnostics = await AnalyzeAsync("""
            using Microsoft.AspNetCore.Authentication.Cookies;
            using Microsoft.AspNetCore.Http;
            class Demo
            {
                static void Configure(CookieAuthenticationOptions auth, HttpResponse response)
                {
                    auth.Cookie = new CookieBuilder
                    {
                        HttpOnly = false,
                        SecurePolicy = CookieSecurePolicy.None
                    };
                    response.Cookies.Append("cross-site", "x", new CookieOptions
                    {
                        SameSite = SameSiteMode.None
                    });
                    response.Cookies.Append("safe-cross-site", "x", new CookieOptions
                    {
                        SameSite = SameSiteMode.None,
                        Secure = true
                    });
                }
            }
            """, new CookieSettingsAnalyzer());

        var findings = diagnostics.Where(diagnostic => diagnostic.Id == "DNA0010").ToArray();
        Assert.Equal(2, findings.Length);
        Assert.Contains(findings, diagnostic => diagnostic.GetMessage().Contains("HttpOnly=false", StringComparison.Ordinal));
        Assert.Contains(findings, diagnostic => diagnostic.GetMessage().Contains("cross-site", StringComparison.Ordinal));
    }

    private static async Task<ImmutableArray<Diagnostic>> AnalyzeAsync(string source, params DiagnosticAnalyzer[] analyzers)
    {
        var trustedAssemblies = (string)AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES")!;
        var references = trustedAssemblies.Split(Path.PathSeparator)
            .Select(path => MetadataReference.CreateFromFile(path))
            .ToArray();
        var tree = CSharpSyntaxTree.ParseText(source, new CSharpParseOptions(LanguageVersion.Preview), "Example.cs");
        var compilation = CSharpCompilation.Create("Example", new[] { tree }, references,
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));
        Assert.DoesNotContain(compilation.GetDiagnostics(), diagnostic => diagnostic.Severity == DiagnosticSeverity.Error);
        return await compilation.WithAnalyzers(analyzers.ToImmutableArray()).GetAnalyzerDiagnosticsAsync();
    }
}
