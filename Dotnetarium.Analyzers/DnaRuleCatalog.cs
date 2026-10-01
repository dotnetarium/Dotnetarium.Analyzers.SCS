using System.Collections.Generic;
using Microsoft.CodeAnalysis;

namespace Dotnetarium.Analyzers
{
    /// <summary>Stable diagnostic identities for the 2.x C# analyzer.</summary>
    public static class DnaRuleCatalog
    {
        public static readonly DiagnosticDescriptor SqlInjection = Taint("DNA0001", "SQL injection", 89);
        public static readonly DiagnosticDescriptor CommandInjection = Taint("DNA0002", "OS command injection", 78);
        public static readonly DiagnosticDescriptor CrossSiteScripting = Taint("DNA0003", "Cross-site scripting", 79);
        public static readonly DiagnosticDescriptor PathEscape = Taint("DNA0004", "Path escape", 22);
        public static readonly DiagnosticDescriptor OpenRedirect = Taint("DNA0005", "Open redirect", 601);
        public static readonly DiagnosticDescriptor LdapInjection = Taint("DNA0006", "LDAP injection", 90);
        public static readonly DiagnosticDescriptor XPathInjection = Taint("DNA0007", "XPath injection", 643);
        public static readonly DiagnosticDescriptor UnsafeDeserialization = Taint("DNA0008", "Unsafe deserialization", 502);
        public static readonly DiagnosticDescriptor UnsafeDeserializationSetting = Create("DNA0008", "Unsafe deserialization", "Json.NET TypeNameHandling value '{0}' can materialize untrusted types.", 502);
        public static readonly DiagnosticDescriptor HardcodedSecret = Create("DNA0009", "Hardcoded secret", "A secret passed to '{0}' is hardcoded.", 798);
        public static readonly DiagnosticDescriptor CookieConfiguration = Create("DNA0010", "Insecure cookie configuration", "Cookie '{0}' has unsafe settings: {1}.", 614);
        public static readonly DiagnosticDescriptor ServerSideRequestForgery = Taint("DNA0011", "Server-side request forgery", 918);
        public static readonly DiagnosticDescriptor DynamicCodeExecution = Taint("DNA0012", "Dynamic code execution", 94);

        private static readonly IReadOnlyDictionary<string, int> CweById = new Dictionary<string, int>
        {
            ["DNA0001"] = 89, ["DNA0002"] = 78, ["DNA0003"] = 79, ["DNA0004"] = 22,
            ["DNA0005"] = 601, ["DNA0006"] = 90, ["DNA0007"] = 643, ["DNA0008"] = 502,
            ["DNA0009"] = 798, ["DNA0010"] = 614, ["DNA0011"] = 918, ["DNA0012"] = 94
        };

        public static bool TryGetCwe(string id, out int cwe) => CweById.TryGetValue(id, out cwe);

        private static DiagnosticDescriptor Taint(string id, string title, int cwe) =>
            Create(id, title, $"Potential {title.ToLowerInvariant()} where '{{0}}' in '{{1}}' receives untrusted data from '{{2}}' in '{{3}}'.", cwe);

        private static DiagnosticDescriptor Create(string id, string title, string message, int cwe) =>
            new DiagnosticDescriptor(
                id,
                title,
                message,
                "Security",
                DiagnosticSeverity.Warning,
                isEnabledByDefault: true,
                description: $"CWE-{cwe}. Review the reported data flow and use a context-appropriate mitigation.",
                helpLinkUri: $"https://github.com/dotnetarium/dotnetarium/blob/main/docs/rules/{id}.md",
                customTags: new[] { $"CWE-{cwe}" });
    }
}
