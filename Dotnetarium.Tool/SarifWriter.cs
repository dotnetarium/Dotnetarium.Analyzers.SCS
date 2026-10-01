using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.CodeAnalysis;
using Dotnetarium.Analyzers;

namespace Dotnetarium.Tool;

internal static class SarifWriter
{
    internal static async Task WriteAsync(string output, string target, IReadOnlyList<Diagnostic> diagnostics,
        bool absolutePaths)
    {
        var root = Path.GetDirectoryName(Path.GetFullPath(target))!;
        var rules = diagnostics.Select(diagnostic => diagnostic.Descriptor)
            .GroupBy(descriptor => descriptor.Id)
            .Select(group => group.First())
            .OrderBy(descriptor => descriptor.Id, StringComparer.Ordinal)
            .Select(descriptor =>
            {
                var rule = new JsonObject
                {
                    ["id"] = descriptor.Id,
                    ["name"] = descriptor.Title.ToString(),
                    ["shortDescription"] = new JsonObject { ["text"] = descriptor.Title.ToString() },
                    ["fullDescription"] = new JsonObject { ["text"] = descriptor.Description.ToString() },
                    ["defaultConfiguration"] = new JsonObject { ["level"] = "warning" }
                };
                if (descriptor.HelpLinkUri != null) rule["helpUri"] = descriptor.HelpLinkUri;
                if (DnaRuleCatalog.TryGetCwe(descriptor.Id, out var cwe))
                    rule["properties"] = new JsonObject
                    {
                        ["tags"] = new JsonArray(JsonValue.Create($"CWE-{cwe}"))
                    };
                return rule;
            });

        var results = diagnostics.Select(diagnostic => CreateResult(diagnostic, root, absolutePaths)).ToArray();
        var run = new JsonObject
        {
            ["tool"] = new JsonObject
            {
                ["driver"] = new JsonObject
                {
                    ["name"] = "Dotnetarium",
                    ["informationUri"] = "https://github.com/dotnetarium/Dotnetarium.Analyzers.SCS",
                    ["rules"] = new JsonArray(rules.Select(rule => (JsonNode?)rule).ToArray())
                }
            },
            ["results"] = new JsonArray(results.Select(result => (JsonNode?)result).ToArray())
        };

        if (!absolutePaths)
        {
            var uri = new Uri(root.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar).AbsoluteUri;
            run["originalUriBaseIds"] = new JsonObject
            {
                ["%SRCROOT%"] = new JsonObject { ["uri"] = uri }
            };
        }

        var sarif = new JsonObject
        {
            ["$schema"] = "https://json.schemastore.org/sarif-2.1.0.json",
            ["version"] = "2.1.0",
            ["runs"] = new JsonArray(run)
        };

        var path = Path.GetFullPath(output);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        await File.WriteAllTextAsync(path, sarif.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
    }

    private static JsonObject CreateResult(Diagnostic diagnostic, string root, bool absolutePaths)
    {
        var result = new JsonObject
        {
            ["ruleId"] = diagnostic.Id,
            ["level"] = diagnostic.Severity == DiagnosticSeverity.Error ? "error" : "warning",
            ["message"] = new JsonObject { ["text"] = diagnostic.GetMessage() },
            ["locations"] = new JsonArray(CreateLocation(diagnostic.Location, root, absolutePaths))
        };

        var related = diagnostic.AdditionalLocations
            .Where(location => location.IsInSource && location.SourceTree != null)
            .Select((location, index) => new JsonObject
            {
                ["id"] = index + 1,
                ["physicalLocation"] = CreatePhysicalLocation(location, root, absolutePaths)
            });
        if (diagnostic.AdditionalLocations.Count > 0)
            result["relatedLocations"] = new JsonArray(related.Select(location => (JsonNode?)location).ToArray());

        if (diagnostic.Properties.TryGetValue("dotnetarium.flow", out var marker) && marker == "true" &&
            diagnostic.AdditionalLocations.Count >= 2 &&
            diagnostic.AdditionalLocations.All(location => location.IsInSource && location.SourceTree != null) &&
            diagnostic.AdditionalLocations[^1].Equals(diagnostic.Location))
        {
            var steps = diagnostic.AdditionalLocations
                .Select(location => new JsonObject
                {
                    ["location"] = CreateLocation(location, root, absolutePaths)
                });
            result["codeFlows"] = new JsonArray(new JsonObject
            {
                ["threadFlows"] = new JsonArray(new JsonObject
                {
                    ["locations"] = new JsonArray(steps.Select(step => (JsonNode?)step).ToArray())
                })
            });
        }
        return result;
    }

    private static JsonObject CreateLocation(Location location, string root, bool absolutePaths) =>
        new JsonObject { ["physicalLocation"] = CreatePhysicalLocation(location, root, absolutePaths) };

    private static JsonObject CreatePhysicalLocation(Location location, string root, bool absolutePaths)
    {
        var span = location.GetLineSpan();
        var artifact = new JsonObject
        {
            ["uri"] = absolutePaths
                ? new Uri(Path.GetFullPath(span.Path)).AbsoluteUri
                : string.Join("/", Path.GetRelativePath(root, span.Path).Replace('\\', '/').Split('/')
                    .Select(Uri.EscapeDataString))
        };
        if (!absolutePaths) artifact["uriBaseId"] = "%SRCROOT%";

        return new JsonObject
        {
            ["artifactLocation"] = artifact,
            ["region"] = new JsonObject
            {
                ["startLine"] = span.StartLinePosition.Line + 1,
                ["startColumn"] = span.StartLinePosition.Character + 1,
                ["endLine"] = span.EndLinePosition.Line + 1,
                ["endColumn"] = span.EndLinePosition.Character + 1
            }
        };
    }
}
