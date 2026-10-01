using System.Collections.Immutable;
using System.Text;
using Dotnetarium.Config;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Text;

namespace Dotnetarium.Analyzers.Tests;

public sealed class ConfigurationTests
{
    [Fact]
    public void Built_in_models_drop_legacy_deserializers_and_web_forms()
    {
        var config = new ConfigurationReader().GetBuiltinConfiguration();
        Assert.Contains(config.Sinks, sink => sink.Type == "System.Net.Http.HttpClient");
        Assert.DoesNotContain(config.Sinks, sink => sink.Type.Contains("BinaryFormatter", StringComparison.Ordinal));
        Assert.DoesNotContain(config.Sinks, sink => sink.Type.StartsWith("System.Web.", StringComparison.Ordinal));
        Assert.DoesNotContain(config.TaintSources, source => source.Type.StartsWith("System.Web.", StringComparison.Ordinal));
    }

    [Fact]
    public void Rejects_duplicate_JSON_properties()
    {
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes("{\"Version\":\"2.0\",\"Version\":\"2.0\"}"));
        using var reader = new StreamReader(stream);
        Assert.Throws<System.Text.Json.JsonException>(() =>
            new ConfigurationReader().DeserializeAndValidate<ConfigData>(reader, validate: true));
    }

    [Fact]
    public void Rejects_unknown_JSON_properties()
    {
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes("{\"Version\":\"2.0\",\"Sinkz\":[]}"));
        using var reader = new StreamReader(stream);
        Assert.Throws<System.Text.Json.JsonException>(() =>
            new ConfigurationReader().DeserializeAndValidate<ConfigData>(reader, validate: true));
    }

    [Theory]
    [InlineData("dotnetarium.json")]
    [InlineData("Dotnetarium.json")]
    public void Project_models_add_sinks_without_changing_built_ins(string fileName)
    {
        var reader = new ConfigurationReader();
        var builtin = reader.GetBuiltinConfiguration();
        var project = reader.GetProjectConfiguration(ImmutableArray.Create<AdditionalText>(new TextFile(
            fileName, """
                {"Version":"2.0","Sinks":[{"Type":"Example.Query","TaintTypes":["SqlInjection"],"Methods":[{"Name":"Execute","Arguments":["query"]}]}]}
                """)));
        var merged = new ConfigData();
        merged.Merge(builtin);
        merged.Merge(project);

        Assert.Contains(merged.Sinks, sink => sink.Type == "Example.Query");
        Assert.DoesNotContain(builtin.Sinks, sink => sink.Type == "Example.Query");
    }

    [Fact]
    public void Same_config_added_twice_is_read_once()
    {
        var file = new TextFile("dotnetarium.json", """{"Version":"2.0"}""");
        var project = new ConfigurationReader().GetProjectConfiguration(
            ImmutableArray.Create<AdditionalText>(file, file));
        Assert.Equal("2.0", project.Version);
    }

    private sealed class TextFile(string path, string text) : AdditionalText
    {
        public override string Path => path;
        public override SourceText GetText(CancellationToken cancellationToken = default) => SourceText.From(text);
    }
}
