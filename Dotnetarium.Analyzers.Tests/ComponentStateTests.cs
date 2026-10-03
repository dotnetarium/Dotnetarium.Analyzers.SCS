using Dotnetarium.Analyzers.Taint;

namespace Dotnetarium.Analyzers.Tests;

public sealed class ComponentStateTests
{
    [Theory]
    [InlineData("builder.OpenElement(0, \"input\"); builder.AddAttribute(1, \"onchange\", EventCallback.Factory.CreateBinder<string>(this, value => text = value, text)); builder.CloseElement();", 1)]
    [InlineData("builder.OpenComponent<InputText>(0); builder.AddComponentParameter(1, \"ValueChanged\", RuntimeHelpers.CreateInferredEventCallback(this, (string value) => text = value, text)); builder.CloseComponent();", 1)]
    [InlineData("builder.OpenComponent<Other>(0); builder.AddComponentParameter(1, \"onchange\", EventCallback.Factory.Create<string>(this, value => text = value)); builder.CloseComponent();", 0)]
    public async Task Generated_binding_callbacks_require_DOM_or_framework_input_components(string binding, int expected)
    {
        var findings = await FrameworkProbe.Analyze("""
            using Microsoft.AspNetCore.Components;
            using Microsoft.AspNetCore.Components.CompilerServices;
            using Microsoft.AspNetCore.Components.Forms;
            using Microsoft.AspNetCore.Components.Rendering;
            public sealed class Other : ComponentBase { [Parameter] public EventCallback<string> onchange { get; set; } }
            public sealed class Parent : ComponentBase {
                private string text = "fixed";
                protected override void BuildRenderTree(RenderTreeBuilder builder) {
            """ + binding + "builder.AddMarkupContent(3, text); }}", new XssTaintAnalyzer());
        Assert.Equal(expected, findings.Length);
    }

    [Theory]
    [InlineData("value = args.Value.ToString();", "builder.AddMarkupContent(3, value);", 1)]
    [InlineData("value = args.Value.ToString(); value = \"fixed\";", "builder.AddMarkupContent(3, value);", 0)]
    [InlineData("value = \"fixed\";", "builder.AddMarkupContent(3, value);", 0)]
    [InlineData("value = args.Value.ToString();", "builder.AddContent(3, value);", 0)]
    [InlineData("value = args.Value.ToString();", "builder.AddContent(3, (MarkupString)value);", 1)]
    [InlineData("value = args.Value.ToString();", "builder.OpenComponent<Child>(3); builder.AddComponentParameter(4, \"Value\", value); builder.CloseComponent();", 1)]
    [InlineData("value = \"fixed\";", "builder.OpenComponent<Child>(3); builder.AddComponentParameter(4, \"Value\", value); builder.CloseComponent();", 0)]
    public async Task Browser_events_flow_through_state_and_child_parameters_into_raw_rendering(string handler, string render, int expected)
    {
        var findings = await FrameworkProbe.Analyze("""
            using Microsoft.AspNetCore.Components;
            using Microsoft.AspNetCore.Components.Rendering;
            public sealed class Parent : ComponentBase
            {
                private string value = "fixed";
                private void Changed(ChangeEventArgs args) {
            """ + handler + """
                }
                protected override void BuildRenderTree(RenderTreeBuilder builder)
                {
                    builder.OpenElement(0, "input");
                    builder.AddAttribute(1, "onchange", EventCallback.Factory.Create<ChangeEventArgs>(this, Changed));
                    builder.CloseElement();
            """ + render + """
                }
            }
            public sealed class Child : ComponentBase
            {
                [Parameter] public string Value { get; set; } = "fixed";
                protected override void BuildRenderTree(RenderTreeBuilder builder) => builder.AddMarkupContent(0, Value);
            }
            """, new XssTaintAnalyzer());
        Assert.True(expected == findings.Length, $"{handler} / {render}: expected {expected}, actual {findings.Length}");
        Assert.All(findings, finding => Assert.Contains(finding.AdditionalLocations, location => location.SourceTree!.GetText().ToString(location.SourceSpan).Contains("args.Value")));
    }
}
