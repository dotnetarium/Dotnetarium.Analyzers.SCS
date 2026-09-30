using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Rendering;

namespace RazorSmoke.Client;

[Route("/manual")]
public class ManualComponent : ComponentBase
{
    [SupplyParameterFromQuery] public string? Query { get; set; }

    protected override void BuildRenderTree(RenderTreeBuilder builder)
    {
        builder.AddMarkupContent(0, Query);
        builder.AddContent(1, new MarkupString(Query ?? ""));
        builder.AddContent(2, (MarkupString)(Query ?? ""));
        builder.AddContent(3, Query); // Encoded string output is safe.
    }
}
