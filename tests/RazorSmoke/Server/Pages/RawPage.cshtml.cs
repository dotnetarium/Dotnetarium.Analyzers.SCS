using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace RazorSmoke.Server.Pages;

public class RawPageModel : PageModel
{
    [BindProperty(SupportsGet = true)] public string Bound { get; set; } = "";
    public string ParentOnly { get; set; } = "";
    public void OnGet() { }
}
