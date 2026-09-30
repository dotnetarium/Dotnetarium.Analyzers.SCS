var builder = WebApplication.CreateBuilder(args);
builder.Services.AddRazorPages();
builder.Services.AddRazorComponents();
var app = builder.Build();
app.MapRazorPages();
app.Run();
