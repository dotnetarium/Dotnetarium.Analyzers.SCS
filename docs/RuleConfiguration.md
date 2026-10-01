# Rule configuration in 2.x

The built-in models live in `Dotnetarium.Analyzers/Config/Main.json`. Place `dotnetarium.json` beside a project to extend them. The analyzer NuGet package adds it to `AdditionalFiles` automatically. The global tool finds the file beside a scanned project or solution; use `--config` to select another file. If you use the analyzer assembly without its NuGet package, include it manually:

```xml
<ItemGroup>
  <AdditionalFiles Include="dotnetarium.json" />
</ItemGroup>
```

The file must declare `"Version": "2.0"`. JSON property names are case insensitive; duplicate names are rejected. `TaintTypes` uses semantic names such as `SqlInjection`, `CrossSiteScripting`, `PathEscape`, `LdapFilterInjection`, and `LdapDnInjection`. These are internal model contexts and are independent of the public DNA diagnostic IDs.

```json
{
  "Version": "2.0",
  "TaintSources": [
    {
      "Type": "Example.Input",
      "Methods": ["Read"]
    }
  ],
  "Sinks": [
    {
      "Type": "Example.Query",
      "TaintTypes": ["SqlInjection"],
      "Methods": [
        { "Name": "Execute", "Arguments": ["query"] }
      ]
    }
  ],
  "Sanitizers": [
    {
      "Type": "Example.LdapEscaping",
      "TaintTypes": ["LdapFilterInjection"],
      "Methods": [{ "Name": "EncodeFilter" }]
    }
  ]
}
```

`Type` is the fully qualified metadata type. `IsInterface` can be set on source or sink models. `Properties` and `Methods` name members, while a sink method's `Arguments` names its risky parameters. `TaintTypes` limits a model to selected contexts; when omitted from a source, it applies to all taint contexts. A sanitizer applies only to its listed context, so LDAP filter escaping must not clear a distinguished-name flow or vice versa. For more complex entry points, transfers, and conditional sanitizers, follow the examples in `Main.json`.

Project models add to the built-ins. Configure severity and suppression with `.editorconfig` using `dotnet_diagnostic.DNAxxxx.severity`. A rule ID does not appear in `dotnetarium.json` because the analyzer maps internal contexts to DNA diagnostics.

Configuration cannot express arbitrary code flow or whole-application dependency injection resolution. Review findings involving reflection, runtime registrations, and external assemblies with the appropriate deployment context.

Built-in ASP.NET Core inputs include MVC controllers, Razor Pages, Blazor binding, and Minimal API lambdas or named handlers. Minimal API simple parameters and parameters explicitly marked `[FromRoute]`, `[FromQuery]`, `[FromHeader]`, `[FromBody]`, or `[FromForm]` are treated as request data. `[FromServices]` parameters are excluded; complex parameters without explicit binding and `[AsParameters]` aggregates are left for review rather than assumed to be request data, because service injection can use the same parameter shape.
