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

Built-in ASP.NET Core inputs include MVC controllers, Razor Pages, Blazor binding, Minimal API lambdas or named handlers, generated gRPC service overrides, and gRPC server interceptor overrides. Minimal APIs model explicit request binding, parsable parameters, upload files, and body streams. `MapPost`, `MapPut`, and `MapPatch` also infer JSON body inputs when no visible service registration or custom binder takes precedence. Explicit service attributes and visible service registrations are excluded. Mixed `[AsParameters]` aggregates preserve separate request and service members. Registrations hidden in external DI setup require an explicit service attribute to avoid assuming an implicit body. Custom binders and implicit bodies on `MapMethods` are not inferred. For gRPC details and limits, see [gRPC taint analysis](grpc-taint.md).

SignalR hub methods and client upload streams are also entry points. Their binding model excludes explicit and visible implicit service parameters; see [SignalR taint analysis](signalr-taint.md) for supported registrations and limits.
