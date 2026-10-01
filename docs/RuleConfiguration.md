# Rule configuration in 2.x

The built-in models live in `DotnetariumSCS/Config/Main.json`. Projects can extend them with `Dotnetarium.json`. The global tool accepts the same file through `--config`. The analyzer reads it when the project includes:

```xml
<ItemGroup>
  <AdditionalFiles Include="Dotnetarium.json" />
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
      "Type": "Example.SqlEscaping",
      "TaintTypes": ["SqlInjection"],
      "Methods": [{ "Name": "Escape" }]
    }
  ]
}
```

`Type` is the fully qualified metadata type. `IsInterface` can be set on source or sink models. `Properties` and `Methods` name members, while a sink method's `Arguments` names its risky parameters. `TaintTypes` limits a model to selected contexts; when omitted from a source, it applies to all taint contexts. A sanitizer applies only to its listed context, so LDAP filter escaping must not clear a distinguished-name flow or vice versa. For more complex entry points, transfers, and conditional sanitizers, follow the examples in `Main.json`.

Project models add to the built-ins. Configure severity and suppression with `.editorconfig` using `dotnet_diagnostic.DNAxxxx.severity`. A rule ID does not appear in `Dotnetarium.json` because the analyzer maps internal contexts to DNA diagnostics.

Configuration cannot express arbitrary code flow or whole-application dependency injection resolution. Review findings involving reflection, runtime registrations, and external assemblies with the appropriate deployment context.
