# Dotnetarium 2.x

Dotnetarium finds security issues in modern C# applications. The NuGet analyzer runs during builds; the `dotnetarium` global tool scans a project or solution and can write SARIF 2.1.0. Both use the same DNA rules and configuration.

## Install

Once version 2.0.0 is available on NuGet.org, install both packages:

```powershell
dotnet add package Dotnetarium.Analyzers --version 2.0.0
dotnet tool install --global dotnetarium --version 2.0.0
```

The analyzer targets `netstandard2.0` for the Roslyn host and uses Roslyn 5.0, which requires Visual Studio 2026 (18.0) or a compatible .NET SDK. The global tool requires the .NET 10 runtime and an SDK capable of loading the target project. The tool scans C# projects targeting .NET 8 or .NET 10; Visual Basic and .NET Framework support ended with 1.x.

## Scan

```powershell
dotnetarium MyApp.sln --sarif results.sarif --cwe --fail-any-warn
```

SARIF source paths are relative to the solution or project directory by default. `--sarif-absolute-paths` retains absolute file URIs for consumers that require them. `--sdk-path` selects a versioned SDK directory when automatic SDK discovery cannot load a project. Run `dotnetarium --help` for all options.

## Moving from 1.x

The 1.x line is preserved on the `release/1.x` branch. Version 2 uses new
package IDs and a new command: replace `Dotnetarium.Analyzers.SCS` with
`Dotnetarium.Analyzers` and `dotnetarium-scs` with `dotnetarium`. Rules have new
`DNA` IDs, so update `.editorconfig` and any SARIF filters. Replace legacy YAML
rule extensions with `Dotnetarium.json`. The 2.x analyzer supports modern C#;
the tool needs a .NET 10 runtime and scans .NET 8 or .NET 10 projects.

## Rules

| ID | Finding |
| --- | --- |
| DNA0001 | SQL injection |
| DNA0002 | OS command injection |
| DNA0003 | Cross-site scripting |
| DNA0004 | Path escape, including archive extraction |
| DNA0005 | Open redirect |
| DNA0006 | LDAP injection (filter and distinguished name contexts) |
| DNA0007 | XPath injection |
| DNA0008 | Unsafe deserialization |
| DNA0009 | Hardcoded secret |
| DNA0010 | Insecure cookie configuration (Secure, HttpOnly, SameSite) |
| DNA0011 | Server-side request forgery |
| DNA0012 | Dynamic code execution |

DNA IDs start afresh in 2.x. CWE numbers are grouping metadata, not rule IDs. See [rule configuration](docs/RuleConfiguration.md) and the individual [rule notes](docs/rules) for examples and limitations.

Add `Dotnetarium.json` as an `AdditionalFiles` item to extend the built-in source, sink, sanitizer, and transfer models. Configuration is JSON parsed with `System.Text.Json`. Use `.editorconfig` for diagnostic severity:

```ini
[*.cs]
dotnet_diagnostic.DNA0010.severity = error
```

The repository contains the analyzer, global tool, xUnit tests, provider and
Razor smoke checks, and the selected Roslyn flow utilities. See the
[architecture notes](docs/Architecture.md) for how they fit together.
Maintainers can follow the [release instructions](docs/Releasing.md).

## License

Dotnetarium 2.x is licensed under [Apache License 2.0](LICENSE). The bundled
Roslyn sources retain their original licenses; see
[third-party notices](THIRD_PARTY_NOTICES.md).
