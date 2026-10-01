# Dotnetarium 2.x

Dotnetarium finds security issues in modern C# applications. The NuGet analyzer runs during builds; the `dotnetarium-scs` global tool scans a project or solution and can write SARIF 2.1.0. Both use the same DNA rules and configuration.

## Install

```powershell
dotnet add package Dotnetarium.Analyzers.SCS --version 2.0.0-alpha.1
dotnet tool install --global dotnetarium-scs --version 2.0.0-alpha.1
```

The analyzer targets `netstandard2.0` for the Roslyn host and uses Roslyn 5.0, which requires Visual Studio 2026 (18.0) or a compatible .NET SDK. The global tool requires the .NET 10 runtime and an SDK capable of loading the target project. The tool scans C# projects targeting .NET 8 or .NET 10; Visual Basic and .NET Framework support ended with 1.x.

## Scan

```powershell
dotnetarium-scs MyApp.sln --sarif results.sarif --cwe --fail-any-warn
```

SARIF source paths are relative to the solution or project directory by default. `--sarif-absolute-paths` retains absolute file URIs for consumers that require them. `--sdk-path` selects a versioned SDK directory when automatic SDK discovery cannot load a project. Run `dotnetarium-scs --help` for all options.

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

## License

Dotnetarium 2.x is licensed under [Apache License 2.0](LICENSE). The bundled
Roslyn sources retain their original licenses; see
[third-party notices](THIRD_PARTY_NOTICES.md).
