# Architecture

The analyzer package and the global tool share the same rule catalog and taint engine.
The analyzer targets `netstandard2.0` so Roslyn can load it during a build. The
.NET 10 tool loads C# projects through MSBuild, runs the same analyzers, and can
write SARIF 2.1.0. The tool supports projects targeting .NET 8 or .NET 10.

## Taint models

`Dotnetarium.Analyzers/Config/Main.json` contains the built-in source, sink,
sanitizer, and transfer models. Projects can extend those models with a
`dotnetarium.json` additional file; the tool finds it beside a project or solution and accepts an override with `--config`.
The JSON schema and examples are in [RuleConfiguration.md](RuleConfiguration.md).
Public diagnostics use sequential `DNA` IDs. CWE numbers are metadata.

## Flow engine

The `Roslyn/` directory holds the selected upstream analyzer utilities used
by the engine, including interprocedural flow analysis. Dotnetarium's own
taint visitor, DI registration narrowing, rules, and diagnostic reporting
remain in this repository. The separate `dotnetarium/analyzers` repository is
reference material and is not a runtime dependency.

The engine attaches source-to-sink witnesses to diagnostics. The tool emits
complete witnesses as SARIF `codeFlows`. Rule descriptions appear once in the
SARIF rule table; findings reference those rules by ID and index. Source paths
are relative to the scanned project or solution.

Interface dispatch considers implementations present in the source. For
constructor-injected ASP.NET Core controllers, unambiguous built-in
`IServiceCollection` registrations can narrow the targets. Factories,
conditional registrations, and unknown container behavior keep a wider set of
possible targets; the analyzer does not execute dependency injection.

## Engine limitation: mutable interface fields

When a field is typed as an interface and can be reassigned, the engine may
consider every implementation of that interface in the scanned project. A
finding can therefore point into an unsafe implementation even when the field
starts with a safe null object or dummy implementation and the scan finds no
assignment to the unsafe one. The finding represents a possible dispatch
target; it does not prove that the unsafe implementation is assigned at run
time. This is especially relevant to public fields, which other code can
replace.

```csharp
public IRepo Repo = new NullRepo(); // Mutable: another IRepo may be assigned.

public void Search(string input) => Repo.Search(input);
```

If the default implementation is intended to remain in place, make the field
`readonly` (preferably also `private`), or give it the concrete implementation
type:

```csharp
private readonly IRepo _repo = new NullRepo();
```

The engine can then narrow the call to that implementation. If the field
is intentionally replaceable, review the finding and its possible assignments;
do not treat the initializer alone as proof that the call is safe. For
background on why runtime dispatch and unseen writes complicate static data
flow, see [CodeQL's data-flow overview](https://codeql.github.com/docs/writing-codeql-queries/about-data-flow-analysis/).

## Verification

`Dotnetarium.Analyzers.Tests/` contains xUnit tests for rules and model
coverage. `tests/ModernSinkSmoke/` checks real provider APIs,
`tests/RazorSmoke/` checks Razor and Blazor cases, and `tests/CliSmoke/`
installs both packed NuGet packages and scans .NET 8 and .NET 10 fixtures.
The build workflow runs the full suite on Windows and a packaged CLI smoke
check on Linux.
