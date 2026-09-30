# Three-way taint analysis comparison

This compares the updated local `dotnetarium/analyzers` reference (based on
`dotnet/sdk` commit `43ccbc79`), the Dotnetarium analyzer engine on this branch,
and the `DotnetariumSCS` global tool. The reference is a source of upstream flow
fixes; it is not used at runtime by either Dotnetarium package.

| Component | Role | Taint implementation in use |
| --- | --- | --- |
| `analyzers` | Local copy of official .NET/Roslyn analyzer utilities | Updated upstream flow code for comparison only. |
| `Dotnetarium.Analyzers.SCS` (this PR) | NuGet analyzer package and actual Dotnetarium taint engine | Forked Roslyn flow analysis plus Dotnetarium's `TaintAnalyzer`, configuration, and SCS rules. |
| `DotnetariumSCS` | .NET global tool that loads and runs the analyzer package | Its .NET 8/10 project currently references published `Dotnetarium.Analyzers.SCS` **1.1.0**. It also maps diagnostic `AdditionalLocations` to SARIF `relatedLocations`. |

Consequently, this PR has no effect on the published global tool. Shipping its
engine changes requires a new analyzer package version and then a tool update
that consumes that version. The standalone analyzer NuGet package can be used
without the tool.

## Dotnetarium behavior to preserve

The upstream and Dotnetarium taint directories contain the same 51 filenames,
but matching filenames do not imply equivalent behavior. A direct diff of the
taint visitor shows Dotnetarium-specific handling for:

- tainted field references, in addition to upstream property sources;
- configurable method and parameter sink matching, and parameter-level sink
  locations used in SCS diagnostics;
- conditional sanitizers that inspect points-to and value-content results;
- conversion and string-interpolation treatment;
- transfer/sanitization results for `ref` or `out` arguments when a call is not
  analyzed interprocedurally.

`DotnetariumSCS/Analyzers/Taint/TaintAnalyzer.cs` in the analyzer repository
adds the SCS rule set, audit mode, configurable method and local-function call
depth, and source-to-sink locations in `Diagnostic.AdditionalLocations`.
`DotnetariumSCS/Config/Main.yml` defines Dotnetarium's entry points, sources,
sanitizers, and sinks. The global tool discovers analyzers from this package,
runs them over MSBuild compilations, and writes those locations as SARIF flow
context. Replacing the taint visitor or configuration wholesale would change
the product's detection and reporting behavior.

## What this PR changes

`TaintedDataSymbolMap<TInfo>` previously stored one source, sanitizer, or sink
definition per type. This PR retains all definitions for a type. For example,
`System.Web.HttpResponse` has both redirect and file-path sink definitions;
one must not overwrite the other. The change keeps Dotnetarium's interface
lookup and field-source flag, and adds a test for both insertion orders.

The branch now ports the upstream state-trimming rewrite across
`AnalysisEntityDataFlowOperationVisitor`, `DataFlowOperationVisitor`, and four
concrete analysis visitors. It keeps Dotnetarium's taint visitor and rule
configuration. The port uses `Children` for Roslyn 3.11 compatibility and
retains the analyzer's existing skip-analysis option API. The interpolation
visitor is separately fixed so a safe numeric part cannot clear taint from
another part of the same string. The operation-block analyzer now executes
the same CFG once rather than once per recorded root.

## Modern language features

The reference uses `IOperation.ChildOperations` in places where Dotnetarium
uses `Children`. This is an API modernization, not by itself a new taint rule.
The analyzer engine currently targets Roslyn 3.11 APIs, while the tool's
workspace packages are 4.9.2; compatibility must be checked at the analyzer
package boundary before adopting newer API calls.

With the current analyzer loaded by the .NET 10 compiler, a smoke project
produced `SCS0027` for a direct redirect, a C# collection expression held in
an array and indexed, and an interpolated string, inside a class with a primary
constructor. These cases show that the older API can already see these flows;
they do not establish coverage for every newer C# construct. Add a focused
regression case when a concrete false negative is identified.

The legacy analyzer test project targets .NET Framework 4.8. A modern test
harness would make newer syntax regressions runnable in CI independently of
that test assembly.

## Engine review and proposed order of work

### 1. Correct confirmed false negatives

Previously, the custom `VisitInterpolatedString` returned an untainted value
as soon as **any** interpolation had a safe primitive type. A .NET 10 smoke
project detected `Redirect($"{tainted}")`, but missed both
`Redirect($"{123}/{tainted}")` and `Redirect($"{tainted}/{123}")`.
The fix sanitizes each interpolated part individually and keeps the full
string tainted when another part is tainted. It also removes a throw on an
unexpected interpolation operation type. Existing numeric-only cases and new
mixed-string cases are covered by the legacy test suite.

The same smoke project initially detected a tainted URL passed as a helper's
argument, but missed a URL saved to a static field before a helper read it,
and a URL captured by a local function. The taint visitor discarded callee
sink findings whenever the call itself had no tainted argument. It now merges
callee findings regardless of argument taint. Both cases are detected, and
they have focused regression tests in `OpenRedirectAnalyzerTest`.

### 2. Evaluate the shared upstream interprocedural port

The upstream change tracks callee-reachable static members, local-function
captures, aliases, and referenced child entities when trimming state. A
controlled comparison showed why this selective port belongs in the engine:
with the taint visitor fix but the old shared flow files, the captured-local
case was detected while the static-field helper case remained undetected;
with the upstream flow files restored, both were detected. The full Windows
suite passes with the final combination. Runtime measurements on larger
projects remain useful before release. The reference's four redirect
regressions were traced to the separate sink-map collision fixed in this PR.

### 3. Simplify once the behavior is pinned down

- `TaintAnalyzer` previously looped over `rootOperationsNeedingAnalysis` while
  ignoring the loop variable and analyzing the same CFG each time. The branch
  now runs that analysis once per operation block.
- SARIF path reconstruction filters operations by whether their *syntax text*
  contains text from an unrelated interprocedural result, and selects the last
  child result with a sink. Replace this with operation/result identity and an
  explicit path for each source-to-sink pair. Preserve the existing
  `AdditionalLocations` contract consumed by the global tool.
- The taint visitor stores every abstract value because of an old extension
  method regression, whereas upstream stores only tainted or already tracked
  values. Keep the regression, benchmark memory and runtime, and remove the
  extra state only if the result remains correct.
- Move focused modern-syntax and interprocedural cases to a runnable modern
  test harness. The current .NET Framework test suite covers many configured
  sinks and interpolation forms, but cannot serve as the only gate for new
  compiler operation trees.

**Recommendation:** keep the Dotnetarium engine as the product baseline. The
interpolation, sink-map, and callee-result fixes close confirmed detection
gaps. Keep the selective upstream flow port because it is also needed for the
static-field case, while preserving the Dotnetarium taint rules and reporting.
