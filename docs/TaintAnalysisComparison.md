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

No upstream interprocedural visitor has been copied into the analyzer engine
on this branch. The updated reference includes a state-trimming rewrite spread
across `AnalysisEntityDataFlowOperationVisitor`, `DataFlowOperationVisitor`, and
four concrete analysis visitors. That is a coupled flow-semantic change. It
should be ported selectively with Dotnetarium source/sink, sanitizer, flow-path,
and performance regressions in place, including the redirect cases that failed
during the local reference integration.

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

### 1. Correct confirmed false negatives before importing more flow code

The custom `VisitInterpolatedString` returns an untainted value as soon as **any**
interpolation has a safe primitive type. A .NET 10 smoke project using the
branch's analyzer DLL detected `Redirect($"{tainted}")`, but missed both
`Redirect($"{123}/{tainted}")` and `Redirect($"{tainted}/{123}")`.
Sanitization must apply to the individual interpolation, and the full string
must remain tainted if any other part is tainted. Retain the existing tests
that keep numeric-only formatting untainted. Also replace the `throw new
Exception` on an unexpected interpolation operation type with a conservative
taint result; a compiler tree change should not crash the analyzer.

The same smoke project detected a tainted URL passed as a helper's argument,
but missed a URL saved to a static field before a helper read it, and a URL
captured by a local function. These are focused regression cases for any
interprocedural rewrite. The smoke test demonstrates current behavior, not
that the upstream code is already proven to fix each case.

### 2. Port the upstream interprocedural rewrite selectively

The upstream change is potentially valuable. It tracks callee-reachable
static members, local-function captures, aliases, and referenced child
entities when trimming state. Dotnetarium's current implementation skips
trimming for lambdas/local functions and uses an older reachability test for
ordinary calls. A port could improve both precision and performance, but it
changes a shared data-flow contract across multiple analyses. Keep
Dotnetarium's taint visitor, symbol maps, rule configuration, and diagnostic
formatting; adapt the shared flow contract around them. Measure detection and
runtime before and after the port. The reference's four redirect regressions
were traced to the separate sink-map collision fixed in this PR; rerun them
against the engine as a gate rather than assuming equivalence.

### 3. Simplify once the behavior is pinned down

- `TaintAnalyzer` loops over `rootOperationsNeedingAnalysis`, but the loop
  variable is unused and each iteration calls analysis with the same CFG and
  maps. Verify the operation-block cases, then run the analysis once per block.
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

**Recommendation:** keep the Dotnetarium engine as the product baseline. Take
upstream's flow fixes only where a failing case or measured improvement shows
their value. Fix the confirmed interpolation bug first, then port the
interprocedural state handling behind source/sink and SARIF regression tests.
