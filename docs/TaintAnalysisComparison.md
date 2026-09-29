# Taint analysis comparison

Compared this repository with the locally updated `dotnetarium/analyzers` reference copy, based on `dotnet/sdk` commit `43ccbc79` (September 29, 2026).

## Keep Dotnetarium behavior

Dotnetarium's taint visitor adds field sources, configurable method and parameter matching, value-dependent sanitizers, conversion and interpolation handling, and richer source-to-sink locations. The analyzer also supports configurable interprocedural depth, audit mode, and SARIF taint-flow visualization. A wholesale replacement with the reference visitor would remove these behaviors.

## Changes worth taking

- **Included:** Preserve every taint source, sanitizer, or sink definition for a type. Both the reference and Dotnetarium previously kept only one definition, so file-path sinks on `System.Web.HttpResponse` could displace redirect sinks depending on enumeration order.
- **Evaluate separately:** The reference has a newer interprocedural state-trimming algorithm. It changes several coupled flow-analysis visitors and needs focused Dotnetarium correctness and performance tests before adoption.
- **Do not copy as a language fix:** The reference uses `IOperation.ChildOperations` where Dotnetarium uses `Children`. Dotnetarium currently compiles against Roslyn 3.11, which does not expose the newer API. This is a traversal API modernization, not evidence of a missing language feature.

## Modern syntax check

With the current analyzer loaded by the .NET 10 compiler, a smoke project produced `SCS0027` for all three cases: a direct redirect, a C# collection expression held in an array and then indexed, and an interpolated string. The cases were inside a class with a primary constructor. These examples do not establish coverage for every newer C# construct; add focused tests for any reported false negatives.

The existing test project targets .NET Framework 4.8. A modern test harness would let these syntax cases run in CI independently of the older test assembly.
