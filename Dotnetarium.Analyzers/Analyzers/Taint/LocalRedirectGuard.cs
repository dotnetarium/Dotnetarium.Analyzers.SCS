using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Operations;

namespace Dotnetarium.Analyzers.Taint
{
    internal static class LocalRedirectGuard
    {
        public static bool Protects(Location sink, Compilation compilation) =>
            BoundaryValidation.Guarded(sink, compilation, (condition, symbol, outcome) =>
                outcome && condition is IInvocationOperation call && call.TargetMethod.Name == "IsLocalUrl" &&
                call.Arguments.Length == 1 &&
                (call.TargetMethod.ContainingType.ToDisplayString() is
                    "Microsoft.AspNetCore.Mvc.IUrlHelper" or "Microsoft.AspNetCore.Http.HttpResults.RedirectHttpResult") &&
                SymbolEqualityComparer.Default.Equals(
                    BoundaryValidation.ReferencedSymbol(BoundaryValidation.Unwrap(call.Arguments[0].Value)), symbol));
    }
}
