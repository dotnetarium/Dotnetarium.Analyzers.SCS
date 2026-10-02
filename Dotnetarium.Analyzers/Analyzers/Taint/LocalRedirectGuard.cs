using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace Dotnetarium.Analyzers.Taint
{
    internal static class LocalRedirectGuard
    {
        public static bool Protects(Location sink, Compilation compilation)
        {
            if (!sink.IsInSource || sink.SourceTree == null)
                return false;

            var model = compilation.GetSemanticModel(sink.SourceTree);
            var node = sink.SourceTree.GetRoot().FindNode(sink.SourceSpan);
            var argument = node.AncestorsAndSelf().OfType<ArgumentSyntax>().FirstOrDefault();
            if (argument?.Expression is not IdentifierNameSyntax redirectValue)
                return false;

            var redirectedSymbol = model.GetSymbolInfo(redirectValue).Symbol;
            if (redirectedSymbol is not (ILocalSymbol or IParameterSymbol))
                return false;

            foreach (var branch in argument.Ancestors().OfType<IfStatementSyntax>())
            {
                if (!IsOnlyStatementInTrueBranch(branch.Statement, argument))
                    continue;

                if (Unwrap(branch.Condition) is not InvocationExpressionSyntax check ||
                    check.ArgumentList.Arguments.Count != 1 ||
                    Unwrap(check.ArgumentList.Arguments[0].Expression) is not IdentifierNameSyntax checkedValue ||
                    !SymbolEqualityComparer.Default.Equals(
                        redirectedSymbol, model.GetSymbolInfo(checkedValue).Symbol))
                    continue;

                if (model.GetSymbolInfo(check).Symbol is not IMethodSymbol method ||
                    method.Name != "IsLocalUrl" || method.Parameters.Length != 1)
                    continue;

                var owner = method.ContainingType.ToDisplayString();
                if (owner == "Microsoft.AspNetCore.Mvc.IUrlHelper" ||
                    owner == "Microsoft.AspNetCore.Http.HttpResults.RedirectHttpResult")
                    return true;
            }

            return false;
        }

        private static bool IsOnlyStatementInTrueBranch(StatementSyntax statement, SyntaxNode sink)
        {
            if (statement is BlockSyntax block)
            {
                if (block.Statements.Count != 1)
                    return false;
                statement = block.Statements[0];
            }

            // Keep this narrow: an intervening statement or another expression
            // could replace the checked value before the redirect executes.
            var call = sink.AncestorsAndSelf().OfType<InvocationExpressionSyntax>().FirstOrDefault();
            return call != null && (statement is ReturnStatementSyntax returned &&
                returned.Expression == call || statement is ExpressionStatementSyntax expression &&
                expression.Expression == call);
        }

        private static ExpressionSyntax Unwrap(ExpressionSyntax expression)
        {
            while (expression is ParenthesizedExpressionSyntax parentheses)
                expression = parentheses.Expression;
            return expression;
        }
    }
}
