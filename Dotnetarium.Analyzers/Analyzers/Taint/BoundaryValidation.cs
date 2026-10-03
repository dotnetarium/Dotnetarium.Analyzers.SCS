using System;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Operations;

namespace Dotnetarium.Analyzers.Taint
{
    /// <summary>Only consuming branches and stable values establish validation, never ignored calls.</summary>
    internal static class BoundaryValidation
    {
        internal static IOperation? SinkValue(Location sink, Compilation compilation)
        {
            if (sink.SourceTree == null) return null;
            var node = sink.SourceTree.GetRoot().FindNode(sink.SourceSpan);
            var model = compilation.GetSemanticModel(sink.SourceTree);
            if (node.AncestorsAndSelf().OfType<ArgumentSyntax>().FirstOrDefault() is { } argument) return model.GetOperation(argument.Expression);
            if (node.AncestorsAndSelf().OfType<AssignmentExpressionSyntax>().FirstOrDefault() is { } assignment) return model.GetOperation(assignment.Right);
            return null;
        }

        internal static bool Guarded(Location sink, Compilation compilation, Func<IOperation, ISymbol, bool, bool> validates)
        {
            var value = Unwrap(SinkValue(sink, compilation));
            var symbol = ReferencedSymbol(value);
            if (symbol is not (ILocalSymbol or IParameterSymbol) || value == null || sink.SourceTree == null) return false;
            var node = value.Syntax;
            var model = compilation.GetSemanticModel(sink.SourceTree);
            var scope = node.Ancestors().TakeWhile(ancestor => ancestor is not (BaseMethodDeclarationSyntax or LambdaExpressionSyntax or LocalFunctionStatementSyntax)).ToArray();
            foreach (var branch in scope.OfType<IfStatementSyntax>())
            {
                bool? outcome = branch.Statement.Span.Contains(node.Span) ? true : branch.Else?.Statement.Span.Contains(node.Span) == true ? false : null;
                if (outcome.HasValue && model.GetOperation(branch.Condition) is { } condition && Requires(condition, outcome.Value) &&
                    StableBetween(branch.Condition, node)) return true;
            }
            foreach (var block in scope.OfType<BlockSyntax>())
            {
                var statement = block.Statements.FirstOrDefault(statement => statement.Span.Contains(node.Span));
                if (statement == null) continue;
                foreach (var guard in block.Statements.TakeWhile(previous => previous != statement).OfType<IfStatementSyntax>())
                    if (guard.Else == null && Exits(guard.Statement) && model.GetOperation(guard.Condition) is { } condition &&
                        Requires(condition, false) && StableBetween(guard.Condition, node)) return true;
            }
            return false;

            bool Requires(IOperation condition, bool outcome)
            {
                condition = Unwrap(condition)!;
                if (condition is IUnaryOperation { OperatorKind: UnaryOperatorKind.Not, OperatorMethod: null } unary) return Requires(unary.Operand, !outcome);
                if (condition is IBinaryOperation { OperatorMethod: null } binary)
                {
                    if (binary.OperatorKind == BinaryOperatorKind.ConditionalAnd) return outcome && (Requires(binary.LeftOperand, true) || Requires(binary.RightOperand, true));
                    if (binary.OperatorKind == BinaryOperatorKind.ConditionalOr) return !outcome && (Requires(binary.LeftOperand, false) || Requires(binary.RightOperand, false));
                }
                return validates(condition, symbol, outcome);
            }

            bool StableBetween(SyntaxNode checkedAt, SyntaxNode consumedAt)
            {
                var owner = checkedAt.Ancestors().FirstOrDefault(ancestor => ancestor is BaseMethodDeclarationSyntax or LambdaExpressionSyntax);
                if (owner == null || owner.DescendantNodes().OfType<GotoStatementSyntax>().Any()) return false;
                foreach (var syntax in owner.DescendantNodes())
                {
                    var operation = model.GetOperation(syntax);
                    bool writes = operation is IAssignmentOperation assignment && SymbolEqualityComparer.Default.Equals(ReferencedSymbol(Unwrap(assignment.Target)), symbol) ||
                        operation is IArgumentOperation argument && argument.Parameter?.RefKind is RefKind.Ref or RefKind.Out &&
                            SymbolEqualityComparer.Default.Equals(ReferencedSymbol(Unwrap(argument.Value)), symbol);
                    if (writes && (syntax.SpanStart >= checkedAt.Span.End && syntax.SpanStart < consumedAt.Span.End ||
                        syntax.Ancestors().Any(ancestor => ancestor is LambdaExpressionSyntax or LocalFunctionStatementSyntax))) return false;
                }
                return true;
            }
        }

        internal static bool HasConstantAllowlist(Location sink, Compilation compilation) => Guarded(sink, compilation, (condition, symbol, outcome) =>
        {
            if (condition is IBinaryOperation { OperatorMethod: null } equality &&
                (outcome && equality.OperatorKind == BinaryOperatorKind.Equals || !outcome && equality.OperatorKind == BinaryOperatorKind.NotEquals))
                return Matches(equality.LeftOperand, equality.RightOperand) || Matches(equality.RightOperand, equality.LeftOperand);
            if (outcome && condition is IInvocationOperation call && call.TargetMethod.Name == "Contains" &&
                call.TargetMethod.ContainingType.ToDisplayString() == "System.Linq.Enumerable" && call.Arguments.Length == 2 &&
                SymbolEqualityComparer.Default.Equals(ReferencedSymbol(Unwrap(call.Arguments[1].Value)), symbol) &&
                Unwrap(call.Arguments[0].Value) is IArrayCreationOperation { Initializer: { } initializer })
                return initializer.ElementValues.Length > 0 && initializer.ElementValues.All(item => item.ConstantValue.HasValue && item.ConstantValue.Value is string);
            return false;
            bool Matches(IOperation reference, IOperation literal) => literal.ConstantValue.HasValue && literal.ConstantValue.Value is string &&
                SymbolEqualityComparer.Default.Equals(ReferencedSymbol(Unwrap(reference)), symbol);
        });

        internal static bool HasCanonicalPathRoot(Location sink, Compilation compilation) => Guarded(sink, compilation, (condition, symbol, outcome) =>
        {
            if (!outcome) return false;
            if (symbol is not ILocalSymbol local || StableInitializer(local, compilation) is not IInvocationOperation canonical ||
                canonical.TargetMethod.ContainingType.ToDisplayString() != "System.IO.Path" || canonical.TargetMethod.Name != "GetFullPath") return false;
            if (condition is not IInvocationOperation check || check.TargetMethod.ContainingType.SpecialType != SpecialType.System_String ||
                check.TargetMethod.Name != "StartsWith" || check.Arguments.Length != 2 ||
                !SymbolEqualityComparer.Default.Equals(ReferencedSymbol(Unwrap(check.Instance)), symbol) ||
                check.Arguments[0].Value.ConstantValue.Value is not string root || root.Length < 2 ||
                root.Last() is not ('/' or '\\') || root.Split('/', '\\').Any(segment => segment is "." or "..") ||
                check.Arguments[1].Value.ConstantValue.Value is not int comparison || comparison != (int)StringComparison.Ordinal) return false;
            return root.StartsWith("/", StringComparison.Ordinal) && !root.StartsWith("//", StringComparison.Ordinal) ||
                root.Length > 3 && char.IsLetter(root[0]) && root[1] == ':' && root[2] is '/' or '\\';
        });

        internal static bool HasFixedRequestAuthority(Location sink, Compilation compilation)
        {
            var operation = Unwrap(SinkValue(sink, compilation));
            if (operation is ILocalReferenceOperation local) operation = Unwrap(StableInitializer(local.Local, compilation));
            if (operation is IObjectCreationOperation creation && creation.Type?.ToDisplayString() == "System.Uri" && creation.Arguments.Length == 1)
                operation = Unwrap(creation.Arguments[0].Value);
            var prefix = Prefix(operation);
            if (prefix == null || !Uri.TryCreate(prefix, UriKind.Absolute, out var uri) || uri.Scheme is not ("http" or "https") || uri.UserInfo.Length != 0) return false;
            var authorityStart = prefix.IndexOf("://", StringComparison.Ordinal);
            return authorityStart >= 0 && prefix.IndexOf('/', authorityStart + 3) >= 0;

            string? Prefix(IOperation? value)
            {
                value = Unwrap(value);
                if (value?.ConstantValue.Value is string literal) return literal;
                if (value is IBinaryOperation { OperatorKind: BinaryOperatorKind.Add, OperatorMethod: null } binary && value.Type?.SpecialType == SpecialType.System_String)
                    return Prefix(binary.LeftOperand);
                if (value is IInterpolatedStringOperation interpolation && interpolation.Parts.FirstOrDefault() is IInterpolatedStringTextOperation text)
                    return text.Text.ConstantValue.Value as string;
                return null;
            }
        }

        internal static IOperation? StableInitializer(ILocalSymbol local, Compilation compilation)
        {
            if (local.DeclaringSyntaxReferences.FirstOrDefault()?.GetSyntax() is not VariableDeclaratorSyntax declaration || declaration.Initializer == null) return null;
            var model = compilation.GetSemanticModel(declaration.SyntaxTree);
            var owner = declaration.Ancestors().FirstOrDefault(node => node is BaseMethodDeclarationSyntax or LambdaExpressionSyntax);
            if (owner == null || owner.DescendantNodes().Select(node => model.GetOperation(node)).Any(operation =>
                operation is IAssignmentOperation assignment && SymbolEqualityComparer.Default.Equals(ReferencedSymbol(Unwrap(assignment.Target)), local) ||
                operation is IArgumentOperation argument && argument.Parameter?.RefKind is RefKind.Ref or RefKind.Out &&
                    SymbolEqualityComparer.Default.Equals(ReferencedSymbol(Unwrap(argument.Value)), local))) return null;
            return model.GetOperation(declaration.Initializer.Value);
        }

        internal static IOperation? Unwrap(IOperation? operation)
        { while (operation is IConversionOperation conversion) operation = conversion.Operand; return operation; }
        internal static ISymbol? ReferencedSymbol(IOperation? operation) => operation switch
        { ILocalReferenceOperation local => local.Local, IParameterReferenceOperation parameter => parameter.Parameter, _ => null };
        private static bool Exits(StatementSyntax statement) => statement is ReturnStatementSyntax or ThrowStatementSyntax ||
            statement is BlockSyntax block && block.Statements.Count == 1 && Exits(block.Statements[0]);
    }
}
