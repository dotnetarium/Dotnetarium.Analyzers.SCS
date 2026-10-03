using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Operations;

namespace Dotnetarium.Analyzers.Transport
{
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public sealed class CertificateValidationAnalyzer : DiagnosticAnalyzer
    {
        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics =>
            ImmutableArray.Create(DnaRuleCatalog.CertificateValidationBypass);

        public override void Initialize(AnalysisContext context)
        {
            context.EnableConcurrentExecution();
            context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
            context.RegisterOperationAction(AnalyzeAssignment, OperationKind.SimpleAssignment);
            context.RegisterOperationAction(AnalyzeCreation, OperationKind.ObjectCreation);
        }

        private static void AnalyzeAssignment(OperationAnalysisContext context)
        {
            var assignment = (ISimpleAssignmentOperation)context.Operation;
            if (assignment.Target is IPropertyReferenceOperation property && IsValidationProperty(property.Property) &&
                !IsDevelopmentOnly(assignment) &&
                IsAcceptAll(assignment.Value, context.Compilation, new HashSet<ISymbol>(SymbolEqualityComparer.Default)))
                Report(context, assignment.Value, property.Property.ContainingType.Name + "." + property.Property.Name);
        }

        private static void AnalyzeCreation(OperationAnalysisContext context)
        {
            var creation = (IObjectCreationOperation)context.Operation;
            if (creation.Constructor?.ContainingType.ToDisplayString() != "System.Net.Security.SslStream" ||
                IsDevelopmentOnly(creation)) return;
            foreach (var argument in creation.Arguments)
                if (argument.Parameter?.Name == "userCertificateValidationCallback" &&
                    IsAcceptAll(argument.Value, context.Compilation, new HashSet<ISymbol>(SymbolEqualityComparer.Default)))
                    Report(context, argument.Value, "SslStream");
        }

        private static bool IsValidationProperty(IPropertySymbol property) =>
            (property.ContainingType.ToDisplayString(), property.Name) switch
            {
                ("System.Net.Http.HttpClientHandler", "ServerCertificateCustomValidationCallback") => true,
                ("System.Net.Security.SslClientAuthenticationOptions", "RemoteCertificateValidationCallback") => true,
                ("System.Net.Security.SslServerAuthenticationOptions", "RemoteCertificateValidationCallback") => true,
                ("System.Net.WebSockets.ClientWebSocketOptions", "RemoteCertificateValidationCallback") => true,
                ("System.Net.ServicePointManager", "ServerCertificateValidationCallback") => true,
                _ => false
            };

        private static bool IsDevelopmentOnly(IOperation operation)
        {
            for (var child = operation; child.Parent != null; child = child.Parent)
                if (child.Parent is IConditionalOperation conditional &&
                    (child == conditional.WhenTrue && RequiresDevelopment(conditional.Condition, true) ||
                     child == conditional.WhenFalse && RequiresDevelopment(conditional.Condition, false)))
                    return true;
            return false;
        }

        private static bool RequiresDevelopment(IOperation condition, bool outcome)
        {
            while (condition is IConversionOperation conversion) condition = conversion.Operand;
            if (condition is IInvocationOperation invocation && invocation.TargetMethod.Name == "IsDevelopment" &&
                invocation.TargetMethod.ContainingType.ToDisplayString() is
                    "Microsoft.Extensions.Hosting.HostEnvironmentEnvExtensions" or
                    "Microsoft.Extensions.Hosting.HostingEnvironmentExtensions" or
                    "Microsoft.AspNetCore.Hosting.HostingEnvironmentExtensions")
                return outcome;
            if (condition is IUnaryOperation unary && unary.OperatorKind == UnaryOperatorKind.Not && unary.OperatorMethod == null)
                return RequiresDevelopment(unary.Operand, !outcome);
            if (condition is IBinaryOperation binary && binary.OperatorMethod == null)
            {
                if (binary.OperatorKind == BinaryOperatorKind.ConditionalAnd)
                    return outcome && (RequiresDevelopment(binary.LeftOperand, true) || RequiresDevelopment(binary.RightOperand, true));
                if (binary.OperatorKind == BinaryOperatorKind.ConditionalOr)
                    return !outcome && (RequiresDevelopment(binary.LeftOperand, false) || RequiresDevelopment(binary.RightOperand, false));
            }
            return false;
        }

        private static bool IsAcceptAll(IOperation value, Compilation compilation, HashSet<ISymbol> seen)
        {
            while (value is IConversionOperation conversion) value = conversion.Operand;
            if (value is IDelegateCreationOperation creation)
                return IsAcceptAll(creation.Target, compilation, seen);
            if (value is IPropertyReferenceOperation property)
                return property.Property.IsStatic && property.Property.Name == "DangerousAcceptAnyServerCertificateValidator" &&
                    property.Property.ContainingType.ToDisplayString() == "System.Net.Http.HttpClientHandler";
            if (value is IAnonymousFunctionOperation lambda)
                return ReturnsTrueWithoutValidation(lambda.Body);
            if (value is IMethodReferenceOperation reference)
            {
                var method = reference.Method;
                if (method.IsVirtual || method.IsAbstract || method.IsOverride || !seen.Add(method)) return false;
                foreach (var syntax in method.DeclaringSyntaxReferences)
                {
                    var operation = compilation.GetSemanticModel(syntax.SyntaxTree).GetOperation(syntax.GetSyntax());
                    var body = operation is IMethodBodyOperation methodBody
                        ? methodBody.BlockBody ?? methodBody.ExpressionBody
                        : (operation as ILocalFunctionOperation)?.Body;
                    if (body != null) return ReturnsTrueWithoutValidation(body);
                }
            }
            if (value is ILocalReferenceOperation local && seen.Add(local.Local))
            {
                // Follow only a local initialized once in this operation tree. Reassignment,
                // ref/out escapes and writes in nested closures invalidate this shortcut.
                var root = value;
                while (root.Parent != null) root = root.Parent;
                var operations = root.DescendantsAndSelf().ToArray();
                var declarator = operations.OfType<IVariableDeclaratorOperation>().FirstOrDefault(candidate =>
                    SymbolEqualityComparer.Default.Equals(candidate.Symbol, local.Local));
                if (declarator?.Initializer == null || operations.Any(operation =>
                    operation is IAssignmentOperation assignment && References(assignment.Target, local.Local) ||
                    operation is IArgumentOperation argument && argument.Parameter?.RefKind is RefKind.Ref or RefKind.Out &&
                        References(argument.Value, local.Local)))
                    return false;
                return IsAcceptAll(declarator.Initializer.Value, compilation, seen);
            }
            return false;
        }

        private static bool References(IOperation operation, ILocalSymbol local) =>
            operation.DescendantsAndSelf().OfType<ILocalReferenceOperation>().Any(reference =>
                SymbolEqualityComparer.Default.Equals(reference.Local, local));

        private static bool ReturnsTrueWithoutValidation(IBlockOperation body)
        {
            var operations = OwnOperations(body).ToArray();
            var returns = operations.OfType<IReturnOperation>().ToArray();
            // A validator can reject by throwing even if every normal return is true.
            // Unknown calls, getters, user operators and potentially rejecting operations
            // therefore prevent a finding rather than being assumed harmless.
            return returns.Length > 0 && returns.All(operation => operation.ReturnedValue?.ConstantValue.HasValue == true &&
                    operation.ReturnedValue.ConstantValue.Value is true) &&
                !operations.Any(operation => operation is IInvocationOperation or IObjectCreationOperation or
                    IThrowOperation or IAwaitOperation or ILoopOperation or IPropertyReferenceOperation or
                    IArrayElementReferenceOperation or IDynamicInvocationOperation or IDynamicMemberReferenceOperation ||
                    operation is IBinaryOperation binary && binary.OperatorMethod != null ||
                    operation is IUnaryOperation unary && unary.OperatorMethod != null ||
                    operation is IConversionOperation conversion && conversion.OperatorMethod != null);
        }

        private static IEnumerable<IOperation> OwnOperations(IOperation operation)
        {
            yield return operation;
            foreach (var child in operation.ChildOperations)
            {
                if (child is IAnonymousFunctionOperation or ILocalFunctionOperation) continue;
                foreach (var nested in OwnOperations(child)) yield return nested;
            }
        }

        private static void Report(OperationAnalysisContext context, IOperation value, string target) =>
            context.ReportDiagnostic(Diagnostic.Create(DnaRuleCatalog.CertificateValidationBypass,
                value.Syntax.GetLocation(), target));
    }
}
