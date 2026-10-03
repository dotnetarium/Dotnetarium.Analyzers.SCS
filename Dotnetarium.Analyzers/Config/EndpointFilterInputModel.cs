using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Operations;

namespace Dotnetarium.Config
{
    /// <summary>Associates filter argument slots with the bound handler parameters of their endpoints.</summary>
    internal sealed class EndpointFilterInputModel
    {
        private readonly Compilation compilation;
        private readonly Dictionary<IMethodSymbol, List<ImmutableArray<IParameterSymbol>>> bindings = new(SymbolEqualityComparer.Default);

        internal EndpointFilterInputModel(Compilation compilation)
        {
            this.compilation = compilation;
            foreach (var tree in compilation.SyntaxTrees)
            {
                var model = compilation.GetSemanticModel(tree);
                foreach (var syntax in tree.GetRoot().DescendantNodes().OfType<InvocationExpressionSyntax>())
                {
                    if (model.GetOperation(syntax) is not IInvocationOperation filter ||
                        filter.TargetMethod.ContainingType.ToDisplayString() != "Microsoft.AspNetCore.Http.EndpointFilterExtensions" ||
                        filter.TargetMethod.Name is not ("AddEndpointFilter" or "AddEndpointFilterFactory")) continue;
                    var receiver = Unwrap(filter.Instance ?? filter.Arguments.FirstOrDefault()?.Value);
                    while (receiver is IInvocationOperation previous && previous.TargetMethod.Name.StartsWith("AddEndpointFilter", System.StringComparison.Ordinal))
                        receiver = Unwrap(previous.Instance ?? previous.Arguments.FirstOrDefault()?.Value);
                    if (receiver is not IInvocationOperation map || map.TargetMethod.ContainingNamespace.ToDisplayString() != "Microsoft.AspNetCore.Builder" ||
                        map.TargetMethod.Name is not ("Map" or "MapGet" or "MapPost" or "MapPut" or "MapPatch" or "MapDelete" or "MapMethods" or "MapFallback")) continue;
                    var handler = Unwrap(map.Arguments.LastOrDefault()?.Value);
                    var parameters = handler is IAnonymousFunctionOperation lambda ? lambda.Symbol.Parameters :
                        handler is IMethodReferenceOperation named ? named.Method.Parameters : default;
                    if (parameters.IsDefault) continue;
                    foreach (var argument in filter.Arguments)
                        foreach (var nested in argument.Value.DescendantsAndSelf())
                            if (nested is IAnonymousFunctionOperation callback && callback.Symbol.Parameters.Any(IsFilterContext)) Add(callback.Symbol, parameters);
                            else if (nested is IMethodReferenceOperation method && method.Method.Parameters.Any(IsFilterContext)) Add(method.Method, parameters);
                    foreach (var type in filter.TargetMethod.TypeArguments.OfType<INamedTypeSymbol>())
                        foreach (var contract in type.AllInterfaces.Where(contract => contract.ToDisplayString() == "Microsoft.AspNetCore.Http.IEndpointFilter"))
                            foreach (var member in contract.GetMembers("InvokeAsync"))
                                if (type.FindImplementationForInterfaceMember(member) is IMethodSymbol method) Add(method, parameters);
                }
            }
        }

        private void Add(IMethodSymbol filter, ImmutableArray<IParameterSymbol> parameters)
        {
            if (!bindings.TryGetValue(filter, out var list)) bindings.Add(filter, list = new());
            list.Add(parameters);
        }

        internal IEnumerable<IParameterSymbol> GetBoundParameters(IOperation? operation)
        {
            operation = Unwrap(operation);
            IOperation? context = null;
            IOperation? index = null;
            if (operation is IInvocationOperation invocation && invocation.TargetMethod.Name == "GetArgument" &&
                invocation.TargetMethod.ContainingType.ToDisplayString() == "Microsoft.AspNetCore.Http.EndpointFilterInvocationContext" &&
                invocation.Arguments.Length == 1)
            { context = invocation.Instance; index = invocation.Arguments[0].Value; }
            else if (operation is IPropertyReferenceOperation { Property.IsIndexer: true } property && property.Arguments.Length == 1 &&
                Unwrap(property.Instance) is IPropertyReferenceOperation arguments && arguments.Property.Name == "Arguments" &&
                arguments.Property.ContainingType.ToDisplayString() == "Microsoft.AspNetCore.Http.EndpointFilterInvocationContext")
            { context = arguments.Instance; index = property.Arguments[0].Value; }
            if (index?.ConstantValue.Value is not int ordinal || ordinal < 0 ||
                MessageInputModel.StableParameter(context, compilation)?.ContainingSymbol is not IMethodSymbol filter ||
                !bindings.TryGetValue(filter, out var endpoints)) return Enumerable.Empty<IParameterSymbol>();
            return endpoints.Where(parameters => ordinal < parameters.Length).Select(parameters => parameters[ordinal]);
        }

        private static bool IsFilterContext(IParameterSymbol parameter) => parameter.Type.ToDisplayString() == "Microsoft.AspNetCore.Http.EndpointFilterInvocationContext";
        private static IOperation? Unwrap(IOperation? operation)
        {
            while (operation is IConversionOperation or IDelegateCreationOperation)
                operation = operation is IConversionOperation conversion ? conversion.Operand : ((IDelegateCreationOperation)operation).Target;
            return operation;
        }
    }
}
