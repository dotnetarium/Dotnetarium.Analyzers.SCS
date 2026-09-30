using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Runtime.CompilerServices;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Operations;

namespace Analyzer.Utilities.FlowAnalysis.Analysis.TaintedDataAnalysis
{
    /// <summary>
    /// A deliberately small model of registrations in the built-in .NET service collection.
    /// It provides dispatch hints only when a service has one unambiguous registration site.
    /// </summary>
    internal sealed class DependencyInjectionRegistrationModel
    {
        private static readonly ConditionalWeakTable<Compilation, DependencyInjectionRegistrationModel> Cache =
            new ConditionalWeakTable<Compilation, DependencyInjectionRegistrationModel>();

        private readonly Dictionary<ITypeSymbol, List<Registration>> _registrations =
            new Dictionary<ITypeSymbol, List<Registration>>(SymbolEqualityComparer.Default);

        private DependencyInjectionRegistrationModel(Compilation compilation)
        {
            foreach (var tree in compilation.SyntaxTrees)
            {
                if (tree.GetRoot() is not Microsoft.CodeAnalysis.CSharp.CSharpSyntaxNode root)
                {
                    continue;
                }

                var semanticModel = compilation.GetSemanticModel(tree);
                foreach (var syntax in root.DescendantNodes().OfType<InvocationExpressionSyntax>())
                {
                    if (semanticModel.GetOperation(syntax) is not IInvocationOperation invocation ||
                        !IsRegistrationMethod(invocation.TargetMethod))
                    {
                        continue;
                    }

                    var serviceType = GetServiceType(invocation);
                    if (serviceType == null)
                    {
                        continue;
                    }

                    var receiver = invocation.Instance ?? invocation.Arguments.FirstOrDefault()?.Value;
                    if (receiver == null)
                    {
                        continue;
                    }

                    // A composed or conditional collection has runtime-dependent order.
                    var site = semanticModel.GetEnclosingSymbol(syntax.SpanStart)?.ToDisplayString() + ":" + receiver.Syntax;
                    var conditional = syntax.Ancestors().Any(node =>
                        node is IfStatementSyntax || node is SwitchStatementSyntax ||
                        node is ConditionalExpressionSyntax || node is ForStatementSyntax ||
                        node is ForEachStatementSyntax || node is WhileStatementSyntax ||
                        node is DoStatementSyntax || node is TryStatementSyntax);
                    var implementation = GetImplementationType(invocation, serviceType);
                    if (!_registrations.TryGetValue(serviceType, out var registrations))
                    {
                        registrations = new List<Registration>();
                        _registrations.Add(serviceType, registrations);
                    }

                    registrations.Add(new Registration(site, syntax.SpanStart, implementation,
                        invocation.TargetMethod.Name.StartsWith("TryAdd", StringComparison.Ordinal), conditional));
                }
            }
        }

        internal static DependencyInjectionRegistrationModel GetOrCreate(Compilation compilation) =>
            Cache.GetValue(compilation, key => new DependencyInjectionRegistrationModel(key));

        internal bool TryGetImplementations(ITypeSymbol serviceType, bool multiple, out ImmutableArray<INamedTypeSymbol> implementations)
        {
            implementations = ImmutableArray<INamedTypeSymbol>.Empty;
            if (!_registrations.TryGetValue(serviceType, out var registrations) ||
                registrations.Select(registration => registration.Site).Distinct().Count() != 1 ||
                registrations.Any(registration => registration.Conditional))
            {
                return false;
            }

            var selected = new List<INamedTypeSymbol>();
            foreach (var registration in registrations.OrderBy(registration => registration.Position))
            {
                if (registration.Implementation == null)
                {
                    // Factory delegates and unknown implementation types may return anything.
                    return false;
                }

                if (!registration.TryAdd || selected.Count == 0)
                {
                    selected.Add(registration.Implementation);
                }
            }

            implementations = multiple
                ? selected.ToImmutableArray()
                : ImmutableArray.Create(selected[selected.Count - 1]);
            return true;
        }

        private static bool IsRegistrationMethod(IMethodSymbol method)
        {
            if (!method.IsExtensionMethod ||
                !method.ContainingNamespace.ToDisplayString().StartsWith("Microsoft.Extensions.DependencyInjection", StringComparison.Ordinal))
            {
                return false;
            }

            switch (method.Name)
            {
                case "AddScoped":
                case "AddSingleton":
                case "AddTransient":
                case "TryAddScoped":
                case "TryAddSingleton":
                case "TryAddTransient":
                    return true;
                default:
                    return false;
            }
        }

        private static ITypeSymbol? GetServiceType(IInvocationOperation invocation)
        {
            if (invocation.TargetMethod.TypeArguments.Length >= 1)
            {
                return invocation.TargetMethod.TypeArguments[0];
            }

            return invocation.Arguments.Skip(invocation.Instance == null ? 1 : 0).FirstOrDefault()?.Value is ITypeOfOperation typeOf
                ? typeOf.TypeOperand
                : null;
        }

        private static INamedTypeSymbol? GetImplementationType(IInvocationOperation invocation, ITypeSymbol serviceType)
        {
            ITypeSymbol? implementation = null;
            if (invocation.TargetMethod.TypeArguments.Length == 2)
            {
                implementation = invocation.TargetMethod.TypeArguments[1];
            }
            else if (invocation.Arguments.Skip(invocation.Instance == null ? 2 : 1).FirstOrDefault()?.Value is ITypeOfOperation typeOf)
            {
                implementation = typeOf.TypeOperand;
            }
            else if (invocation.TargetMethod.TypeArguments.Length == 1 &&
                invocation.Arguments.Length == (invocation.Instance == null ? 1 : 0))
            {
                implementation = serviceType; // Self registration.
            }

            return implementation is INamedTypeSymbol named && !named.IsAbstract &&
                named.TypeKind == TypeKind.Class && named.AllInterfaces.Contains(serviceType)
                ? named
                : null;
        }

        private sealed class Registration
        {
            internal Registration(string site, int position, INamedTypeSymbol? implementation, bool tryAdd, bool conditional)
            {
                Site = site;
                Position = position;
                Implementation = implementation;
                TryAdd = tryAdd;
                Conditional = conditional;
            }

            internal string Site { get; }
            internal int Position { get; }
            internal INamedTypeSymbol? Implementation { get; }
            internal bool TryAdd { get; }
            internal bool Conditional { get; }
        }
    }
}
