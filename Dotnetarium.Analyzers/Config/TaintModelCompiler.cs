using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using Analyzer.Utilities;
using Analyzer.Utilities.Extensions;
using Analyzer.Utilities.FlowAnalysis.Analysis.TaintedDataAnalysis;
using Analyzer.Utilities.PooledObjects;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.FlowAnalysis.DataFlow.ValueContentAnalysis;
using Microsoft.CodeAnalysis.Operations;
using Dotnetarium.Analyzers.Taint;

namespace Dotnetarium.Config
{
    internal sealed class Configuration
    {
        private static readonly BoundedCacheWithFactory<CompilationStartAnalysisContext, Configuration> Cache =
            new BoundedCacheWithFactory<CompilationStartAnalysisContext, Configuration>();

        public static Configuration GetOrCreate(CompilationStartAnalysisContext context) =>
            Cache.GetOrCreateValue(context, current =>
                new Configuration(
                    ConfigurationManager.GetProjectConfiguration(current.Options.AdditionalFiles),
                    current.Compilation));

        private Configuration(ConfigData data, Compilation compilation)
        {
            MaxInterproceduralMethodCallChain = data.MaxInterproceduralMethodCallChain ?? 5;
            MaxInterproceduralLambdaOrLocalFunctionCallChain =
                data.MaxInterproceduralLambdaOrLocalFunctionCallChain ?? 5;
            TaintFlowVisualizationEnabled = data.TaintFlowVisualizationEnabled ?? true;
            TaintConfiguration = new TaintConfiguration(data, compilation);
        }

        public uint MaxInterproceduralMethodCallChain { get; }
        public uint MaxInterproceduralLambdaOrLocalFunctionCallChain { get; }
        public bool TaintFlowVisualizationEnabled { get; }
        public TaintConfiguration TaintConfiguration { get; }
    }

    internal sealed class TaintConfiguration
    {
        private readonly ConfigData model;
        private readonly Compilation compilation;
        private readonly Lazy<ImmutableHashSet<IMethodSymbol>> minimalApiHandlers;
        private readonly WellKnownTypeProvider types;
        private readonly ConcurrentDictionary<SinkKind, TaintedDataSymbolMap<SourceInfo>> sourceMaps = new();
        private readonly ConcurrentDictionary<SinkKind, TaintedDataSymbolMap<SanitizerInfo>> sanitizerMaps = new();
        private readonly ConcurrentDictionary<SinkKind, TaintedDataSymbolMap<SinkInfo>> sinkMaps = new();

        public TaintConfiguration(ConfigData model, Compilation compilation)
        {
            this.model = model;
            this.compilation = compilation;
            minimalApiHandlers = new Lazy<ImmutableHashSet<IMethodSymbol>>(FindMinimalApiHandlers);
            types = WellKnownTypeProvider.GetOrCreate(compilation);
        }

        public TaintedDataSymbolMap<SourceInfo> GetSourceSymbolMap(SinkKind kind) =>
            sourceMaps.GetOrAdd(kind, current => new TaintedDataSymbolMap<SourceInfo>(types, CompileSources(current)));

        public TaintedDataSymbolMap<SanitizerInfo> GetSanitizerSymbolMap(SinkKind kind) =>
            sanitizerMaps.GetOrAdd(kind, current => new TaintedDataSymbolMap<SanitizerInfo>(types, CompileSanitizers(current)));

        public TaintedDataSymbolMap<SinkInfo> GetSinkSymbolMap(SinkKind kind) =>
            sinkMaps.GetOrAdd(kind, current => new TaintedDataSymbolMap<SinkInfo>(types, CompileSinks(current)));

        private static bool Applies(HashSet<TaintType> contexts, SinkKind kind) =>
            contexts == null || contexts.Any(context => (int)context == (int)kind);

        private ImmutableHashSet<SourceInfo> CompileSources(SinkKind kind)
        {
            var definitions = new Dictionary<string, SourceDefinition>(StringComparer.Ordinal);
            SourceDefinition For(string type)
            {
                if (!definitions.TryGetValue(type, out var definition))
                    definitions.Add(type, definition = new SourceDefinition());
                return definition;
            }

            foreach (var entry in model.TaintEntryPoints ?? new Dictionary<string, TaintEntryPointData>())
                For(entry.Key).EntryPoint = entry.Value;
            foreach (var source in model.TaintSources ?? new List<TaintSource>())
                if (Applies(source.TaintTypes, kind))
                    For(source.Type).Source = source;
            foreach (var transfer in model.Transfers ?? new List<Transfer>())
            {
                var definition = For(transfer.Type);
                definition.IsInterface |= transfer.IsInterface == true;
                definition.Transfers.AddRange(transfer.Methods ?? new List<TransferInfo>());
            }
            foreach (var sanitizer in model.Sanitizers ?? new List<Sanitizer>())
                if (Applies(sanitizer.TaintTypes, kind))
                {
                    var definition = For(sanitizer.Type);
                    definition.IsInterface |= sanitizer.IsInterface == true;
                    definition.Transfers.AddRange(
                        (sanitizer.Methods ?? new List<TransferInfo>()).Where(method =>
                            method.InOut?.Any(pair => pair.outArgumentName != TaintedTargetValue.Return) == true));
                }

            var compiled = ImmutableHashSet.CreateBuilder<SourceInfo>();
            foreach (var (type, definition) in definitions)
            {
                var source = definition.Source;
                var entry = definition.EntryPoint;
                bool isInterface = source?.IsInterface == true || definition.IsInterface;
                var methods = (source?.Methods ?? Array.Empty<string>())
                    .Select<string, (MethodMatcher, ImmutableHashSet<string>)>(name =>
                        ((methodName, _) => methodName == name,
                         ImmutableHashSet<string>.Empty.Add(TaintedTargetValue.Return)))
                    .ToImmutableHashSet();
                var transfers = definition.Transfers
                    .Where(method => method.InOut != null)
                    .Select(method =>
                        ((MethodMatcher)((name, args) => name == method.Name &&
                            (!method.ArgumentCount.HasValue || args.Length == method.ArgumentCount.Value)),
                         method.InOut.Where(pair => pair.outArgumentName != TaintedTargetValue.Return)
                                     .Select(pair => (pair.inArgumentName, pair.outArgumentName))
                                     .ToImmutableHashSet()))
                    .ToImmutableHashSet();

                bool allMembers = source != null && source.Methods == null && source.Properties == null &&
                    source.PropertyAttributes == null && source.ServerPropertyAttributes == null &&
                    source.PreserveTaintOnConversion != true && source.RoutedParameters != true;
                if (allMembers)
                {
                    compiled.Add(new SourceInfo(
                        type,
                        isInterface,
                        methods,
                        ImmutableHashSet<(MethodMatcher, ImmutableHashSet<(PointsToCheck, string)>)>.Empty,
                        ImmutableHashSet<(MethodMatcher, ImmutableHashSet<(ValueContentCheck, string)>)>.Empty,
                        transfers,
                        allProperitesAreTainted: true,
                        allFieldsAreTainted: true,
                        dependencyFullTypeNames: entry?.Dependency?.ToImmutableArray()));
                    continue;
                }

                var parameters = entry == null
                    ? ImmutableHashSet<ParameterMatcher>.Empty
                    : ImmutableHashSet.Create<ParameterMatcher>((parameter, provider) =>
                        IsInputParameter(parameter, provider, entry));

                compiled.Add(new SourceInfo(
                    type,
                    isInterface,
                    taintedProperties: (source?.Properties ?? Array.Empty<string>())
                        .ToImmutableHashSet(StringComparer.Ordinal),
                    taintedArguments: parameters,
                    taintedMethods: methods,
                    taintedMethodsNeedsPointsToAnalysis:
                        ImmutableHashSet<(MethodMatcher, ImmutableHashSet<(PointsToCheck, string)>)>.Empty,
                    taintedMethodsNeedsValueContentAnalysis:
                        ImmutableHashSet<(MethodMatcher, ImmutableHashSet<(ValueContentCheck, string)>)>.Empty,
                    transferProperties: ImmutableHashSet<string>.Empty,
                    transferMethods: transfers,
                    taintConstantArray: false,
                    constantArrayLengthMatcher: null,
                    dependencyFullTypeNames: entry?.Dependency?.ToImmutableArray(),
                    taintedPropertyAttributes: (source?.PropertyAttributes ?? Array.Empty<string>())
                        .ToImmutableHashSet(StringComparer.Ordinal),
                    preserveTaintOnConversion: source?.PreserveTaintOnConversion ?? false,
                    taintRoutedParameters: source?.RoutedParameters ?? false,
                    serverBoundPropertyAttributes: (source?.ServerPropertyAttributes ?? Array.Empty<string>())
                        .ToImmutableHashSet(StringComparer.Ordinal)));
            }

            return compiled.ToImmutable();
        }

        private bool IsInputParameter(
            IParameterSymbol parameter,
            WellKnownTypeProvider provider,
            TaintEntryPointData entry)
        {
            if (IsMinimalApiInputParameter(parameter, compilation))
                return true;
            if (parameter.ContainingSymbol is not IMethodSymbol method ||
                method.MethodKind is MethodKind.PropertyGet or MethodKind.PropertySet)
                return false;
            if (method.ContainingType == null)
                return false;

            var owner = method.ContainingType;
            var classRule = entry.Class;
            if (classRule != null)
            {
                if (classRule.Accessibility != null && !classRule.Accessibility.Contains(owner.DeclaredAccessibility))
                    return false;

                bool classMatches = true;
                if (classRule.Parent != null)
                {
                    classMatches = provider.TryGetOrCreateTypeByMetadataName(classRule.Parent, out var parent) &&
                        (owner.GetBaseTypesAndThis().Any(candidate =>
                             SymbolEqualityComparer.Default.Equals(candidate, parent)) ||
                         owner.AllInterfaces.Any(candidate =>
                             SymbolEqualityComparer.Default.Equals(candidate, parent)));
                }

                if (classRule.Suffix != null)
                {
                    bool matches = owner.Name.EndsWith(classRule.Suffix.Text, StringComparison.Ordinal);
                    if (!matches && classRule.Suffix.IncludeParent)
                        matches = owner.GetBaseTypes().Any(baseType =>
                            baseType.Name.EndsWith(classRule.Suffix.Text, StringComparison.Ordinal));
                    classMatches &= matches;
                }

                if (HasAnyTypeAttribute(owner, provider, classRule.Attributes?.Exclude))
                    return false;
                if (!classMatches &&
                    !HasAnyTypeAttribute(owner, provider, classRule.Attributes?.Include))
                    return false;
            }

            var methodRule = entry.Method;
            if (methodRule != null)
            {
                if (methodRule.Static.HasValue && methodRule.Static.Value != method.IsStatic)
                    return false;
                if (methodRule.IncludeConstructor == false && method.MethodKind == MethodKind.Constructor)
                    return false;
                if (methodRule.IncludeConstructor == true && method.MethodKind != MethodKind.Constructor)
                    return false;
                if (methodRule.Accessibility != null &&
                    !methodRule.Accessibility.Contains(method.DeclaredAccessibility))
                    return false;
                if (methodRule.Name != null && !(methodRule.NameRegex?.IsMatch(method.Name) ??
                    string.Equals(methodRule.Name, method.Name, StringComparison.Ordinal)))
                    return false;
                if (HasAnyMethodAttribute(method, provider, methodRule.Attributes?.Exclude))
                    return false;
            }

            return !HasAnyParameterAttribute(parameter, provider, entry.Parameter?.Attributes?.Exclude);
        }

        private bool IsMinimalApiInputParameter(IParameterSymbol parameter, Compilation compilation)
        {
            if (HasAttribute(parameter, "Microsoft.AspNetCore.Mvc.FromServicesAttribute"))
                return false;

            var syntax = parameter.DeclaringSyntaxReferences.FirstOrDefault()?.GetSyntax();
            var lambda = syntax?.AncestorsAndSelf().OfType<LambdaExpressionSyntax>().FirstOrDefault();
            var argument = lambda?.Ancestors().OfType<ArgumentSyntax>().FirstOrDefault();
            var isLambdaHandler = argument?.Parent?.Parent is InvocationExpressionSyntax invocation &&
                argument == invocation.ArgumentList.Arguments.LastOrDefault() &&
                IsMinimalApiMapMethod(compilation.GetSemanticModel(invocation.SyntaxTree)
                    .GetSymbolInfo(invocation).Symbol as IMethodSymbol);
            var isNamedHandler = parameter.ContainingSymbol is IMethodSymbol owner &&
                minimalApiHandlers.Value.Contains(owner);
            if (!isLambdaHandler && !isNamedHandler)
                return false;

            if (HasAttribute(parameter, "Microsoft.AspNetCore.Http.AsParametersAttribute"))
                return IsRequestOnlyAggregate(parameter.Type);

            if (parameter.GetAttributes().Any(attribute =>
                attribute.AttributeClass?.ToDisplayString() is
                    "Microsoft.AspNetCore.Mvc.FromRouteAttribute" or
                    "Microsoft.AspNetCore.Mvc.FromQueryAttribute" or
                    "Microsoft.AspNetCore.Mvc.FromHeaderAttribute" or
                    "Microsoft.AspNetCore.Mvc.FromBodyAttribute" or
                    "Microsoft.AspNetCore.Mvc.FromFormAttribute"))
                return true;

            // Simple parameters are inferred from the route, query, header, or form.
            // Complex parameters can also be DI services, so require explicit binding.
            return IsSimpleRequestType(parameter.Type);
        }

        private static bool IsRequestOnlyAggregate(ITypeSymbol type)
        {
            if (type is not INamedTypeSymbol aggregate)
                return false;

            // A mixed aggregate can contain injected services. Marking its whole
            // parameter tainted would incorrectly taint those service members.
            var members = aggregate.GetMembers().Where(member =>
                member.DeclaredAccessibility == Accessibility.Public &&
                member is (IPropertySymbol { IsStatic: false, IsIndexer: false } or
                    IFieldSymbol { IsStatic: false })).ToArray();
            return members.Length > 0 && members.All(member =>
                !HasAttribute(member, "Microsoft.AspNetCore.Mvc.FromServicesAttribute") &&
                (HasRequestBindingAttribute(member) || member switch
                {
                    IPropertySymbol property => IsSimpleRequestType(property.Type),
                    IFieldSymbol field => IsSimpleRequestType(field.Type),
                    _ => false
                }));
        }

        private static bool IsSimpleRequestType(ITypeSymbol type) =>
            type.SpecialType is not SpecialType.None and not SpecialType.System_Object ||
            type.TypeKind == TypeKind.Enum;

        private static bool HasRequestBindingAttribute(ISymbol symbol) =>
            symbol.GetAttributes().Any(attribute => attribute.AttributeClass?.ToDisplayString() is
                "Microsoft.AspNetCore.Mvc.FromRouteAttribute" or
                "Microsoft.AspNetCore.Mvc.FromQueryAttribute" or
                "Microsoft.AspNetCore.Mvc.FromHeaderAttribute" or
                "Microsoft.AspNetCore.Mvc.FromBodyAttribute" or
                "Microsoft.AspNetCore.Mvc.FromFormAttribute");

        private static bool HasAttribute(ISymbol symbol, string name) =>
            symbol.GetAttributes().Any(attribute => attribute.AttributeClass?.ToDisplayString() == name);

        private ImmutableHashSet<IMethodSymbol> FindMinimalApiHandlers()
        {
            var handlers = ImmutableHashSet.CreateBuilder<IMethodSymbol>(SymbolEqualityComparer.Default);
            foreach (var tree in compilation.SyntaxTrees)
            {
                var model = compilation.GetSemanticModel(tree);
                foreach (var invocation in tree.GetRoot().DescendantNodes().OfType<InvocationExpressionSyntax>())
                {
                    if (!IsMinimalApiMapMethod(model.GetSymbolInfo(invocation).Symbol as IMethodSymbol) ||
                        invocation.ArgumentList.Arguments.LastOrDefault() is not { } handlerArgument)
                        continue;
                    var binding = model.GetSymbolInfo(handlerArgument.Expression);
                    if ((binding.Symbol as IMethodSymbol ?? binding.CandidateSymbols.OfType<IMethodSymbol>().SingleOrDefault())
                        is { } handler)
                        handlers.Add(handler);
                }
            }
            return handlers.ToImmutable();
        }

        private static bool IsMinimalApiMapMethod(IMethodSymbol? method) =>
            method != null && method.ContainingNamespace.ToDisplayString() == "Microsoft.AspNetCore.Builder" &&
            method.Name is "Map" or "MapGet" or "MapPost" or "MapPut" or "MapDelete" or
                "MapPatch" or "MapMethods" or "MapFallback";

        private static bool HasAnyTypeAttribute(
            INamedTypeSymbol symbol,
            WellKnownTypeProvider provider,
            List<AttributeCheckData> checks) =>
            checks?.Any(check => provider.TryGetOrCreateTypeByMetadataName(check.Type, out var attribute) &&
                symbol.HasDerivedTypeAttribute(attribute)) == true;

        private static bool HasAnyMethodAttribute(
            IMethodSymbol symbol,
            WellKnownTypeProvider provider,
            List<AttributeCheckData> checks) =>
            checks?.Any(check => provider.TryGetOrCreateTypeByMetadataName(check.Type, out var attribute) &&
                symbol.HasDerivedMethodAttribute(attribute)) == true;

        private static bool HasAnyParameterAttribute(
            IParameterSymbol symbol,
            WellKnownTypeProvider provider,
            List<AttributeCheckData> checks) =>
            checks?.Any(check => provider.TryGetOrCreateTypeByMetadataName(check.Type, out var attribute) &&
                symbol.HasAnyAttribute(attribute)) == true;

        private ImmutableHashSet<SanitizerInfo> CompileSanitizers(SinkKind kind)
        {
            var builder = PooledHashSet<SanitizerInfo>.GetInstance();
            foreach (var sanitizer in model.Sanitizers ?? new List<Sanitizer>())
            {
                if (!Applies(sanitizer.TaintTypes, kind))
                    continue;

                var methods = sanitizer.Methods ?? new List<TransferInfo>();
                var direct = methods.Where(method => method.Condition == null)
                    .Select(method =>
                        ((MethodMatcher)((name, arguments) => Matches(method, name, arguments)),
                         method.InOut?.Select(pair => (pair.inArgumentName, pair.outArgumentName)).ToArray()
                            ?? Array.Empty<(string, string)>()));
                var conditional = methods.Where(method => method.Condition != null)
                    .Select(method =>
                        ((MethodMatcher)((name, arguments) => Matches(method, name, arguments)),
                         (ValueContentCheck)((_, values) => MatchesConditions(method, values)),
                         method.InOut?.Select(pair => (pair.inArgumentName, pair.outArgumentName)).ToArray()
                            ?? Array.Empty<(string, string)>()));
                builder.AddSanitizerInfo(
                    sanitizer.Type,
                    isInterface: sanitizer.IsInterface ?? false,
                    isConstructorSanitizing: false,
                    sanitizingMethods: direct,
                    sanitizingMethodsNeedsValueContentAnalysis: conditional,
                    sanitizingInstanceMethods: methods.Where(method => method.CleansInstance == true)
                        .Select(method => method.Name));
            }
            return builder.ToImmutableAndFree();
        }

        private bool Matches(TransferInfo method, string name, ImmutableArray<IArgumentOperation> arguments)
        {
            if (!string.Equals(method.Name, name, StringComparison.Ordinal))
                return false;
            if (method.ArgumentCount.HasValue && method.ArgumentCount.Value != arguments.Length)
                return false;
            if (method.Signature != null &&
                !SignatureMatches(method.Signature, arguments))
                return false;
            if (method.SignatureNot != null &&
                SignatureMatches(method.SignatureNot, arguments))
                return false;
            return true;
        }

        private bool SignatureMatches(string[] signature, ImmutableArray<IArgumentOperation> arguments) =>
            signature.Length <= arguments.Length &&
            signature.Select((typeName, index) =>
                types.TryGetOrCreateTypeByMetadataName(typeName, out var expected) &&
                SymbolEqualityComparer.Default.Equals(arguments[index].Parameter?.Type, expected)).All(match => match);

        private static bool MatchesConditions(
            TransferInfo method,
            ImmutableArray<ValueContentAbstractValue> values) =>
            method.Condition?.All(condition =>
                condition.idx >= 0 && condition.idx < values.Length &&
                values[condition.idx].IsLiteralState &&
                values[condition.idx].LiteralValues.Count == 1 &&
                Equals(condition.value, values[condition.idx].LiteralValues.First())) == true;

        private ImmutableHashSet<SinkInfo> CompileSinks(SinkKind kind)
        {
            var builder = PooledHashSet<SinkInfo>.GetInstance();
            foreach (var sink in model.Sinks ?? new List<Sink>())
            {
                if (!Applies(sink.TaintTypes, kind))
                    continue;

                builder.AddSinkInfo(
                    sink.Type,
                    new[] { kind },
                    isInterface: sink.IsInterface ?? false,
                    isAnyStringParameterInConstructorASink:
                        sink.IsAnyStringParameterInConstructorASink ?? false,
                    sinkProperties: sink.Properties,
                    sinkMethodMatchingParameters:
                        (sink.Methods ?? Array.Empty<SinkMethod>())
                            .Where(method => method.Condition != null)
                            .Select(method =>
                                ((MethodMatcher)((name, arguments) =>
                                    name == method.Name && method.Condition.All(condition =>
                                        arguments.Any(argument =>
                                            argument.Parameter?.Name == condition.argName &&
                                            argument.Value.ConstantValue.HasValue &&
                                            Equals(argument.Value.ConstantValue.Value, condition.value)))),
                                 method.Arguments ?? Array.Empty<string>())),
                    sinkMethodParameters:
                        (sink.Methods ?? Array.Empty<SinkMethod>())
                            .Where(method => method.Condition == null)
                            .Select(method => (method.Name, method.Arguments ?? Array.Empty<string>())));
            }

            return builder.ToImmutableAndFree();
        }

        private sealed class SourceDefinition
        {
            public TaintEntryPointData EntryPoint { get; set; }
            public TaintSource Source { get; set; }
            public bool IsInterface { get; set; }
            public List<TransferInfo> Transfers { get; } = new List<TransferInfo>();
        }
    }
}
