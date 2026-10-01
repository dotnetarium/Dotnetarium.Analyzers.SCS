using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using Analyzer.Utilities;
using Analyzer.Utilities.Extensions;
using Analyzer.Utilities.FlowAnalysis.Analysis.TaintedDataAnalysis;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.FlowAnalysis;
using Microsoft.CodeAnalysis.Operations;
using Dotnetarium.Config;

namespace Dotnetarium.Analyzers.Taint
{
    /// <summary>Runs one configured taint context over each relevant C# operation block.</summary>
    public abstract class TaintAnalyzer : DiagnosticAnalyzer
    {
        protected abstract SinkKind SinkKind { get; }
        protected abstract DiagnosticDescriptor TaintedDataEnteringSinkDescriptor { get; }
        protected virtual IEnumerable<SinkKind> SinkKinds => new[] { SinkKind };
        protected virtual bool AnalyzeRazorGeneratedCode => false;

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics =>
            ImmutableArray.Create(TaintedDataEnteringSinkDescriptor);

        public override void Initialize(AnalysisContext context)
        {
            context.EnableConcurrentExecution();
            context.ConfigureGeneratedCodeAnalysis(AnalyzeRazorGeneratedCode
                ? GeneratedCodeAnalysisFlags.Analyze | GeneratedCodeAnalysisFlags.ReportDiagnostics
                : GeneratedCodeAnalysisFlags.None);

            context.RegisterCompilationStartAction(start =>
            {
                var settings = Configuration.GetOrCreate(start);
                foreach (var kind in SinkKinds)
                {
                    var sourceMap = settings.TaintConfiguration.GetSourceSymbolMap(kind);
                    var sinkMap = settings.TaintConfiguration.GetSinkSymbolMap(kind);
                    if (sourceMap.IsEmpty || sinkMap.IsEmpty)
                        continue;

                    var sanitizerMap = settings.TaintConfiguration.GetSanitizerSymbolMap(kind);
                    start.RegisterOperationBlockAction(block =>
                        AnalyzeBlock(block, kind, settings, sourceMap, sanitizerMap, sinkMap));
                }
            });
        }

        private void AnalyzeBlock(
            OperationBlockAnalysisContext block,
            SinkKind kind,
            Configuration settings,
            TaintedDataSymbolMap<SourceInfo> sources,
            TaintedDataSymbolMap<SanitizerInfo> sanitizers,
            TaintedDataSymbolMap<SinkInfo> sinks)
        {
            if (AnalyzeRazorGeneratedCode && block.OperationBlocks.All(root =>
                IsUnrelatedGeneratedFile(root.Syntax.SyntaxTree.FilePath)))
                return;

            if (block.Options.IsConfiguredToSkipAnalysis(
                    TaintedDataEnteringSinkDescriptor,
                    block.OwningSymbol,
                    block.Compilation,
                    block.CancellationToken))
                return;

            if (!ContainsPotentialSource(block.OperationBlocks, sources, block.Compilation))
                return;

            var graph = block.OperationBlocks.GetControlFlowGraph();
            if (graph == null)
                return;

            AnalyzeGraph(graph, block.OwningSymbol);

            // Route handlers are stored as delegates. RegisterOperationBlockAction
            // receives their containing method, but the parent CFG never invokes
            // the handler, so analyze each request-bound lambda as its own CFG.
            var types = WellKnownTypeProvider.GetOrCreate(block.Compilation);
            foreach (var lambda in graph.DescendantOperations<IFlowAnonymousFunctionOperation>(
                OperationKind.FlowAnonymousFunction))
            {
                if (!lambda.Symbol.Parameters.Any(parameter => sources.IsSourceParameter(parameter, types)))
                    continue;
                AnalyzeGraph(graph.GetAnonymousFunctionControlFlowGraph(lambda), lambda.Symbol);
            }

            void AnalyzeGraph(Microsoft.CodeAnalysis.FlowAnalysis.ControlFlowGraph currentGraph, ISymbol owner)
            {
                var result = TaintedDataAnalysis.TryGetOrComputeResult(
                    currentGraph,
                    block.Compilation,
                    owner,
                    block.Options,
                    TaintedDataEnteringSinkDescriptor,
                    sources,
                    sanitizers,
                    sinks,
                    block.CancellationToken,
                    settings.MaxInterproceduralMethodCallChain,
                    settings.MaxInterproceduralLambdaOrLocalFunctionCallChain);
                if (result == null)
                    return;

                foreach (var pair in result.TaintedDataSourceSinks)
                {
                    if (!pair.SinkKinds.Contains(kind))
                        continue;

                    foreach (var origin in pair.SourceOrigins)
                    {
                        var locations = settings.TaintFlowVisualizationEnabled
                            ? result.GetFlowLocations(pair, origin).ToArray()
                            : new[] { origin.Location };
                        var properties = settings.TaintFlowVisualizationEnabled
                            ? ImmutableDictionary<string, string>.Empty.Add("dotnetarium.flow", "true")
                            : null;
                        block.ReportDiagnostic(Diagnostic.Create(
                            TaintedDataEnteringSinkDescriptor,
                            pair.Sink.Location,
                            additionalLocations: locations,
                            properties: properties,
                            messageArgs: new object[]
                            {
                                pair.Sink.Symbol.Name,
                                pair.Sink.AccessingMethod.ToDisplayString(SymbolDisplayFormat.MinimallyQualifiedFormat),
                                origin.Symbol.ToDisplayString(SymbolDisplayFormat.MinimallyQualifiedFormat),
                                origin.AccessingMethod.ToDisplayString(SymbolDisplayFormat.MinimallyQualifiedFormat)
                            }));
                    }
                }
            }
        }

        private static bool ContainsPotentialSource(
            ImmutableArray<IOperation> roots,
            TaintedDataSymbolMap<SourceInfo> sources,
            Compilation compilation)
        {
            var types = WellKnownTypeProvider.GetOrCreate(compilation);
            foreach (var root in roots)
            {
                foreach (var operation in root.DescendantsAndSelf())
                {
                    switch (operation)
                    {
                        case IPropertyReferenceOperation property when
                            sources.IsSourceProperty(property.Property):
                        case IFieldReferenceOperation field when
                            sources.IsSourceField(field.Field):
                        case IParameterReferenceOperation parameter when
                            sources.IsSourceParameter(parameter.Parameter, types):
                            return true;
                        case IInvocationOperation call when
                            sources.GetInfosForType(call.TargetMethod.ContainingType).Any():
                            return true;
                    }
                }
            }

            return false;
        }

        private static bool IsUnrelatedGeneratedFile(string path) =>
            !string.IsNullOrEmpty(path) &&
            path.EndsWith(".g.cs", StringComparison.OrdinalIgnoreCase) &&
            !path.EndsWith("_razor.g.cs", StringComparison.OrdinalIgnoreCase) &&
            !path.EndsWith("_cshtml.g.cs", StringComparison.OrdinalIgnoreCase);
    }
}
