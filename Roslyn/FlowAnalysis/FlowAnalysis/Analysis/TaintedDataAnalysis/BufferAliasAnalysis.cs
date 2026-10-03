using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.FlowAnalysis;
using Microsoft.CodeAnalysis.FlowAnalysis.DataFlow;
using Microsoft.CodeAnalysis.FlowAnalysis.DataFlow.PointsToAnalysis;
using Microsoft.CodeAnalysis.Operations;

namespace Analyzer.Utilities.FlowAnalysis.Analysis.TaintedDataAnalysis
{
    /// <summary>A forward may-alias lattice for writable buffer views, using Roslyn allocation identities.</summary>
    internal sealed class BufferAliasAnalysis
    {
        private readonly Dictionary<(OperationKind Kind, SyntaxNode Syntax), ImmutableHashSet<AbstractLocation>> views = new();
        private static readonly ImmutableHashSet<AbstractLocation> Empty = ImmutableHashSet<AbstractLocation>.Empty;

        internal BufferAliasAnalysis(ControlFlowGraph graph, PointsToAnalysisResult? points)
        {
            if (points == null) return;
            var outputs = new State?[graph.Blocks.Length];
            var pending = new Queue<BasicBlock>(); pending.Enqueue(graph.Blocks[0]);
            while (pending.Count > 0)
            {
                var block = pending.Dequeue();
                var state = new State();
                foreach (var predecessor in block.Predecessors)
                    if (outputs[predecessor.Source.Ordinal] is { } previous) state.Union(previous);
                foreach (var operation in block.Operations) Visit(operation, state);
                if (block.BranchValue != null) Visit(block.BranchValue, state);
                if (outputs[block.Ordinal]?.Same(state) == true) continue;
                outputs[block.Ordinal] = state;
                if (block.FallThroughSuccessor?.Destination is { } fallThrough) pending.Enqueue(fallThrough);
                if (block.ConditionalSuccessor?.Destination is { } conditional) pending.Enqueue(conditional);
            }

            ImmutableHashSet<AbstractLocation> Evaluate(IOperation? operation, State state)
            {
                if (operation == null) return Empty;
                if (operation is IArgumentOperation argument) return Evaluate(argument.Value, state);
                if (operation is IConversionOperation conversion) return Evaluate(conversion.Operand, state);
                if (operation.Type is IArrayTypeSymbol) return points[operation].Locations;
                var type = operation.Type?.OriginalDefinition.ToDisplayString();
                if (type is not ("System.Memory<T>" or "System.Span<T>" or "System.ArraySegment<T>")) return Empty;
                if (operation is ILocalReferenceOperation local) return state.Locals.TryGetValue(local.Local, out var value) ? value : Empty;
                if (operation is IFlowCaptureReferenceOperation capture) return state.Captures.TryGetValue(capture.Id, out var value) ? value : Empty;
                if (operation is IObjectCreationOperation creation && creation.Arguments.Length > 0 && creation.Arguments[0].Value.Type is IArrayTypeSymbol)
                    return Evaluate(creation.Arguments[0].Value, state);
                if (operation is IInvocationOperation invocation)
                {
                    if (invocation.TargetMethod.ContainingType.ToDisplayString() == "System.MemoryExtensions" &&
                        invocation.TargetMethod.Name is "AsMemory" or "AsSpan" && invocation.Arguments.Length > 0)
                        return Evaluate(invocation.Arguments[0].Value, state);
                    if (invocation.TargetMethod.Name == "Slice") return Evaluate(invocation.Instance, state);
                }
                if (operation is IPropertyReferenceOperation property && property.Property.Name == "Span" &&
                    property.Property.ContainingType.OriginalDefinition.ToDisplayString() == "System.Memory<T>")
                    return Evaluate(property.Instance, state);
                return Empty;
            }

            void Visit(IOperation operation, State state)
            {
                foreach (var child in operation.ChildOperations) Visit(child, state);
                var value = Evaluate(operation, state);
                views[(operation.Kind, operation.Syntax)] = value;
                if (operation is ISimpleAssignmentOperation { Target: ILocalReferenceOperation local } assignment)
                    state.Locals[local.Local] = Evaluate(assignment.Value, state);
                if (operation is IFlowCaptureOperation capture) state.Captures[capture.Id] = Evaluate(capture.Value, state);
                if (operation is IArgumentOperation argument && argument.Parameter?.RefKind is RefKind.Ref or RefKind.Out &&
                    argument.Value is ILocalReferenceOperation escaped) state.Locals[escaped.Local] = Empty;
            }
        }

        internal ImmutableHashSet<AbstractLocation> GetStorage(IOperation operation) =>
            views.TryGetValue((operation.Kind, operation.Syntax), out var locations) ? locations : Empty;

        private sealed class State
        {
            internal readonly Dictionary<ILocalSymbol, ImmutableHashSet<AbstractLocation>> Locals = new(SymbolEqualityComparer.Default);
            internal readonly Dictionary<CaptureId, ImmutableHashSet<AbstractLocation>> Captures = new();
            internal void Union(State other)
            {
                foreach (var pair in other.Locals) Locals[pair.Key] = Locals.TryGetValue(pair.Key, out var old) ? old.Union(pair.Value) : pair.Value;
                foreach (var pair in other.Captures) Captures[pair.Key] = Captures.TryGetValue(pair.Key, out var old) ? old.Union(pair.Value) : pair.Value;
            }
            internal bool Same(State other) => Locals.Count == other.Locals.Count && Captures.Count == other.Captures.Count &&
                Locals.All(pair => other.Locals.TryGetValue(pair.Key, out var value) && value.SetEquals(pair.Value)) &&
                Captures.All(pair => other.Captures.TryGetValue(pair.Key, out var value) && value.SetEquals(pair.Value));
        }
    }
}
