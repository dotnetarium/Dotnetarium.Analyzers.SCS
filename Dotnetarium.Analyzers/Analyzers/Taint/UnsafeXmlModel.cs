using System.Collections.Generic;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Operations;

namespace Dotnetarium.Analyzers.Taint
{
    /// <summary>Requires explicit unrestricted resolution at a tainted parsing operation.</summary>
    internal static class UnsafeXmlModel
    {
        internal static bool IsUnsafe(Location sink, Compilation compilation)
        {
            if (sink.SourceTree == null) return false;
            var model = compilation.GetSemanticModel(sink.SourceTree);
            var node = sink.SourceTree.GetRoot().FindNode(sink.SourceSpan);
            var call = node.AncestorsAndSelf().Select(candidate => model.GetOperation(candidate)).OfType<IInvocationOperation>().FirstOrDefault();
            if (call == null) return false;
            var root = (IOperation)call;
            while (root.Parent != null) root = root.Parent;
            bool unsafeAtSink = false;
            Visit(root, new State());
            return unsafeAtSink;

            void Visit(IOperation operation, State state)
            {
                if (operation is IAnonymousFunctionOperation or ILocalFunctionOperation)
                {
                    // Deferred callbacks have a separate execution boundary. Start
                    // without assuming the enclosing method's mutable settings.
                    foreach (var child in operation.ChildOperations) Visit(child, new State());
                    return;
                }
                if (operation is IConditionalOperation conditional)
                {
                    Visit(conditional.Condition, state);
                    var left = state.Clone(); var right = state.Clone();
                    Visit(conditional.WhenTrue, left);
                    if (conditional.WhenFalse != null) Visit(conditional.WhenFalse, right);
                    state.Merge(left, right);
                    return;
                }
                if (operation is ILoopOperation loop)
                {
                    // Possible earlier iterations can alter any settings referenced
                    // by the loop. Do not infer unsafe parser state across them.
                    foreach (var argument in loop.DescendantsAndSelf().OfType<IPropertyReferenceOperation>())
                        if (state.Resolve(argument.Instance) is { } id) state.Configs.Remove(id);
                }
                if (operation is IObjectCreationOperation creation)
                {
                    var type = creation.Type?.ToDisplayString();
                    if (type is "System.Xml.XmlReaderSettings" or "System.Xml.XmlTextReader" or "System.Xml.XmlDocument")
                        state.Configs[creation.Syntax] = (type == "System.Xml.XmlDocument", false);
                    if (type == "System.Xml.XmlUrlResolver") state.Resolvers.Add(creation.Syntax);
                    foreach (var argument in creation.Arguments) Visit(argument, state);
                    if (creation.Initializer != null) Visit(creation.Initializer, state);
                    return;
                }
                if (operation is IVariableDeclaratorOperation declarator && declarator.Initializer != null)
                {
                    Visit(declarator.Initializer.Value, state);
                    state.Assign(declarator.Symbol, declarator.Initializer.Value);
                    return;
                }
                if (operation is ISimpleAssignmentOperation assignment)
                {
                    Visit(assignment.Value, state);
                    if (assignment.Target is ILocalReferenceOperation local) state.Assign(local.Local, assignment.Value);
                    if (assignment.Target is IPropertyReferenceOperation property && state.Resolve(property.Instance) is { } id &&
                        state.Configs.TryGetValue(id, out var config))
                    {
                        if (property.Property.Name == "DtdProcessing")
                            config.Parse = assignment.Value.ConstantValue.HasValue && assignment.Value.ConstantValue.Value is int value && value == 2;
                        if (property.Property.Name == "XmlResolver")
                            config.Resolve = state.Resolve(assignment.Value) is { } resolver && state.Resolvers.Contains(resolver);
                        state.Configs[id] = config;
                    }
                    return;
                }
                foreach (var child in operation.ChildOperations) Visit(child, state);
                if (operation is IInvocationOperation invocation)
                {
                    if (invocation.Syntax.Span == call.Syntax.Span)
                    {
                        var type = invocation.TargetMethod.ContainingType.ToDisplayString();
                        var parser = type == "System.Xml.XmlReader" && invocation.TargetMethod.Name == "Create"
                            ? invocation.Arguments.FirstOrDefault(argument => argument.Parameter?.Name == "settings")?.Value
                            : invocation.Instance;
                        unsafeAtSink |= state.Resolve(parser) is { } id && state.Configs.TryGetValue(id, out var config) && config.Parse && config.Resolve;
                    }
                    // An unknown helper can mutate aliased settings. Only modeled
                    // parsing calls are known not to change their security settings.
                    if (invocation.TargetMethod.ContainingNamespace.ToDisplayString() != "System.Xml")
                        foreach (var argument in invocation.Arguments)
                            if (state.Resolve(argument.Value) is { } id) state.Configs.Remove(id);
                }
            }
        }

        private sealed class State
        {
            internal readonly Dictionary<ISymbol, SyntaxNode> Aliases = new(SymbolEqualityComparer.Default);
            internal readonly Dictionary<SyntaxNode, (bool Parse, bool Resolve)> Configs = new();
            internal readonly HashSet<SyntaxNode> Resolvers = new();
            internal SyntaxNode? Resolve(IOperation? value)
            {
                while (value is IConversionOperation conversion) value = conversion.Operand;
                if (value is IInstanceReferenceOperation)
                    for (var ancestor = value.Parent; ancestor != null; ancestor = ancestor.Parent)
                        if (ancestor is IObjectOrCollectionInitializerOperation initializer) return initializer.Parent?.Syntax;
                return value switch
                {
                    IObjectCreationOperation creation => creation.Syntax,
                    ILocalReferenceOperation local when Aliases.TryGetValue(local.Local, out var id) => id,
                    _ => null
                };
            }
            internal void Assign(ISymbol symbol, IOperation value)
            {
                if (Resolve(value) is { } id) Aliases[symbol] = id; else Aliases.Remove(symbol);
            }
            internal State Clone()
            {
                var clone = new State();
                foreach (var pair in Aliases) clone.Aliases.Add(pair.Key, pair.Value);
                foreach (var pair in Configs) clone.Configs.Add(pair.Key, pair.Value);
                clone.Resolvers.UnionWith(Resolvers);
                return clone;
            }
            internal void Merge(State left, State right)
            {
                Aliases.Clear(); Configs.Clear(); Resolvers.Clear();
                foreach (var pair in left.Aliases)
                    if (right.Aliases.TryGetValue(pair.Key, out var id) && id == pair.Value) Aliases.Add(pair.Key, id);
                foreach (var pair in left.Configs)
                    if (right.Configs.TryGetValue(pair.Key, out var config))
                        Configs.Add(pair.Key, (pair.Value.Parse && config.Parse, pair.Value.Resolve && config.Resolve));
                Resolvers.UnionWith(left.Resolvers.Intersect(right.Resolvers));
            }
        }
    }
}
