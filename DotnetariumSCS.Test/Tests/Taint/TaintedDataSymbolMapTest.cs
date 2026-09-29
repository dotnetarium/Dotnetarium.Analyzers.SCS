using System;
using System.Collections.Immutable;
using System.Linq;
using Analyzer.Utilities;
using Analyzer.Utilities.FlowAnalysis.Analysis.TaintedDataAnalysis;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace DotnetariumSCS.Test.Taint
{
    [TestClass]
    public class TaintedDataSymbolMapTest
    {
        [TestMethod]
        public void KeepsRedirectAndFilePathSinksForTheSameType()
        {
            var compilation = CSharpCompilation.Create(
                "SinkMapTest",
                syntaxTrees: new[] { CSharpSyntaxTree.ParseText("namespace System.Web { public class HttpResponse { } }") },
                references: new[] { MetadataReference.CreateFromFile(typeof(string).Assembly.Location) });
            var responseType = compilation.GetTypeByMetadataName("System.Web.HttpResponse");
            Assert.IsNotNull(responseType);

            var redirect = CreateSinkInfo(SinkKind.Redirect, "Redirect");
            var filePath = CreateSinkInfo(SinkKind.FilePathInjection, "TransmitFile");
            foreach (var infos in new[] { new[] { redirect, filePath }, new[] { filePath, redirect } })
            {
                var map = new TaintedDataSymbolMap<SinkInfo>(WellKnownTypeProvider.GetOrCreate(compilation), infos);
                var resolved = map.GetInfosForType(responseType).ToArray();
                CollectionAssert.Contains(resolved, redirect);
                CollectionAssert.Contains(resolved, filePath);
                Assert.AreEqual(2, resolved.Length);
            }
        }

        private static SinkInfo CreateSinkInfo(SinkKind kind, string method)
            => new SinkInfo(
                "System.Web.HttpResponse",
                ImmutableHashSet.Create(kind),
                isInterface: false,
                isAnyStringParameterInConstructorASink: false,
                sinkProperties: ImmutableHashSet<string>.Empty,
                sinkMethodMatchingParameters: ImmutableHashSet<(MethodMatcher, ImmutableHashSet<string>)>.Empty,
                sinkMethodParameters: ImmutableDictionary<string, ImmutableHashSet<string>>.Empty.Add(method, ImmutableHashSet.Create("value")));
    }
}
