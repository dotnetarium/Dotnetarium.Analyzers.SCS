# ASP.NET Core gRPC taint analysis

Generated gRPC service bases marked with `BindServiceMethodAttribute` identify incoming handlers. The analyzer treats protobuf request parameters and `IAsyncStreamReader<T>` request streams on their overrides as untrusted. This covers unary requests, client and duplex streams, and messages read through `Current` or `ReadAllAsync`. `ServerCallContext.RequestHeaders` is also an untrusted input. These sources feed the existing injection rules; there is no separate gRPC diagnostic.

The model excludes ordinary helpers, response writers, `ServerCallContext.Method`, and locally created metadata. It recognizes the generated service pattern used by `Grpc.AspNetCore` and `Google.Protobuf`; code-first services and values from custom interceptors are not modeled as gRPC entry points. A finding still depends on a value reaching a modeled sink.
