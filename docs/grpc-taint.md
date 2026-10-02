# ASP.NET Core gRPC taint analysis

Generated gRPC service bases marked with `BindServiceMethodAttribute` identify incoming handlers. The analyzer treats protobuf request parameters and `IAsyncStreamReader<T>` request streams on their overrides as untrusted. This covers unary requests, client and duplex streams, and messages read through `Current` or `ReadAllAsync`. `ServerCallContext.RequestHeaders` is also an untrusted input. These sources feed the existing injection rules; there is no separate gRPC diagnostic.

Overrides of the four server methods on `Grpc.Core.Interceptors.Interceptor` also receive incoming request or request-stream taint. Client interceptor overrides, ordinary helpers, response writers, `ServerCallContext.Method`, and locally created metadata are excluded. Generated services use the `Grpc.AspNetCore` and `Google.Protobuf` pattern; code-first services are not modeled as gRPC entry points. A finding still depends on a value reaching a modeled sink.

The existing SSRF rule covers untrusted addresses passed to `GrpcChannel.ForAddress`. Two separate configuration rules flag unconditional `EnableDetailedErrors = true` in gRPC registration ([DNA0018](rules/DNA0018.md)) and the explicit combination of a remote plaintext channel, insecure call-credential opt-in, and call credentials ([DNA0019](rules/DNA0019.md)).
