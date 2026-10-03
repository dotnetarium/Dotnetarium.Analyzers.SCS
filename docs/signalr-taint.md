# SignalR taint analysis

Public instance methods declared on a `Hub` or `Hub<T>` subclass receive client arguments. Dotnetarium follows scalar values, concrete DTOs, arrays, and client upload streams (`IAsyncEnumerable<T>` and `ChannelReader<T>`) into the existing injection rules. Stream items are covered through enumeration, `ReadAsync`, and `TryRead`.

Constructors, static and private helpers, framework lifecycle overrides, cancellation tokens, and explicit service parameters are excluded. Visible registrations in the built-in service collection also exclude implicit service parameters, including factory, conditional, and descriptor registrations. A constant `DisableImplicitFromServicesParameters = true` in `AddSignalR` or `AddHubOptions<T>` allows those parameters to be treated as client input; explicit service attributes still exclude them.

This is a static binding model. Registrations hidden inside external methods or another DI container are not inferred. Unregistered interface and abstract parameter types are left unmodeled. Hub filters, client results returned through `ISingleClientProxy.InvokeAsync`, and server-to-client hub calls need separate models. Use explicit service attributes when registration is hidden from the analyzer.
