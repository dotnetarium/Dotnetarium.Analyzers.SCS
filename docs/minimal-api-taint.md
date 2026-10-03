# Minimal API binding and filters

Request-bound route-handler parameters are sources. `[FromServices]`, registered
services, and service members of `[AsParameters]` aggregates are excluded.

For a source-defined `BindAsync(HttpContext[, ParameterInfo])` returning
`ValueTask<T>`, the analyzer follows request data into the fields/properties of
the instances actually returned. Async binders and explicit
`IBindableFromHttpContext<T>.BindAsync` implementations are supported. Fixed
members, service-derived values, discarded objects, and members overwritten with
constants stay clean. A custom binder is not a blanket source for its whole DTO.

Endpoint filters attached directly to a mapped endpoint use that handler's
binding information. `GetArgument<T>(constantIndex)` and
`Arguments[constantIndex]` inherit the corresponding bound parameter's
provenance, including custom binder member summaries. Inline callbacks, typed
`IEndpointFilter` implementations, and returned factory callbacks are supported.
Locally created invocation contexts and service slots are not generic sources.

Filters registered later through aliases or route groups, dynamic indexes,
inherited binders and metadata-only binders are not currently summarized. Shared
filter code attached to multiple endpoints conservatively combines their
possible inputs. Recursive binder member summaries stop at the recursion boundary.

Prefer safe sink APIs and consuming validation branches. Calling a validation
method and ignoring its result does not sanitize input. See
[validation precision](taint-validation.md) and the
[ASP.NET Core binding documentation](https://learn.microsoft.com/aspnet/core/fundamentals/minimal-apis/parameter-binding?view=aspnetcore-10.0).
