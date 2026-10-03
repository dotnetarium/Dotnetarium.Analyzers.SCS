# Message inputs

Incoming message data uses the same injection rules and SARIF flows as HTTP input.

| API | Sources | Excluded |
| --- | --- | --- |
| MassTransit | `Message` and `Headers` in `IConsumer<T>.Consume`, including explicit implementations, for consumers registered inside `AddMassTransit` | Mediator-only consumers, unregistered consumers, local/outgoing DTOs, injected services, cancellation tokens |
| RabbitMQ.Client | `AsyncEventingBasicConsumer.ReceivedAsync` body, properties, exchange and routing key; `HandleBasicDeliverAsync` delivery payloads; `IChannel.BasicGetAsync` results | Locally constructed event args and outgoing payloads |
| Confluent.Kafka | `IConsumer<TKey,TValue>.Consume` results and their message keys, values and headers | Locally constructed messages/results |

MassTransit registration must be visible in the same compilation. Assembly
scanning, registrations hidden in another assembly, and arbitrary registration
helpers are not inferred. Add a narrow custom entry-point model when a verified
transport boundary is outside this coverage; do not mark every message DTO as a
source. See [rule configuration](RuleConfiguration.md).

Stable callback aliases are supported. A replaced or ref/out-escaped callback
argument is not assumed to still be the incoming delivery. Helpers are followed
by the normal interprocedural engine when their source provenance is known.

Receiving a message does not by itself indicate a vulnerability: the rule needs
a flow into a configured sink. Validate against a finite allowlist or use a safe
API such as parameterized SQL. Trust in a broker does not guarantee that every
producer is trusted.

API references: [MassTransit consumers](https://masstransit.io/documentation/concepts/consumers),
[RabbitMQ .NET guide](https://www.rabbitmq.com/client-libraries/dotnet-api-guide),
[Kafka consumer API](https://docs.confluent.io/platform/current/clients/confluent-kafka-dotnet/_site/api/Confluent.Kafka.IConsumer-2.html).
