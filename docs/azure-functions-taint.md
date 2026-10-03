# Azure Functions inputs

The isolated-worker model requires a public `[Function]` method and an exact
trigger attribute on the payload parameter. It covers HTTP and Service Bus,
plus Queue Storage, Event Grid and Event Hubs.

| Trigger | Payload examples |
| --- | --- |
| `QueueTrigger` | `string`, deserialized POCO, `QueueMessage.MessageText` |
| `EventGridTrigger` | `EventGridEvent.Data`, `CloudEvent.Data`, `string` |
| `EventHubTrigger` | `EventData.EventBody`, event properties, single or batch payloads |

The payload remains untrusted after deserialization. Other parameters such as
`FunctionContext`, injected services and message actions are not payload sources.
Output-binding attributes, ordinary helper methods, and locally constructed SDK
objects do not create input provenance. Metadata-only function bodies cannot be
analyzed.

Avoid blanket DTO sources to work around an unsupported binding. Configure the
exact trigger boundary, and use safe sink APIs or explicit validation; see
[rule configuration](RuleConfiguration.md).
