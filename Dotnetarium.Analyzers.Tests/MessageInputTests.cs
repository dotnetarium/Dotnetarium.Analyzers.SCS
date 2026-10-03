using Dotnetarium.Analyzers.Taint;

namespace Dotnetarium.Analyzers.Tests;

public sealed class MessageInputTests
{
    [Theory]
    [InlineData("services.AddMassTransit(x => x.AddConsumer<Worker>());", "Process.Start(context.Message.Value);", 1)]
    [InlineData("services.AddMassTransit(x => x.AddConsumer<Worker>());", "Process.Start(context.Headers.Get<string>(\"command\"));", 1)]
    [InlineData("services.AddMassTransit(x => x.AddConsumer<Worker>());", "var received = context; Process.Start(received.Message.Value);", 1)]
    [InlineData("services.AddMassTransit(x => x.AddConsumer<Worker>());", "Process.Start(service.Value); Process.Start(context.CancellationToken.ToString());", 0)]
    [InlineData("services.AddMassTransit(x => x.AddConsumer<Worker>());", "var message = new Input { Value = \"fixed\" }; Process.Start(message.Value); await context.Publish(message);", 0)]
    [InlineData("services.AddMediator(x => x.AddConsumer<Worker>());", "Process.Start(context.Message.Value);", 0)]
    [InlineData("", "Process.Start(context.Message.Value);", 0)]
    public async Task MassTransit_requires_bus_registration_and_only_payload_members_are_sources(string registration, string body, int expected)
    {
        var diagnostics = await FrameworkProbe.Analyze("""
            using System.Diagnostics;
            using System.Threading.Tasks;
            using MassTransit;
            using Microsoft.Extensions.DependencyInjection;
            public class Input { public string Value { get; set; } = "fixed"; }
            public class Worker : IConsumer<Input>
            {
                private readonly Input service = new Input();
                public async Task Consume(ConsumeContext<Input> context) {
            """ + body + """
                }
                public static void Configure(IServiceCollection services) {
            """ + registration + "}}", new CommandInjectionTaintAnalyzer());
        Assert.Equal(expected, diagnostics.Length);
        Assert.All(diagnostics, finding => Assert.NotEmpty(finding.AdditionalLocations));
    }

    [Theory]
    [InlineData("consumer.ReceivedAsync += async (_, args) => { Process.Start(Encoding.UTF8.GetString(args.Body.Span)); await Task.CompletedTask; };", 1)]
    [InlineData("consumer.ReceivedAsync += async (_, args) => { Process.Start(args.BasicProperties.Headers[\"command\"].ToString()); await Task.CompletedTask; };", 1)]
    [InlineData("consumer.ReceivedAsync += Handle;", 1)]
    [InlineData("consumer.ReceivedAsync += async (_, args) => { Process.Start(args.CancellationToken.ToString()); await Task.CompletedTask; };", 0)]
    [InlineData("var args = new BasicDeliverEventArgs(\"tag\", 1, false, \"fixed\", \"fixed\", new BasicProperties(), Encoding.UTF8.GetBytes(\"fixed\")); Process.Start(Encoding.UTF8.GetString(args.Body.Span));", 0)]
    [InlineData("consumer.ReceivedAsync += async (_, args) => { args = new BasicDeliverEventArgs(\"tag\", 1, false, \"fixed\", \"fixed\", new BasicProperties(), Encoding.UTF8.GetBytes(\"fixed\")); Process.Start(Encoding.UTF8.GetString(args.Body.Span)); await Task.CompletedTask; };", 0)]
    [InlineData("var result = await channel.BasicGetAsync(\"queue\", true); Process.Start(Encoding.UTF8.GetString(result.Body.Span));", 1)]
    public async Task RabbitMQ_receive_callbacks_and_get_are_sources(string body, int expected)
    {
        var findings = await FrameworkProbe.Analyze("""
            using System;
            using System.Diagnostics;
            using System.Text;
            using System.Threading.Tasks;
            using RabbitMQ.Client;
            using RabbitMQ.Client.Events;
            public static class Worker
            {
                public static async Task Configure(IChannel channel) {
                    var consumer = new AsyncEventingBasicConsumer(channel);
            """ + body + """
                }
                private static Task Handle(object sender, BasicDeliverEventArgs args) {
                    Process.Start(Encoding.UTF8.GetString(args.Body.Span)); return Task.CompletedTask;
                }
            }
            """, new CommandInjectionTaintAnalyzer());
        Assert.Equal(expected, findings.Length);
    }

    [Theory]
    [InlineData("var result = consumer.Consume(default(System.Threading.CancellationToken)); Process.Start(result.Message.Value);", 1)]
    [InlineData("var result = consumer.Consume(TimeSpan.FromSeconds(1)); Process.Start(result.Message.Key);", 1)]
    [InlineData("var result = consumer.Consume(TimeSpan.FromSeconds(1)); Process.Start(Encoding.UTF8.GetString(result.Message.Headers.GetLastBytes(\"command\")));", 1)]
    [InlineData("var message = new Message<string, string> { Key = \"fixed\", Value = \"fixed\" }; Process.Start(message.Value);", 0)]
    [InlineData("var result = new ConsumeResult<string, string> { Message = new Message<string, string> { Value = \"fixed\" } }; Process.Start(result.Message.Value);", 0)]
    public async Task Kafka_taints_consumed_results_but_not_outgoing_messages(string body, int expected)
    {
        var findings = await FrameworkProbe.Analyze("""
            using System;
            using System.Diagnostics;
            using System.Text;
            using Confluent.Kafka;
            public static class Worker { public static void Run(IConsumer<string, string> consumer) {
            """ + body + "}}", new CommandInjectionTaintAnalyzer());
        Assert.Equal(expected, findings.Length);
    }

    [Fact]
    public async Task Explicit_MassTransit_consumer_implementation_is_an_incoming_boundary()
    {
        var findings = await FrameworkProbe.Analyze("""
            using System.Diagnostics;
            using System.Threading.Tasks;
            using MassTransit;
            using Microsoft.Extensions.DependencyInjection;
            public sealed class Input { public string Value { get; set; } }
            public sealed class Worker : IConsumer<Input> {
                Task IConsumer<Input>.Consume(ConsumeContext<Input> context) { Process.Start(context.Message.Value); return Task.CompletedTask; }
                public static void Configure(IServiceCollection services) => services.AddMassTransit(x => x.AddConsumer<Worker>());
            }
            """, new CommandInjectionTaintAnalyzer());
        Assert.Single(findings);
    }

    [Theory]
    [InlineData("Process.Start(input.Value);", 1)]
    [InlineData("Process.Start(service.Value);", 0)]
    public async Task Conventional_MassTransit_consumer_does_not_taint_injected_services(string body, int expected)
    {
        var findings = await FrameworkProbe.Analyze("""
            using System.Diagnostics;
            using System.Threading.Tasks;
            using MassTransit;
            using Microsoft.Extensions.DependencyInjection;
            public sealed class Input { public string Value { get; set; } }
            public sealed class Service { public string Value => "fixed"; }
            [Consumer] public sealed class Worker : IConsumer {
                public Task Consume(Input input, Service service) {
            """ + body + """
                    return Task.CompletedTask;
                }
                public static void Configure(IServiceCollection services) => services.AddMassTransit(x => x.AddConsumer<Worker>());
            }
            """, new CommandInjectionTaintAnalyzer());
        Assert.Equal(expected, findings.Length);
    }

    [Theory]
    [InlineData("Process.Start(Encoding.UTF8.GetString(body.Span));", 1)]
    [InlineData("Process.Start(properties.Headers[\"command\"].ToString());", 1)]
    [InlineData("Process.Start(cancellationToken.ToString());", 0)]
    public async Task RabbitMQ_delivery_override_only_taints_incoming_payload_and_headers(string body, int expected)
    {
        var findings = await FrameworkProbe.Analyze("""
            using System;
            using System.Diagnostics;
            using System.Text;
            using System.Threading;
            using System.Threading.Tasks;
            using RabbitMQ.Client;
            public sealed class Worker : AsyncDefaultBasicConsumer {
                public Worker(IChannel channel) : base(channel) { }
                public override Task HandleBasicDeliverAsync(string consumerTag, ulong deliveryTag, bool redelivered, string exchange,
                    string routingKey, IReadOnlyBasicProperties properties, ReadOnlyMemory<byte> body, CancellationToken cancellationToken = default) {
            """ + body + "return Task.CompletedTask; }}", new CommandInjectionTaintAnalyzer());
        Assert.Equal(expected, findings.Length);
    }
}
