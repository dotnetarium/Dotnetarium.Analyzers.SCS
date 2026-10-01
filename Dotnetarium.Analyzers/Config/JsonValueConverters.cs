using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Dotnetarium.Config
{
    internal sealed class StringPairArrayConverter : JsonConverter<(string, string)[]>
    {
        public override (string, string)[] Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            using var document = JsonDocument.ParseValue(ref reader);
            var pairs = new List<(string, string)>();
            foreach (var entry in document.RootElement.EnumerateArray())
            {
                foreach (var property in entry.EnumerateObject())
                    pairs.Add((property.Name, property.Value.GetString() ?? string.Empty));
            }
            return pairs.ToArray();
        }

        public override void Write(Utf8JsonWriter writer, (string, string)[] value, JsonSerializerOptions options) =>
            throw new NotSupportedException();
    }

    internal sealed class IntObjectPairArrayConverter : JsonConverter<(int, object)[]>
    {
        public override (int, object)[] Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            using var document = JsonDocument.ParseValue(ref reader);
            var pairs = new List<(int, object)>();
            foreach (var entry in document.RootElement.EnumerateArray())
            {
                foreach (var property in entry.EnumerateObject())
                    pairs.Add((int.Parse(property.Name, System.Globalization.CultureInfo.InvariantCulture), PrimitiveObjectConverter.Convert(property.Value)));
            }
            return pairs.ToArray();
        }

        public override void Write(Utf8JsonWriter writer, (int, object)[] value, JsonSerializerOptions options) =>
            throw new NotSupportedException();
    }

    internal sealed class StringObjectPairArrayConverter : JsonConverter<(string, object)[]>
    {
        public override (string, object)[] Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            using var document = JsonDocument.ParseValue(ref reader);
            var pairs = new List<(string, object)>();
            foreach (var entry in document.RootElement.EnumerateArray())
            {
                foreach (var property in entry.EnumerateObject())
                    pairs.Add((property.Name, PrimitiveObjectConverter.Convert(property.Value)));
            }
            return pairs.ToArray();
        }

        public override void Write(Utf8JsonWriter writer, (string, object)[] value, JsonSerializerOptions options) =>
            throw new NotSupportedException();
    }

    internal sealed class PrimitiveObjectConverter : JsonConverter<object>
    {
        internal static object? Convert(JsonElement element) => element.ValueKind switch
        {
            JsonValueKind.String => element.GetString(),
            JsonValueKind.Number when element.TryGetInt32(out var number) => number,
            JsonValueKind.Number => element.GetDouble(),
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            JsonValueKind.Null => null,
            _ => throw new JsonException("Configuration conditions must contain primitive values.")
        };

        public override object? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            using var document = JsonDocument.ParseValue(ref reader);
            return Convert(document.RootElement);
        }

        public override void Write(Utf8JsonWriter writer, object value, JsonSerializerOptions options) =>
            throw new NotSupportedException();
    }
}
