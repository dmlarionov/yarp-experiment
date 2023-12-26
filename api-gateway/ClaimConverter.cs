using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.Extensions.Options;

namespace ApiGateway
{
	public class ClaimConverter : JsonConverter<Claim>
    {
        public override bool CanConvert(Type objectType)
        {
            return (objectType == typeof(Claim));
        }

        public override Claim? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            if (reader.TokenType != JsonTokenType.StartObject)
                throw new JsonException();

            var dictionary = new Dictionary<string, string>();
            var stringConverter = (JsonConverter<string>)options.GetConverter(typeof(string));
            string? prop = null;
            int depth = 0;

            while (depth >=0 && reader.Read())
            {
                switch (reader.TokenType)
                {
                    case JsonTokenType.StartObject:
                    case JsonTokenType.StartArray:
                        prop = null;
                        depth++;
                        continue;

                    case JsonTokenType.EndObject:
                    case JsonTokenType.EndArray:
                        prop = null;
                        if (depth-- == 0)
                            break;
                        else
                            continue;

                    case JsonTokenType.PropertyName:
                        // Take only root level props
                        prop = (depth == 0) ? reader.GetString()?.ToLowerInvariant() : null;
                        continue;

                    case JsonTokenType.String:
                        // Add to dictionary.
                        if (prop != null)
                        {
                            dictionary.Add(prop, stringConverter.Read(ref reader, typeof(string), options)!);
                            prop = null;
                        }
                        continue;

                    default:
                        prop = null;
                        continue;
                }
            }

            if (!string.IsNullOrEmpty(dictionary["type"]) && !string.IsNullOrEmpty(dictionary["value"]))
            {
                var claim = new Claim(
                    dictionary["type"],
                    dictionary["value"],
                    dictionary["valuetype"],
                    dictionary["issuer"],
                    dictionary["originalissuer"]);
                return claim;
            }
            else
                throw new JsonException("Claim must contain Type and Value.");
        }

        public override void Write(Utf8JsonWriter writer, Claim claim, JsonSerializerOptions options)
        {
            writer.WriteStartObject();
            writer.WriteString("Type", claim.Type);
            writer.WriteString("Value", claim.Value);
            writer.WriteString("ValueType", claim.ValueType);
            writer.WriteString("Issuer", claim.Issuer);
            writer.WriteString("OriginalIssuer", claim.OriginalIssuer);
            writer.WriteEndObject();
        }
    }
}

