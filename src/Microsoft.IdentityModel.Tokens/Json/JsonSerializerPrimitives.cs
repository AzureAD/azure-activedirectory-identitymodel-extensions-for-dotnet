// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text.Json;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Tokens.Json
{
    internal static class JsonSerializerPrimitives
    {
        internal static Exception CreateJsonReaderException(
            ref Utf8JsonReader reader,
            string expectedType,
            string className,
            string propertyName,
            Exception innerException = null)
        {
            if (innerException == null)
                return new JsonException(
                    LogHelper.FormatInvariant(
                        LogMessages.IDX11020,
                        LogHelper.MarkAsNonPII(reader.TokenType),
                        LogHelper.MarkAsNonPII(expectedType),
                        LogHelper.MarkAsNonPII(className),
                        LogHelper.MarkAsNonPII(propertyName),
                        LogHelper.MarkAsNonPII(reader.TokenStartIndex),
                        LogHelper.MarkAsNonPII(reader.CurrentDepth),
                        LogHelper.MarkAsNonPII(reader.BytesConsumed)));
            else
                return new JsonException(
                    LogHelper.FormatInvariant(
                        LogMessages.IDX11020,
                        LogHelper.MarkAsNonPII(reader.TokenType),
                        LogHelper.MarkAsNonPII(expectedType),
                        LogHelper.MarkAsNonPII(className),
                        LogHelper.MarkAsNonPII(propertyName),
                        LogHelper.MarkAsNonPII(reader.TokenStartIndex),
                        LogHelper.MarkAsNonPII(reader.CurrentDepth),
                        LogHelper.MarkAsNonPII(reader.BytesConsumed)),
                    innerException);
        }

        internal static Exception CreateJsonReaderExceptionInvalidType(ref Utf8JsonReader reader, string expectedType, string className, string propertyName)
        {
            return new JsonException(
                LogHelper.FormatInvariant(
                    LogMessages.IDX11022,
                    LogHelper.MarkAsNonPII(expectedType),
                    LogHelper.MarkAsNonPII(reader.TokenType),
                    LogHelper.MarkAsNonPII(className),
                    LogHelper.MarkAsNonPII(propertyName),
                    LogHelper.MarkAsNonPII(reader.TokenStartIndex),
                    LogHelper.MarkAsNonPII(reader.CurrentDepth),
                    LogHelper.MarkAsNonPII(reader.BytesConsumed)));
        }

        internal static string GetPropertyName(ref Utf8JsonReader reader, string className, bool advanceReader)
        {
            if (reader.TokenType == JsonTokenType.None)
                ReaderRead(ref reader);

            if (reader.TokenType != JsonTokenType.PropertyName)
                throw LogHelper.LogExceptionMessage(CreateJsonReaderExceptionInvalidType(ref reader, "JsonTokenType.PropertyName", string.Empty, className));

            if (advanceReader)
            {
                string propertyName = reader.GetString();
                ReaderRead(ref reader);
                return propertyName;
            }

            return reader.GetString();
        }

        /// <summary>
        /// This method is called when deserializing a known type where the JSON property does not map to a type property.
        /// We put the object into a Dictionary[string, object].
        /// </summary>
        /// <param name="reader"></param>
        /// <returns></returns>
        internal static object GetUnknownProperty(ref Utf8JsonReader reader)
        {
            switch (reader.TokenType)
            {
                case JsonTokenType.False:
                    return false;
                case JsonTokenType.Number:
                    return ReadNumber(ref reader);
                case JsonTokenType.True:
                    return true;
                case JsonTokenType.Null:
                    return null;
                case JsonTokenType.String:
                    return reader.GetString();
                case JsonTokenType.StartObject:
                case JsonTokenType.StartArray:
                    return ReadJsonElement(ref reader);
                default:
                    // There is something broken here as this was called when the reader is pointing at a property.
                    // It must be a known Json type.
                    Debug.Assert(false, $"Utf8JsonReader.TokenType is not one of the expected types: False, Number, True, Null, String, StartArray, StartObject. Is: '{reader.TokenType}'.");
                    return null;
            }
        }

        internal static bool IsReaderAtTokenType(ref Utf8JsonReader reader, JsonTokenType tokenType, bool advanceReader)
        {
            if (reader.TokenType == JsonTokenType.None)
                ReaderRead(ref reader);

            if (reader.TokenType != tokenType)
                return false;

            if (advanceReader)
                ReaderRead(ref reader);

            return true;
        }

        internal static bool ReaderRead(ref Utf8JsonReader reader)
        {
            try
            {
                return reader.Read();
            }
            catch (JsonException ex)
            {
                throw new JsonException(ex.Message, ex);
            }
        }

        internal static bool ReadBoolean(ref Utf8JsonReader reader, string propertyName, string className)
        {
            if (reader.TokenType == JsonTokenType.True || reader.TokenType == JsonTokenType.False)
                return reader.GetBoolean();

            throw LogHelper.LogExceptionMessage(
                CreateJsonReaderException(ref reader, "JsonTokenType.False or JsonTokenType.True", className, propertyName));
        }

        internal static double ReadDouble(ref Utf8JsonReader reader, string propertyName, string className)
        {
            if (reader.TokenType == JsonTokenType.Number)
            {
                try
                {
                    return reader.GetDouble();
                }
                catch (Exception ex)
                {
                    throw LogHelper.LogExceptionMessage(
                        CreateJsonReaderException(ref reader, typeof(double).ToString(), className, propertyName, ex));
                }
            }

            throw LogHelper.LogExceptionMessage(
                CreateJsonReaderException(ref reader, "JsonTokenType.Number", className, propertyName));
        }

        internal static int ReadInt(ref Utf8JsonReader reader, string propertyName, string className)
        {
            if (reader.TokenType == JsonTokenType.Number)
            {
                try
                {
                    return reader.GetInt32();
                }
                catch (Exception ex)
                {
                    throw LogHelper.LogExceptionMessage(
                        CreateJsonReaderException(ref reader, typeof(int).ToString(), className, propertyName, ex));
                }
            }

            throw LogHelper.LogExceptionMessage(
                CreateJsonReaderException(ref reader, "JsonTokenType.Number", className, propertyName));
        }

        internal static JsonElement ReadJsonElement(ref Utf8JsonReader reader)
        {
#if NET6_0_OR_GREATER
            JsonElement? jsonElement;
            bool ret = JsonElement.TryParseValue(ref reader, out jsonElement);
            if (ret)
                return jsonElement.Value;

            return default;
#else
            using (JsonDocument jsonDocument = JsonDocument.ParseValue(ref reader))
                return jsonDocument.RootElement.Clone();
#endif
        }

        /// <summary>
        /// Currently used by test code only
        /// </summary>
        /// <param name="reader"></param>
        /// <param name="objects"></param>
        /// <param name="propertyName"></param>
        /// <param name="className"></param>
        /// <returns></returns>
        internal static IList<object> ReadObjects(ref Utf8JsonReader reader, IList<object> objects, string propertyName, string className)
        {
            _ = objects ?? throw LogHelper.LogExceptionMessage(new ArgumentNullException(nameof(objects)));

            // returning null keeps the same logic as JsonSerialization.ReadObject
            if (reader.TokenType == JsonTokenType.Null)
                return null;

            if (!IsReaderAtTokenType(ref reader, JsonTokenType.StartArray, false))
                throw LogHelper.LogExceptionMessage(
                    CreateJsonReaderExceptionInvalidType(ref reader, "JsonTokenType.StartArray", className, propertyName));

            while (ReaderRead(ref reader))
            {
                if (IsReaderAtTokenType(ref reader, JsonTokenType.EndArray, true))
                    break;

                objects.Add(ReadJsonElement(ref reader));
            } 

            return objects;
        }

        internal static string ReadString(ref Utf8JsonReader reader, string propertyName, string className)
        {
            // returning null keeps the same logic as JsonSerialization.ReadObject
            if (reader.TokenType == JsonTokenType.Null)
                return null;

            if (reader.TokenType != JsonTokenType.String)
                throw LogHelper.LogExceptionMessage(
                    CreateJsonReaderException(ref reader, "JsonTokenType.String", className, propertyName));

            return reader.GetString();
        }

        internal static IList<string> ReadStrings(ref Utf8JsonReader reader, IList<string> strings, string propertyName, string className)
        {
            // returning null keeps the same logic as JsonSerialization.ReadObject
            if (reader.TokenType == JsonTokenType.Null)
                return null;

            if (!IsReaderAtTokenType(ref reader, JsonTokenType.StartArray, false))
                throw LogHelper.LogExceptionMessage(
                    CreateJsonReaderExceptionInvalidType(ref reader, "JsonTokenType.StartArray", className, propertyName));

            while (ReaderRead(ref reader))
            {
                if (IsReaderAtTokenType(ref reader, JsonTokenType.EndArray, false))
                    break;

                strings.Add(ReadString(ref reader, propertyName, className));
            }

            return strings;
        }

        /// <summary>
        /// This method is only called when we are on a JsonTokenType.Number AND reading into AdditionalData which is an IDictionary[string, object].
        /// We have to make a choice of the type to return.
        /// </summary>
        /// <param name="reader"></param>
        /// <returns>If possible a .net numerical type, otherwise a JsonElement.</returns>
        internal static object ReadNumber(ref Utf8JsonReader reader)
        {
            // Assume reader is a Utf8JsonReader positioned at a JsonTokenType.Number
            if (reader.TryGetInt32(out int i))
                return i;
            else if (reader.TryGetInt64(out long l))
                return l;
            else if (reader.TryGetUInt32(out uint u))
                return u;
            else if (reader.TryGetSingle(out float f))
                return f;
            else if (reader.TryGetDouble(out double d))
                return d;
            else if (reader.TryGetDecimal(out decimal m))
                return m;

            Debug.Assert(false, "expected to read a number, but none of the Utf8JsonReader.TryGet... methods returned true.");

            return ReadJsonElement(ref reader);
        }

        internal static void WriteAdditionalData(ref Utf8JsonWriter writer, IDictionary<string, object> additionalData)
        {
            if (additionalData.Count > 0)
            {
                foreach (KeyValuePair<string,object> kvp in additionalData)
                {
                    if (kvp.Value is string)
                        writer.WriteString(kvp.Key, kvp.Value as string);
                    else if (kvp.Value is int)
                         writer.WriteNumber(kvp.Key, (int)kvp.Value);
                    else if (kvp.Value is bool)
                        writer.WriteBoolean(kvp.Key, (bool)kvp.Value);
                    else if (kvp.Value is decimal)
                        writer.WriteNumber(kvp.Key, (decimal)kvp.Value);
                    else if (kvp.Value is double)
                        writer.WriteNumber(kvp.Key, (double)kvp.Value);
                    else if (kvp.Value is float)
                        writer.WriteNumber(kvp.Key, (float)kvp.Value);
                    else if (kvp.Value is long)
                        writer.WriteNumber(kvp.Key, (long)kvp.Value);
                    else if (kvp.Value is null)
                        writer.WriteNull(kvp.Key);
                    else if (kvp.Value is JsonElement element)
                    {
                        writer.WritePropertyName(kvp.Key);
                        element.WriteTo(writer);
                    }
                    else
                    {
                        writer.WriteString(kvp.Key, kvp.Value.ToString());
                    }
                }
            }
        }

        internal static void WriteStrings(ref Utf8JsonWriter writer, string propertyName, IList<string> strings)
        {
            writer.WritePropertyName(propertyName);
            writer.WriteStartArray();
            foreach (string str in strings)
                writer.WriteStringValue(str);

            writer.WriteEndArray();
        }

        internal static void WriteStrings(ref Utf8JsonWriter writer, JsonEncodedText propertyName, IList<string> strings)
        {
            writer.WritePropertyName(propertyName);
            writer.WriteStartArray();
            foreach (string str in strings)
                writer.WriteStringValue(str);

            writer.WriteEndArray();
        }
    }
}
