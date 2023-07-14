// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Collections.Generic;
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
                reader.Read();

            if (reader.TokenType != JsonTokenType.PropertyName)
                throw LogHelper.LogExceptionMessage(CreateJsonReaderExceptionInvalidType(ref reader, "JsonTokenType.PropertyName", string.Empty, className));

            if (advanceReader)
            {
                string propertyName = reader.GetString();
                reader.Read();
                return propertyName;
            }

            return reader.GetString();
        }

        internal static bool IsReaderAtTokenType(ref Utf8JsonReader reader, JsonTokenType tokenType, bool advanceReader)
        {
            if (reader.TokenType == JsonTokenType.None)
                reader.Read();

            if (reader.TokenType != tokenType)
                return false;

            if (advanceReader)
                reader.Read();

            return true;
        }

        internal static bool ReadBoolean(ref Utf8JsonReader reader, string propertyName, string className, bool advanceReader)
        {
            if (reader.TokenType == JsonTokenType.True || reader.TokenType == JsonTokenType.False)
            {
                bool retVal = reader.GetBoolean();
                if (advanceReader)
                    reader.Read();

                return retVal;
            }

            throw LogHelper.LogExceptionMessage(
                CreateJsonReaderException(ref reader, "JsonTokenType.False or JsonTokenType.True", className, propertyName));
        }

        internal static double ReadDouble(ref Utf8JsonReader reader, string propertyName, string className, bool advanceReader)
        {
            if (reader.TokenType == JsonTokenType.Number)
            {
                double retVal;
                try
                {
                    retVal = reader.GetDouble();
                }
                catch (Exception ex)
                {
                    throw LogHelper.LogExceptionMessage(
                        CreateJsonReaderException(ref reader, typeof(double).ToString(), className, propertyName, ex));
                }

                if (advanceReader)
                    reader.Read();

                return retVal;
            }

            throw LogHelper.LogExceptionMessage(
                CreateJsonReaderException(ref reader, typeof(double).ToString(), className, propertyName));
        }

        internal static int ReadInt(ref Utf8JsonReader reader, string propertyName, string className, bool advanceReader)
        {
            if (reader.TokenType == JsonTokenType.Number)
            {
                int retVal;
                try
                {
                    retVal = reader.GetInt32();
                }
                catch(Exception ex)
                {
                    throw LogHelper.LogExceptionMessage(
                        CreateJsonReaderException(ref reader, typeof(int).ToString(), className, propertyName, ex));
                }

                if (advanceReader)
                    reader.Read();

                return retVal;
            }

            throw LogHelper.LogExceptionMessage(
                CreateJsonReaderException(ref reader, "JsonTokenType.Number", className, propertyName));
        }

        internal static object ReadObject(ref Utf8JsonReader reader, bool advanceReader)
        {
            object retVal = null;
            using (JsonDocument jsonDocument = JsonDocument.ParseValue(ref reader))
            {
                if (jsonDocument.RootElement.ValueKind == JsonValueKind.Null)
                    return null;

                retVal = jsonDocument.RootElement.Clone();
            }

            if (advanceReader)
                reader.Read();

            return retVal;
        }

        internal static IList<object> ReadObjects(ref Utf8JsonReader reader, IList<object> objects, string propertyName, string className, bool advanceReader)
        {
            // returning null keeps the same logic as JsonSerialization.ReadObject
            if (reader.TokenType == JsonTokenType.Null)
            {
                if (advanceReader)
                    reader.Read();

                return null;
            }

            if (!IsReaderAtTokenType(ref reader, JsonTokenType.StartArray, true))
            {
                throw LogHelper.LogExceptionMessage(
                    CreateJsonReaderExceptionInvalidType(ref reader, "JsonTokenType.StartArray", className, propertyName));
            }

            do
            {
                if (IsReaderAtTokenType(ref reader, JsonTokenType.EndArray, true))
                    break;

                objects.Add(ReadObject(ref reader, false));

            } while (reader.Read());

            return objects;
        }

        internal static string ReadString(ref Utf8JsonReader reader, string propertyName, string className, bool advanceReader)
        {
            if (reader.TokenType == JsonTokenType.Null)
            {
                if (advanceReader)
                    reader.Read();

                return null;
            }

            if (reader.TokenType != JsonTokenType.String)
                throw LogHelper.LogExceptionMessage(
                    CreateJsonReaderException(ref reader, "JsonTokenType.String", className, propertyName));

            string retVal = reader.GetString();
            if (advanceReader)
                reader.Read();

            return retVal;
        }

        internal static IList<string> ReadStrings(ref Utf8JsonReader reader, IList<string> strings, string propertyName, string className, bool advanceReader)
        {
            if (reader.TokenType == JsonTokenType.Null)
            {
                if (advanceReader)
                    reader.Read();

                return null;
            }

            if (!IsReaderAtTokenType(ref reader, JsonTokenType.StartArray, true))
                throw LogHelper.LogExceptionMessage(
                    CreateJsonReaderExceptionInvalidType(ref reader, "JsonTokenType.StartArray", className, propertyName));

            do
            {
                if (IsReaderAtTokenType(ref reader, JsonTokenType.EndArray, true))
                    break;

                strings.Add(ReadString(ref reader, propertyName, className, false));

            } while (reader.Read());

            return strings;
        }

        // used by JsonWebKey which will be in this release
        internal static void WriteStrings(ref Utf8JsonWriter writer, string propertyName, IList<string> strings)
        {
            writer.WritePropertyName(propertyName);
            writer.WriteStartArray();
            foreach (string str in strings)
                writer.WriteStringValue(str);

            writer.WriteEndArray();
        }
    }
}

