// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Tokens.Json
{
    internal static class JsonWebKeySerializer
    {
        public static HashSet<string> JsonWebKeyParameterNamesUpperCase = new HashSet<string>
        {
            "ALG",
            "CRV",
            "D",
            "DP",
            "DQ",
            "E",
            "K",
            "KEY_OPS",
            "KEYS",
            "KID",
            "KTY",
            "N",
            "OTH",
            "P",
            "Q",
            "QI",
            "USE",
            "X",
            "X5C",
            "X5T",
            "X5T#S256",
            "X5U",
            "Y"
        };

        #region Read
        public static JsonWebKey Read(string json)
        {
            return Read(json, new JsonWebKey());
        }

        public static JsonWebKey Read(string json, JsonWebKey jsonWebKey)
        {
            Utf8JsonReader reader = new(Encoding.UTF8.GetBytes(json).AsSpan());
            return Read(ref reader, jsonWebKey);
        }

        /// <summary>
        /// Reads a JsonWebKey. see: https://datatracker.ietf.org/doc/html/rfc7517
        /// </summary>
        /// <param name="reader">a <see cref="Utf8JsonReader"/> pointing at a StartObject.</param>
        /// <param name="jsonWebKey"></param>
        /// <returns>A <see cref="JsonWebKey"/>.</returns>
        public static JsonWebKey Read(ref Utf8JsonReader reader, JsonWebKey jsonWebKey)
        {
            if (!JsonSerializerPrimitives.IsReaderAtTokenType(ref reader, JsonTokenType.StartObject, false))
                throw LogHelper.LogExceptionMessage(
                    new JsonException(
                        LogHelper.FormatInvariant(
                        LogMessages.IDX11023,
                        LogHelper.MarkAsNonPII("JsonTokenType.StartObject"),
                        LogHelper.MarkAsNonPII(reader.TokenType),
                        LogHelper.MarkAsNonPII(JsonWebKey.ClassName),
                        LogHelper.MarkAsNonPII(reader.TokenStartIndex),
                        LogHelper.MarkAsNonPII(reader.CurrentDepth),
                        LogHelper.MarkAsNonPII(reader.BytesConsumed))));

            while(JsonSerializerPrimitives.ReaderRead(ref reader))
            {
                #region Check property name using ValueTextEquals
                // common names are tried first
                // the JsonWebKey spec, https://datatracker.ietf.org/doc/html/rfc7517#section-4, does not require that we reject JSON with
                // duplicate member names, in strict mode, we could add logic to try a property once and throw if a duplicate shows up.
                // 6x uses the last value.
                if (reader.TokenType == JsonTokenType.PropertyName)
                {
                    if (reader.ValueTextEquals(JsonWebKeyParameterUtf8Bytes.K))
                    {
                        JsonSerializerPrimitives.ReaderRead(ref reader);
                        jsonWebKey.K = JsonSerializerPrimitives.ReadString(ref reader, JsonWebKeyParameterNames.K, JsonWebKey.ClassName);
                    }
                    else if (reader.ValueTextEquals(JsonWebKeyParameterUtf8Bytes.E))
                    {
                        JsonSerializerPrimitives.ReaderRead(ref reader);
                        jsonWebKey.E = JsonSerializerPrimitives.ReadString(ref reader, JsonWebKeyParameterNames.E, JsonWebKey.ClassName);
                    }
                    else if (reader.ValueTextEquals(JsonWebKeyParameterUtf8Bytes.Kid))
                    {
                        JsonSerializerPrimitives.ReaderRead(ref reader);
                        jsonWebKey.Kid = JsonSerializerPrimitives.ReadString(ref reader, JsonWebKeyParameterNames.Kid, JsonWebKey.ClassName);
                    }
                    else if (reader.ValueTextEquals(JsonWebKeyParameterUtf8Bytes.Kty))
                    {
                        JsonSerializerPrimitives.ReaderRead(ref reader);
                        jsonWebKey.Kty = JsonSerializerPrimitives.ReadString(ref reader, JsonWebKeyParameterNames.Kty, JsonWebKey.ClassName);
                    }
                    else if (reader.ValueTextEquals(JsonWebKeyParameterUtf8Bytes.N))
                    {
                        JsonSerializerPrimitives.ReaderRead(ref reader);
                        jsonWebKey.N = JsonSerializerPrimitives.ReadString(ref reader, JsonWebKeyParameterNames.N, JsonWebKey.ClassName);
                    }
                    else if (reader.ValueTextEquals(JsonWebKeyParameterUtf8Bytes.X5c))
                    {
                        JsonSerializerPrimitives.ReaderRead(ref reader);
                        JsonSerializerPrimitives.ReadStrings(ref reader, jsonWebKey.X5c, JsonWebKeyParameterNames.X5c, JsonWebKey.ClassName);
                    }
                    else if (reader.ValueTextEquals(JsonWebKeyParameterUtf8Bytes.Alg))
                    {
                        JsonSerializerPrimitives.ReaderRead(ref reader);
                        jsonWebKey.Alg = JsonSerializerPrimitives.ReadString(ref reader, JsonWebKeyParameterNames.Alg, JsonWebKey.ClassName);
                    }
                    else if (reader.ValueTextEquals(JsonWebKeyParameterUtf8Bytes.Crv))
                    {
                        JsonSerializerPrimitives.ReaderRead(ref reader);
                        jsonWebKey.Crv = JsonSerializerPrimitives.ReadString(ref reader, JsonWebKeyParameterNames.Crv, JsonWebKey.ClassName);
                    }
                    else if (reader.ValueTextEquals(JsonWebKeyParameterUtf8Bytes.D))
                    {
                        JsonSerializerPrimitives.ReaderRead(ref reader);
                        jsonWebKey.D = JsonSerializerPrimitives.ReadString(ref reader, JsonWebKeyParameterNames.D, JsonWebKey.ClassName);
                    }
                    else if (reader.ValueTextEquals(JsonWebKeyParameterUtf8Bytes.DP))
                    {
                        JsonSerializerPrimitives.ReaderRead(ref reader);
                        jsonWebKey.DP = JsonSerializerPrimitives.ReadString(ref reader, JsonWebKeyParameterNames.DP, JsonWebKey.ClassName);
                    }
                    else if (reader.ValueTextEquals(JsonWebKeyParameterUtf8Bytes.DQ))
                    {
                        JsonSerializerPrimitives.ReaderRead(ref reader);
                        jsonWebKey.DQ = JsonSerializerPrimitives.ReadString(ref reader, JsonWebKeyParameterNames.DQ, JsonWebKey.ClassName);
                    }
                    else if (reader.ValueTextEquals(JsonWebKeyParameterUtf8Bytes.KeyOps))
                    {
                        JsonSerializerPrimitives.ReaderRead(ref reader);
                        // the value can be null if the value is 'nill'
                        if (JsonSerializerPrimitives.ReadStrings(ref reader, jsonWebKey.KeyOps, JsonWebKeyParameterNames.KeyOps, JsonWebKey.ClassName) == null)
                        {
                            throw LogHelper.LogExceptionMessage(
                                new ArgumentNullException(
                                    JsonWebKeyParameterNames.KeyOps,
                                    new JsonException(
                                        LogHelper.FormatInvariant(
                                        LogMessages.IDX11022,
                                        LogHelper.MarkAsNonPII("JsonTokenType.StartArray"),
                                        LogHelper.MarkAsNonPII(reader.TokenType),
                                        LogHelper.MarkAsNonPII(JsonWebKey.ClassName),
                                        LogHelper.MarkAsNonPII(JsonWebKeyParameterNames.KeyOps),
                                        LogHelper.MarkAsNonPII(reader.TokenStartIndex),
                                        LogHelper.MarkAsNonPII(reader.CurrentDepth),
                                        LogHelper.MarkAsNonPII(reader.BytesConsumed)))));
                        }
                    }
                    else if (reader.ValueTextEquals(JsonWebKeyParameterUtf8Bytes.Oth))
                    {
                        JsonSerializerPrimitives.ReaderRead(ref reader);
                        JsonSerializerPrimitives.ReadStrings(ref reader, jsonWebKey.Oth, JsonWebKeyParameterNames.Oth, JsonWebKey.ClassName);
                    }
                    else if (reader.ValueTextEquals(JsonWebKeyParameterUtf8Bytes.P))
                    {
                        JsonSerializerPrimitives.ReaderRead(ref reader);
                        jsonWebKey.P = JsonSerializerPrimitives.ReadString(ref reader, JsonWebKeyParameterNames.P, JsonWebKey.ClassName);
                    }
                    else if (reader.ValueTextEquals(JsonWebKeyParameterUtf8Bytes.Q))
                    {
                        JsonSerializerPrimitives.ReaderRead(ref reader);
                        jsonWebKey.Q = JsonSerializerPrimitives.ReadString(ref reader, JsonWebKeyParameterNames.Q, JsonWebKey.ClassName);
                    }
                    else if (reader.ValueTextEquals(JsonWebKeyParameterUtf8Bytes.QI))
                    {
                        JsonSerializerPrimitives.ReaderRead(ref reader);
                        jsonWebKey.QI = JsonSerializerPrimitives.ReadString(ref reader, JsonWebKeyParameterNames.QI, JsonWebKey.ClassName);
                    }
                    else if (reader.ValueTextEquals(JsonWebKeyParameterUtf8Bytes.Use))
                    {
                        JsonSerializerPrimitives.ReaderRead(ref reader);
                        jsonWebKey.Use = JsonSerializerPrimitives.ReadString(ref reader, JsonWebKeyParameterNames.Use, JsonWebKey.ClassName);
                    }
                    else if (reader.ValueTextEquals(JsonWebKeyParameterUtf8Bytes.X))
                    {
                        JsonSerializerPrimitives.ReaderRead(ref reader);
                        jsonWebKey.X = JsonSerializerPrimitives.ReadString(ref reader, JsonWebKeyParameterNames.X, JsonWebKey.ClassName);
                    }
                    else if (reader.ValueTextEquals(JsonWebKeyParameterUtf8Bytes.X5t))
                    {
                        JsonSerializerPrimitives.ReaderRead(ref reader);
                        jsonWebKey.X5t = JsonSerializerPrimitives.ReadString(ref reader, JsonWebKeyParameterNames.X5t, JsonWebKey.ClassName);
                    }
                    else if (reader.ValueTextEquals(JsonWebKeyParameterUtf8Bytes.X5tS256))
                    {
                        JsonSerializerPrimitives.ReaderRead(ref reader);
                        jsonWebKey.X5tS256 = JsonSerializerPrimitives.ReadString(ref reader, JsonWebKeyParameterNames.X5tS256, JsonWebKey.ClassName);
                    }
                    else if (reader.ValueTextEquals(JsonWebKeyParameterUtf8Bytes.X5u))
                    {
                        JsonSerializerPrimitives.ReaderRead(ref reader);
                        jsonWebKey.X5u = JsonSerializerPrimitives.ReadString(ref reader, JsonWebKeyParameterNames.X5u, JsonWebKey.ClassName);
                    }
                    else if (reader.ValueTextEquals(JsonWebKeyParameterUtf8Bytes.Y))
                    {
                        JsonSerializerPrimitives.ReaderRead(ref reader);
                        jsonWebKey.Y = JsonSerializerPrimitives.ReadString(ref reader, JsonWebKeyParameterNames.Y, JsonWebKey.ClassName);
                    }
                    #endregion
                    else
                    {
                        #region case-insensitive
                        // fallback to checking property names as case insensitive
                        // first check to see if the upper case property value is a valid property name if not add to AdditionalData, to avoid unnecessary string compares.
                        string propertyName = JsonSerializerPrimitives.GetPropertyName(ref reader, JsonWebKey.ClassName, true);
                        if (!JsonWebKeyParameterNamesUpperCase.Contains(propertyName.ToUpperInvariant()))
                        {
                            jsonWebKey.AdditionalData[propertyName] = JsonSerializerPrimitives.GetUnknownProperty(ref reader);
                        }
                        else
                        {
                            if (propertyName.Equals(JsonWebKeyParameterNames.E, StringComparison.OrdinalIgnoreCase))
                            {
                                jsonWebKey.E = JsonSerializerPrimitives.ReadString(ref reader, JsonWebKeyParameterNames.E, JsonWebKey.ClassName);
                            }
                            else if (propertyName.Equals(JsonWebKeyParameterNames.Kid, StringComparison.OrdinalIgnoreCase))
                            {
                                jsonWebKey.Kid = JsonSerializerPrimitives.ReadString(ref reader, JsonWebKeyParameterNames.Kid, JsonWebKey.ClassName);
                            }
                            else if (propertyName.Equals(JsonWebKeyParameterNames.Kty, StringComparison.OrdinalIgnoreCase))
                            {
                                jsonWebKey.Kty = JsonSerializerPrimitives.ReadString(ref reader, JsonWebKeyParameterNames.Kty, JsonWebKey.ClassName);
                            }
                            else if (propertyName.Equals(JsonWebKeyParameterNames.N, StringComparison.OrdinalIgnoreCase))
                            {
                                jsonWebKey.N = JsonSerializerPrimitives.ReadString(ref reader, JsonWebKeyParameterNames.N, JsonWebKey.ClassName);
                            }
                            else if (propertyName.Equals(JsonWebKeyParameterNames.Use, StringComparison.OrdinalIgnoreCase))
                            {
                                jsonWebKey.Use = JsonSerializerPrimitives.ReadString(ref reader, JsonWebKeyParameterNames.Use, JsonWebKey.ClassName);
                            }
                            else if (propertyName.Equals(JsonWebKeyParameterNames.Alg, StringComparison.OrdinalIgnoreCase))
                            {
                                jsonWebKey.Alg = JsonSerializerPrimitives.ReadString(ref reader, JsonWebKeyParameterNames.Alg, JsonWebKey.ClassName);
                            }
                            else if (propertyName.Equals(JsonWebKeyParameterNames.Crv, StringComparison.OrdinalIgnoreCase))
                            {
                                jsonWebKey.Crv = JsonSerializerPrimitives.ReadString(ref reader, JsonWebKeyParameterNames.Crv, JsonWebKey.ClassName);
                            }
                            else if (propertyName.Equals(JsonWebKeyParameterNames.D, StringComparison.OrdinalIgnoreCase))
                            {
                                jsonWebKey.D = JsonSerializerPrimitives.ReadString(ref reader, JsonWebKeyParameterNames.D, JsonWebKey.ClassName);
                            }
                            else if (propertyName.Equals(JsonWebKeyParameterNames.DP, StringComparison.OrdinalIgnoreCase))
                            {
                                jsonWebKey.DP = JsonSerializerPrimitives.ReadString(ref reader, JsonWebKeyParameterNames.DP, JsonWebKey.ClassName);
                            }
                            else if (propertyName.Equals(JsonWebKeyParameterNames.DQ, StringComparison.OrdinalIgnoreCase))
                            {
                                jsonWebKey.DQ = JsonSerializerPrimitives.ReadString(ref reader, JsonWebKeyParameterNames.DQ, JsonWebKey.ClassName);
                            }
                            else if (propertyName.Equals(JsonWebKeyParameterNames.K, StringComparison.OrdinalIgnoreCase))
                            {
                                jsonWebKey.K = JsonSerializerPrimitives.ReadString(ref reader, JsonWebKeyParameterNames.K, JsonWebKey.ClassName);
                            }
                            else if (propertyName.Equals(JsonWebKeyParameterNames.KeyOps, StringComparison.OrdinalIgnoreCase))
                            {
                                // the value can be null if the value is 'nill'
                                if (JsonSerializerPrimitives.ReadStrings(ref reader, jsonWebKey.KeyOps, JsonWebKeyParameterNames.KeyOps, JsonWebKey.ClassName) == null)
                                {
                                    throw LogHelper.LogExceptionMessage(
                                        new ArgumentNullException(
                                            JsonWebKeyParameterNames.KeyOps,
                                            new JsonException(
                                                LogHelper.FormatInvariant(
                                                LogMessages.IDX11022,
                                                LogHelper.MarkAsNonPII("JsonTokenType.StartArray"),
                                                LogHelper.MarkAsNonPII(reader.TokenType),
                                                LogHelper.MarkAsNonPII(JsonWebKey.ClassName),
                                                LogHelper.MarkAsNonPII(JsonWebKeyParameterNames.KeyOps),
                                                LogHelper.MarkAsNonPII(reader.TokenStartIndex),
                                                LogHelper.MarkAsNonPII(reader.CurrentDepth),
                                                LogHelper.MarkAsNonPII(reader.BytesConsumed)))));
                                }
                            }
                            else if (propertyName.Equals(JsonWebKeyParameterNames.Oth, StringComparison.OrdinalIgnoreCase))
                            {
                                JsonSerializerPrimitives.ReadStrings(ref reader, jsonWebKey.Oth, JsonWebKeyParameterNames.Oth, JsonWebKey.ClassName);
                            }
                            else if (propertyName.Equals(JsonWebKeyParameterNames.P, StringComparison.OrdinalIgnoreCase))
                            {
                                jsonWebKey.P = JsonSerializerPrimitives.ReadString(ref reader, JsonWebKeyParameterNames.P, JsonWebKey.ClassName);
                            }
                            else if (propertyName.Equals(JsonWebKeyParameterNames.Q, StringComparison.OrdinalIgnoreCase))
                            {
                                jsonWebKey.Q = JsonSerializerPrimitives.ReadString(ref reader, JsonWebKeyParameterNames.Q, JsonWebKey.ClassName);
                            }
                            else if (propertyName.Equals(JsonWebKeyParameterNames.QI, StringComparison.OrdinalIgnoreCase))
                            {
                                jsonWebKey.QI = JsonSerializerPrimitives.ReadString(ref reader, JsonWebKeyParameterNames.QI, JsonWebKey.ClassName);
                            }
                            else if (propertyName.Equals(JsonWebKeyParameterNames.X, StringComparison.OrdinalIgnoreCase))
                            {
                                jsonWebKey.X = JsonSerializerPrimitives.ReadString(ref reader, JsonWebKeyParameterNames.X, JsonWebKey.ClassName);
                            }
                            else if (propertyName.Equals(JsonWebKeyParameterNames.X5c, StringComparison.OrdinalIgnoreCase))
                            {
                                JsonSerializerPrimitives.ReadStrings(ref reader, jsonWebKey.X5c, JsonWebKeyParameterNames.X5c, JsonWebKey.ClassName);
                            }
                            else if (propertyName.Equals(JsonWebKeyParameterNames.X5t, StringComparison.OrdinalIgnoreCase))
                            {
                                jsonWebKey.X5t = JsonSerializerPrimitives.ReadString(ref reader, JsonWebKeyParameterNames.X5t, JsonWebKey.ClassName);
                            }
                            else if (propertyName.Equals(JsonWebKeyParameterNames.X5tS256, StringComparison.OrdinalIgnoreCase))
                            {
                                jsonWebKey.X5tS256 = JsonSerializerPrimitives.ReadString(ref reader, JsonWebKeyParameterNames.X5tS256, JsonWebKey.ClassName);
                            }
                            else if (propertyName.Equals(JsonWebKeyParameterNames.X5u, StringComparison.OrdinalIgnoreCase))
                            {
                                jsonWebKey.X5u = JsonSerializerPrimitives.ReadString(ref reader, JsonWebKeyParameterNames.X5u, JsonWebKey.ClassName);
                            }
                            else if (propertyName.Equals(JsonWebKeyParameterNames.Y, StringComparison.OrdinalIgnoreCase))
                            {
                                jsonWebKey.Y = JsonSerializerPrimitives.ReadString(ref reader, JsonWebKeyParameterNames.Y, JsonWebKey.ClassName);
                            }
                        }
                        #endregion case-insensitive
                    }
                }
                else if (JsonSerializerPrimitives.IsReaderAtTokenType(ref reader, JsonTokenType.EndObject, false))
                    break;
            }

            return jsonWebKey;
        }
        #endregion

        #region Write
        public static string Write(JsonWebKey jsonWebKey)
        {
            using (MemoryStream memoryStream = new MemoryStream())
            {
                Utf8JsonWriter writer = null;
                try
                {
                    writer = new Utf8JsonWriter(memoryStream, new JsonWriterOptions { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping });
                    Write(ref writer, jsonWebKey);
                    writer.Flush();
                    return Encoding.UTF8.GetString(memoryStream.ToArray());
                }
                finally
                {
                    writer?.Dispose();
                }
            }
        }

        public static void Write(ref Utf8JsonWriter writer, JsonWebKey jsonWebKey)
        {
            _ = jsonWebKey ?? throw new ArgumentNullException(nameof(jsonWebKey));
            _ = writer ?? throw new ArgumentNullException(nameof(writer));

            writer.WriteStartObject();

            if (!string.IsNullOrEmpty(jsonWebKey.Alg))
                writer.WriteString(EncodedJsonWebKeyParameterNames.Alg, jsonWebKey.Alg);

            if (!string.IsNullOrEmpty(jsonWebKey.Crv))
                writer.WriteString(EncodedJsonWebKeyParameterNames.Crv, jsonWebKey.Crv);

            if (!string.IsNullOrEmpty(jsonWebKey.D))
                writer.WriteString(EncodedJsonWebKeyParameterNames.D, jsonWebKey.D);

            if (!string.IsNullOrEmpty(jsonWebKey.DP))
                writer.WriteString(EncodedJsonWebKeyParameterNames.DP, jsonWebKey.DP);

            if (!string.IsNullOrEmpty(jsonWebKey.DQ))
                writer.WriteString(EncodedJsonWebKeyParameterNames.DQ, jsonWebKey.DQ);

            if (!string.IsNullOrEmpty(jsonWebKey.E))
                writer.WriteString(EncodedJsonWebKeyParameterNames.E, jsonWebKey.E);

            if (!string.IsNullOrEmpty(jsonWebKey.K))
                writer.WriteString(EncodedJsonWebKeyParameterNames.K, jsonWebKey.K);

            if (jsonWebKey.KeyOps.Count > 0)
                JsonSerializerPrimitives.WriteStrings(ref writer, EncodedJsonWebKeyParameterNames.KeyOps, jsonWebKey.KeyOps);

            if (!string.IsNullOrEmpty(jsonWebKey.Kid))
                writer.WriteString(EncodedJsonWebKeyParameterNames.Kid, jsonWebKey.Kid);

            if (!string.IsNullOrEmpty(jsonWebKey.Kty))
                writer.WriteString(EncodedJsonWebKeyParameterNames.Kty, jsonWebKey.Kty);

            if (!string.IsNullOrEmpty(jsonWebKey.N))
                writer.WriteString(EncodedJsonWebKeyParameterNames.N, jsonWebKey.N);

            if (jsonWebKey.Oth.Count > 0)
                JsonSerializerPrimitives.WriteStrings(ref writer, EncodedJsonWebKeyParameterNames.Oth, jsonWebKey.Oth);

            if (!string.IsNullOrEmpty(jsonWebKey.P))
                writer.WriteString(EncodedJsonWebKeyParameterNames.P, jsonWebKey.P);

            if (!string.IsNullOrEmpty(jsonWebKey.Q))
                writer.WriteString(EncodedJsonWebKeyParameterNames.Q, jsonWebKey.Q);

            if (!string.IsNullOrEmpty(jsonWebKey.QI))
                writer.WriteString(EncodedJsonWebKeyParameterNames.QI, jsonWebKey.QI);

            if (!string.IsNullOrEmpty(jsonWebKey.Use))
                writer.WriteString(EncodedJsonWebKeyParameterNames.Use, jsonWebKey.Use);

            if (!string.IsNullOrEmpty(jsonWebKey.X))
                writer.WriteString(EncodedJsonWebKeyParameterNames.X, jsonWebKey.X);

            if (jsonWebKey.X5c.Count > 0)
                JsonSerializerPrimitives.WriteStrings(ref writer, EncodedJsonWebKeyParameterNames.X5c, jsonWebKey.X5c);

            if (!string.IsNullOrEmpty(jsonWebKey.X5t))
                writer.WriteString(EncodedJsonWebKeyParameterNames.X5t, jsonWebKey.X5t);

            if (!string.IsNullOrEmpty(jsonWebKey.X5tS256))
                writer.WriteString(EncodedJsonWebKeyParameterNames.X5tS256, jsonWebKey.X5tS256);

            if (!string.IsNullOrEmpty(jsonWebKey.X5u))
                writer.WriteString(EncodedJsonWebKeyParameterNames.X5u, jsonWebKey.X5u);

            if (!string.IsNullOrEmpty(jsonWebKey.Y))
                writer.WriteString(EncodedJsonWebKeyParameterNames.Y, jsonWebKey.Y);

            JsonSerializerPrimitives.WriteAdditionalData(ref writer, jsonWebKey.AdditionalData);

            writer.WriteEndObject();
        }
        #endregion
    }
}

