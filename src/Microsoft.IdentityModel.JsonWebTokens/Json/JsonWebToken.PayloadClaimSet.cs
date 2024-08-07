// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Text.Json;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens.Json;

namespace Microsoft.IdentityModel.JsonWebTokens
{
    public partial class JsonWebToken
    {
        internal JsonClaimSet CreatePayloadClaimSet(byte[] bytes, int length)
        {
            return CreatePayloadClaimSet(bytes.AsMemory(0, length));
        }

        internal JsonClaimSet CreatePayloadClaimSet(Memory<byte> tokenPayloadAsMemory)
        {
            if (tokenPayloadAsMemory.Length == 0)
                return new JsonClaimSet([]);

            Utf8JsonReader reader = new(tokenPayloadAsMemory.Span);
            if (!JsonSerializerPrimitives.IsReaderAtTokenType(ref reader, JsonTokenType.StartObject, true))
                throw LogHelper.LogExceptionMessage(
                    new JsonException(
                        LogHelper.FormatInvariant(
                        Tokens.LogMessages.IDX11023,
                        LogHelper.MarkAsNonPII("JsonTokenType.StartObject"),
                        LogHelper.MarkAsNonPII(reader.TokenType),
                        LogHelper.MarkAsNonPII(ClassName),
                        LogHelper.MarkAsNonPII(reader.TokenStartIndex),
                        LogHelper.MarkAsNonPII(reader.CurrentDepth),
                        LogHelper.MarkAsNonPII(reader.BytesConsumed))));

            Dictionary<string, object> claims = [];

            while (true)
            {
                if (reader.TokenType == JsonTokenType.PropertyName)
                {
                    string claimName = reader.GetString();
                    claims[claimName] = ReadTokenPayloadValueDelegate(ref reader, claimName);
                }
                // We read a JsonTokenType.StartObject above, exiting and positioning reader at next token.
                else if (JsonSerializerPrimitives.IsReaderAtTokenType(ref reader, JsonTokenType.EndObject, false))
                    break;
                else if (!reader.Read())
                    break;
            };

#if NET8_0_OR_GREATER
            return new JsonClaimSet(claims, tokenPayloadAsMemory);
#else
            return new JsonClaimSet(claims);
#endif
        }

        /// <summary>
        /// Reads and saves the value of the payload claim from the reader.
        /// </summary>
        /// <param name="reader">The reader over the JWT.</param>
        /// <param name="claimName">The claim at the current position of the reader.</param>
        /// <returns>A claim that was read.</returns>
        public static object ReadTokenPayloadValue(ref Utf8JsonReader reader, string claimName)
        {
            if (reader.ValueTextEquals(JwtPayloadUtf8Bytes.Aud))
            {
                List<string> _audiences = [];
                reader.Read();
                if (reader.TokenType == JsonTokenType.StartArray)
                {
                    JsonSerializerPrimitives.ReadStringsSkipNulls(ref reader, _audiences, JwtRegisteredClaimNames.Aud, ClassName);
                }
                else
                {
                    if (reader.TokenType != JsonTokenType.Null)
                    {
                        _audiences.Add(JsonSerializerPrimitives.ReadString(ref reader, JwtRegisteredClaimNames.Aud, ClassName));
                    }
                }
                return _audiences;
            }
            else if (reader.ValueTextEquals(JwtPayloadUtf8Bytes.Azp))
            {
#if NET8_0_OR_GREATER
                return JsonSerializerPrimitives.ReadStringBytesLocation(ref reader, JwtRegisteredClaimNames.Azp, ClassName, true);
#else
                return JsonSerializerPrimitives.ReadString(ref reader, JwtRegisteredClaimNames.Azp, ClassName, true);
#endif
            }
            else if (reader.ValueTextEquals(JwtPayloadUtf8Bytes.Exp))
            {
                return JsonSerializerPrimitives.ReadLong(ref reader, JwtRegisteredClaimNames.Exp, ClassName, true);
            }
            else if (reader.ValueTextEquals(JwtPayloadUtf8Bytes.Iat))
            {
                return JsonSerializerPrimitives.ReadLong(ref reader, JwtRegisteredClaimNames.Iat, ClassName, true);
            }
            else if (reader.ValueTextEquals(JwtPayloadUtf8Bytes.Iss))
            {
#if NET8_0_OR_GREATER
                return JsonSerializerPrimitives.ReadStringBytesLocation(ref reader, JwtRegisteredClaimNames.Iss, ClassName, true);
#else
                return JsonSerializerPrimitives.ReadString(ref reader, JwtRegisteredClaimNames.Iss, ClassName, true);
#endif
            }
            else if (reader.ValueTextEquals(JwtPayloadUtf8Bytes.Jti))
            {
#if NET8_0_OR_GREATER
                return JsonSerializerPrimitives.ReadStringBytesLocation(ref reader, JwtRegisteredClaimNames.Jti, ClassName, true);
#else
                return JsonSerializerPrimitives.ReadString(ref reader, JwtRegisteredClaimNames.Jti, ClassName, true);
#endif
            }
            else if (reader.ValueTextEquals(JwtPayloadUtf8Bytes.Nbf))
            {
                return JsonSerializerPrimitives.ReadLong(ref reader, JwtRegisteredClaimNames.Nbf, ClassName, true);
            }
            else if (reader.ValueTextEquals(JwtPayloadUtf8Bytes.Sub))
            {
                return JsonSerializerPrimitives.ReadStringOrNumberAsString(ref reader, JwtRegisteredClaimNames.Sub, ClassName, true);
            }

            return JsonSerializerPrimitives.ReadPropertyValueAsObject(ref reader, claimName, JsonClaimSet.ClassName, true);
        }
    }
}
