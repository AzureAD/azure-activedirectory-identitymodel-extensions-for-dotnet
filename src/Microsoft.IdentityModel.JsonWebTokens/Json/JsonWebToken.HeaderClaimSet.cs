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
        internal JsonClaimSet CreateHeaderClaimSet(byte[] bytes)
        {
            return CreateHeaderClaimSet(bytes.AsMemory());
        }

        internal JsonClaimSet CreateHeaderClaimSet(byte[] bytes, int length)
        {
            return CreateHeaderClaimSet(bytes.AsMemory(0, length));
        }

        internal JsonClaimSet CreateHeaderClaimSet(Memory<byte> tokenHeaderAsMemory)
        {
            Utf8JsonReader reader = new(tokenHeaderAsMemory.Span);
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
                    claims[claimName] = ReadTokenHeaderValueDelegate(ref reader, claimName);
                }
                // We read a JsonTokenType.StartObject above, exiting and positioning reader at next token.
                else if (JsonSerializerPrimitives.IsReaderAtTokenType(ref reader, JsonTokenType.EndObject, false))
                    break;
                else if (!reader.Read())
                    break;
            };

#if NET8_0_OR_GREATER
            return new JsonClaimSet(claims, tokenHeaderAsMemory);
#else
            return new JsonClaimSet(claims);
#endif
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="reader"></param>
        /// <param name="claimName"></param>
        /// <returns></returns>
        public static object ReadTokenHeaderValue(ref Utf8JsonReader reader, string claimName)
        {
#if NET8_0_OR_GREATER
            if (reader.ValueTextEquals(JwtHeaderUtf8Bytes.Alg))
            {
                return JsonSerializerPrimitives.ReadStringBytesLocation(ref reader, JwtHeaderParameterNames.Alg, ClassName, true);
            }
            else if (reader.ValueTextEquals(JwtHeaderUtf8Bytes.Cty))
            {
                return JsonSerializerPrimitives.ReadStringBytesLocation(ref reader, JwtHeaderParameterNames.Cty, ClassName, true);
            }
            else if (reader.ValueTextEquals(JwtHeaderUtf8Bytes.Kid))
            {
                return JsonSerializerPrimitives.ReadStringBytesLocation(ref reader, JwtHeaderParameterNames.Kid, ClassName, true);
            }
            else if (reader.ValueTextEquals(JwtHeaderUtf8Bytes.Typ))
            {
                return JsonSerializerPrimitives.ReadStringBytesLocation(ref reader, JwtHeaderParameterNames.Typ, ClassName, true);
            }
            else if (reader.ValueTextEquals(JwtHeaderUtf8Bytes.X5t))
            {
                return JsonSerializerPrimitives.ReadStringBytesLocation(ref reader, JwtHeaderParameterNames.X5t, ClassName, true);
            }
            else if (reader.ValueTextEquals(JwtHeaderUtf8Bytes.Zip))
            {
                return JsonSerializerPrimitives.ReadStringBytesLocation(ref reader, JwtHeaderParameterNames.Zip, ClassName, true);
            }
#else
            if (reader.ValueTextEquals(JwtHeaderUtf8Bytes.Alg))
            {
                return JsonSerializerPrimitives.ReadString(ref reader, JwtHeaderParameterNames.Alg, ClassName, true);
            }
            else if (reader.ValueTextEquals(JwtHeaderUtf8Bytes.Cty))
            {
                return JsonSerializerPrimitives.ReadString(ref reader, JwtHeaderParameterNames.Cty, ClassName, true);
            }
            else if (reader.ValueTextEquals(JwtHeaderUtf8Bytes.Kid))
            {
                return JsonSerializerPrimitives.ReadString(ref reader, JwtHeaderParameterNames.Kid, ClassName, true);
            }
            else if (reader.ValueTextEquals(JwtHeaderUtf8Bytes.Typ))
            {
                return JsonSerializerPrimitives.ReadString(ref reader, JwtHeaderParameterNames.Typ, ClassName, true);
            }
            else if (reader.ValueTextEquals(JwtHeaderUtf8Bytes.X5t))
            {
                return JsonSerializerPrimitives.ReadString(ref reader, JwtHeaderParameterNames.X5t, ClassName, true);
            }
            else if (reader.ValueTextEquals(JwtHeaderUtf8Bytes.Zip))
            {
                return JsonSerializerPrimitives.ReadString(ref reader, JwtHeaderParameterNames.Zip, ClassName, true);
            }
#endif

            return JsonSerializerPrimitives.ReadPropertyValueAsObject(ref reader, claimName, JsonClaimSet.ClassName, true);
        }
    }
}
