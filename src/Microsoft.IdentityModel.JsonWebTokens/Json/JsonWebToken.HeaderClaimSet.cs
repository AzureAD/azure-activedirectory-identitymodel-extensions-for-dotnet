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
#if NET8_0_OR_GREATER
            Dictionary<string, (int startIndex, int length)?> claimsBytes = [];
#endif
            while (true)
            {
                if (reader.TokenType == JsonTokenType.PropertyName)
                {
#if NET8_0_OR_GREATER
                    ReadHeaderValue(ref reader, claims, claimsBytes, tokenHeaderAsMemory);
#else
                    ReadHeaderValue(ref reader, claims);
#endif
                }
                // We read a JsonTokenType.StartObject above, exiting and positioning reader at next token.
                else if (JsonSerializerPrimitives.IsReaderAtTokenType(ref reader, JsonTokenType.EndObject, false))
                    break;
                else if (!reader.Read())
                    break;
            };

#if NET8_0_OR_GREATER
            return new JsonClaimSet(claims, claimsBytes, tokenHeaderAsMemory);
#else
            return new JsonClaimSet(claims);
#endif
        }

        private protected virtual void ReadHeaderValue(ref Utf8JsonReader reader, IDictionary<string, object> claims)
        {
            _ = claims ?? throw LogHelper.LogArgumentNullException(nameof(claims));

            if (reader.ValueTextEquals(JwtHeaderUtf8Bytes.Alg))
            {
                _alg = JsonSerializerPrimitives.ReadString(ref reader, JwtHeaderParameterNames.Alg, ClassName, true);
                claims[JwtHeaderParameterNames.Alg] = _alg;
            }
            else if (reader.ValueTextEquals(JwtHeaderUtf8Bytes.Cty))
            {
                _cty = JsonSerializerPrimitives.ReadString(ref reader, JwtHeaderParameterNames.Cty, ClassName, true);
                claims[JwtHeaderParameterNames.Cty] = _cty;
            }
            else if (reader.ValueTextEquals(JwtHeaderUtf8Bytes.Kid))
            {
                _kid = JsonSerializerPrimitives.ReadString(ref reader, JwtHeaderParameterNames.Kid, ClassName, true);
                claims[JwtHeaderParameterNames.Kid] = _kid;
            }
            else if (reader.ValueTextEquals(JwtHeaderUtf8Bytes.Typ))
            {
                _typ = JsonSerializerPrimitives.ReadString(ref reader, JwtHeaderParameterNames.Typ, ClassName, true);
                claims[JwtHeaderParameterNames.Typ] = _typ;
            }
            else if (reader.ValueTextEquals(JwtHeaderUtf8Bytes.X5t))
            {
                _x5t = JsonSerializerPrimitives.ReadString(ref reader, JwtHeaderParameterNames.X5t, ClassName, true);
                claims[JwtHeaderParameterNames.X5t] = _x5t;
            }
            else if (reader.ValueTextEquals(JwtHeaderUtf8Bytes.Zip))
            {
                _zip = JsonSerializerPrimitives.ReadString(ref reader, JwtHeaderParameterNames.Zip, ClassName, true);
                claims[JwtHeaderParameterNames.Zip] = _zip;
            }
            else
            {
                string propertyName = reader.GetString();
                claims[propertyName] = JsonSerializerPrimitives.ReadPropertyValueAsObject(ref reader, propertyName, JsonClaimSet.ClassName, true);
            }
        }

#if NET8_0_OR_GREATER
        private protected virtual void ReadHeaderValue(
            ref Utf8JsonReader reader,
            Dictionary<string, object> claims,
            Dictionary<string, (int startIndex, int length)?> claimsBytes,
            Memory<byte> tokenAsMemory)
        {
            _ = claims ?? throw LogHelper.LogArgumentNullException(nameof(claims));
            _ = claimsBytes ?? throw LogHelper.LogArgumentNullException(nameof(claimsBytes));

            if (reader.ValueTextEquals(JwtHeaderUtf8Bytes.Alg))
            {
                claimsBytes[JwtHeaderParameterNames.Alg] = JsonSerializerPrimitives.ReadStringBytesLocation(ref reader, tokenAsMemory, JwtRegisteredClaimNames.Alg, ClassName, true);
            }
            else if (reader.ValueTextEquals(JwtHeaderUtf8Bytes.Cty))
            {
                claimsBytes[JwtHeaderParameterNames.Cty] = JsonSerializerPrimitives.ReadStringBytesLocation(ref reader, tokenAsMemory, JwtHeaderParameterNames.Cty, ClassName, true);
            }
            else if (reader.ValueTextEquals(JwtHeaderUtf8Bytes.Kid))
            {
                claimsBytes[JwtHeaderParameterNames.Kid] = JsonSerializerPrimitives.ReadStringBytesLocation(ref reader, tokenAsMemory, JwtHeaderParameterNames.Kid, ClassName, true);
            }
            else if (reader.ValueTextEquals(JwtHeaderUtf8Bytes.Typ))
            {
                claimsBytes[JwtHeaderParameterNames.Typ] = JsonSerializerPrimitives.ReadStringBytesLocation(ref reader, tokenAsMemory, JwtHeaderParameterNames.Typ, ClassName, true);
            }
            else if (reader.ValueTextEquals(JwtHeaderUtf8Bytes.X5t))
            {
                claimsBytes[JwtHeaderParameterNames.X5t] = JsonSerializerPrimitives.ReadStringBytesLocation(ref reader, tokenAsMemory, JwtHeaderParameterNames.X5t, ClassName, true);
            }
            else if (reader.ValueTextEquals(JwtHeaderUtf8Bytes.Zip))
            {
                claimsBytes[JwtHeaderParameterNames.Zip] = JsonSerializerPrimitives.ReadStringBytesLocation(ref reader, tokenAsMemory, JwtHeaderParameterNames.Zip, ClassName, true);
            }
            else
            {
                string propertyName = reader.GetString();
                claims[propertyName] = JsonSerializerPrimitives.ReadPropertyValueAsObject(ref reader, propertyName, JsonClaimSet.ClassName, true);
            }
        }
#endif
    }
}
