// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Text.Json;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
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
#if NET8_0_OR_GREATER
            Dictionary<string, (int startIndex, int length)?> claimsBytes = [];
#endif
            while (true)
            {
                if (reader.TokenType == JsonTokenType.PropertyName)
                {
#if NET8_0_OR_GREATER
                    ReadPayloadValue(ref reader, claims, claimsBytes, tokenPayloadAsMemory);
#else
                    ReadPayloadValue(ref reader, claims);
#endif
                }
                // We read a JsonTokenType.StartObject above, exiting and positioning reader at next token.
                else if (JsonSerializerPrimitives.IsReaderAtTokenType(ref reader, JsonTokenType.EndObject, false))
                    break;
                else if (!reader.Read())
                    break;
            };

#if NET8_0_OR_GREATER
            return new JsonClaimSet(claims, claimsBytes, tokenPayloadAsMemory);
#else
            return new JsonClaimSet(claims);
#endif
        }

        private protected virtual void ReadPayloadValue(ref Utf8JsonReader reader, IDictionary<string, object> claims)
        {
            _ = claims ?? throw LogHelper.LogArgumentNullException(nameof(claims));

            if (reader.ValueTextEquals(JwtPayloadUtf8Bytes.Aud))
            {
                _audiences = [];
                reader.Read();
                if (reader.TokenType == JsonTokenType.StartArray)
                {
                    JsonSerializerPrimitives.ReadStringsSkipNulls(ref reader, _audiences, JwtRegisteredClaimNames.Aud, ClassName);
                    claims[JwtRegisteredClaimNames.Aud] = _audiences;
                }
                else
                {
                    if (reader.TokenType != JsonTokenType.Null)
                    {
                        _audiences.Add(JsonSerializerPrimitives.ReadString(ref reader, JwtRegisteredClaimNames.Aud, ClassName));
                        claims[JwtRegisteredClaimNames.Aud] = _audiences[0];
                    }
                    else
                    {
                        claims[JwtRegisteredClaimNames.Aud] = _audiences;
                    }
                }
            }
            else if (reader.ValueTextEquals(JwtPayloadUtf8Bytes.Azp))
            {
                _azp = JsonSerializerPrimitives.ReadString(ref reader, JwtRegisteredClaimNames.Azp, ClassName, true);
                claims[JwtRegisteredClaimNames.Azp] = _azp;
            }
            else if (reader.ValueTextEquals(JwtPayloadUtf8Bytes.Exp))
            {
                _exp = JsonSerializerPrimitives.ReadLong(ref reader, JwtRegisteredClaimNames.Exp, ClassName, true);
                _expDateTime = EpochTime.DateTime(_exp.Value);
                claims[JwtRegisteredClaimNames.Exp] = _exp;
            }
            else if (reader.ValueTextEquals(JwtPayloadUtf8Bytes.Iat))
            {
                _iat = JsonSerializerPrimitives.ReadLong(ref reader, JwtRegisteredClaimNames.Iat, ClassName, true);
                _iatDateTime = EpochTime.DateTime(_iat.Value);
                claims[JwtRegisteredClaimNames.Iat] = _iat;
            }
            else if (reader.ValueTextEquals(JwtPayloadUtf8Bytes.Iss))
            {
                _iss = JsonSerializerPrimitives.ReadString(ref reader, JwtRegisteredClaimNames.Iss, ClassName, true);
                claims[JwtRegisteredClaimNames.Iss] = _iss;
            }
            else if (reader.ValueTextEquals(JwtPayloadUtf8Bytes.Jti))
            {
                _jti = JsonSerializerPrimitives.ReadString(ref reader, JwtRegisteredClaimNames.Jti, ClassName, true);
                claims[JwtRegisteredClaimNames.Jti] = _jti;
            }
            else if (reader.ValueTextEquals(JwtPayloadUtf8Bytes.Nbf))
            {
                _nbf = JsonSerializerPrimitives.ReadLong(ref reader, JwtRegisteredClaimNames.Nbf, ClassName, true);
                _nbfDateTime = EpochTime.DateTime(_nbf.Value);
                claims[JwtRegisteredClaimNames.Nbf] = _nbf;
            }
            else if (reader.ValueTextEquals(JwtPayloadUtf8Bytes.Sub))
            {
                _sub = JsonSerializerPrimitives.ReadStringOrNumberAsString(ref reader, JwtRegisteredClaimNames.Sub, ClassName, true);
                claims[JwtRegisteredClaimNames.Sub] = _sub;
            }
            else
            {
                string propertyName = reader.GetString();
                claims[propertyName] = JsonSerializerPrimitives.ReadPropertyValueAsObject(ref reader, propertyName, JsonClaimSet.ClassName, true);
            }
        }

#if NET8_0_OR_GREATER
        private protected virtual void ReadPayloadValue(
            ref Utf8JsonReader reader,
            Dictionary<string, object> claims,
            Dictionary<string, (int startIndex, int length)?> claimsBytes,
            Memory<byte> tokenAsMemory)
        {
            _ = claims ?? throw LogHelper.LogArgumentNullException(nameof(claims));
            _ = claimsBytes ?? throw LogHelper.LogArgumentNullException(nameof(claimsBytes));

            if (reader.ValueTextEquals(JwtPayloadUtf8Bytes.Aud))
            {
                _audiences = [];
                reader.Read();
                if (reader.TokenType == JsonTokenType.StartArray)
                {
                    JsonSerializerPrimitives.ReadStringsSkipNulls(ref reader, _audiences, JwtRegisteredClaimNames.Aud, ClassName);
                    claims[JwtRegisteredClaimNames.Aud] = _audiences;
                }
                else
                {
                    if (reader.TokenType != JsonTokenType.Null)
                    {
                        _audiences.Add(JsonSerializerPrimitives.ReadString(ref reader, JwtRegisteredClaimNames.Aud, ClassName));
                        claims[JwtRegisteredClaimNames.Aud] = _audiences[0];
                    }
                    else
                    {
                        claims[JwtRegisteredClaimNames.Aud] = _audiences;
                    }
                }
            }
            else if (reader.ValueTextEquals(JwtPayloadUtf8Bytes.Azp))
            {
                claimsBytes[JwtRegisteredClaimNames.Azp] = JsonSerializerPrimitives.ReadStringBytesLocation(ref reader, tokenAsMemory, JwtRegisteredClaimNames.Azp, ClassName, true);
            }
            else if (reader.ValueTextEquals(JwtPayloadUtf8Bytes.Exp))
            {
                _exp = JsonSerializerPrimitives.ReadLong(ref reader, JwtRegisteredClaimNames.Exp, ClassName, true);
                _expDateTime = EpochTime.DateTime(_exp.Value);
                claims[JwtRegisteredClaimNames.Exp] = _exp;
            }
            else if (reader.ValueTextEquals(JwtPayloadUtf8Bytes.Iat))
            {
                _iat = JsonSerializerPrimitives.ReadLong(ref reader, JwtRegisteredClaimNames.Iat, ClassName, true);
                _iatDateTime = EpochTime.DateTime(_iat.Value);
                claims[JwtRegisteredClaimNames.Iat] = _iat;
            }
            else if (reader.ValueTextEquals(JwtPayloadUtf8Bytes.Iss))
            {
                claimsBytes[JwtRegisteredClaimNames.Iss] = JsonSerializerPrimitives.ReadStringBytesLocation(ref reader, tokenAsMemory, JwtRegisteredClaimNames.Iss, ClassName, true);
            }
            else if (reader.ValueTextEquals(JwtPayloadUtf8Bytes.Jti))
            {
                claimsBytes[JwtRegisteredClaimNames.Jti] = JsonSerializerPrimitives.ReadStringBytesLocation(ref reader, tokenAsMemory, JwtRegisteredClaimNames.Jti, ClassName, true);
            }
            else if (reader.ValueTextEquals(JwtPayloadUtf8Bytes.Nbf))
            {
                _nbf = JsonSerializerPrimitives.ReadLong(ref reader, JwtRegisteredClaimNames.Nbf, ClassName, true);
                _nbfDateTime = EpochTime.DateTime(_nbf.Value);
                claims[JwtRegisteredClaimNames.Nbf] = _nbf;
            }
            else if (reader.ValueTextEquals(JwtPayloadUtf8Bytes.Sub))
            {
                _sub = JsonSerializerPrimitives.ReadStringOrNumberAsString(ref reader, JwtRegisteredClaimNames.Sub, ClassName, true);
                claims[JwtRegisteredClaimNames.Sub] = _sub;
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
