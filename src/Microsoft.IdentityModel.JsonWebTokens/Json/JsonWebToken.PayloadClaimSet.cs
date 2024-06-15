﻿// Copyright (c) Microsoft Corporation. All rights reserved.
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
            return CreatePayloadClaimSet(bytes.AsSpan(0, length));
        }

        internal JsonClaimSet CreatePayloadClaimSet(ReadOnlySpan<byte> byteSpan)
        {
            Utf8JsonReader reader = new(byteSpan);
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
                    ReadPayloadValue(ref reader, claims);
                }
                // We read a JsonTokenType.StartObject above, exiting and positioning reader at next token.
                else if (JsonSerializerPrimitives.IsReaderAtTokenType(ref reader, JsonTokenType.EndObject, false))
                    break;
                else if (!reader.Read())
                    break;
            };

            return new JsonClaimSet(claims);
        }

        private protected virtual void ReadPayloadValue(ref Utf8JsonReader reader, IDictionary<string, object> claims)
        {
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
    }
}
