//------------------------------------------------------------------------------
//
// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
//------------------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Security.Claims;
using Microsoft.IdentityModel.Logging;
using Newtonsoft.Json.Linq;

namespace Microsoft.IdentityModel.Tokens.Jwt
{
    /// <summary>
    /// A <see cref="SecurityToken"/> designed for representing a JSON Web Token (JWT).
    /// </summary>
    public class JsonWebToken : SecurityToken
    {
        /// <summary>
        /// Initializes a new instance of <see cref="JsonWebToken"/> from a string in JWS Compact serialized format.
        /// </summary>
        /// <param name="jwtEncodedString">A JSON Web Token that has been serialized in JWS Compact serialized format.</param>
        /// <exception cref="ArgumentNullException">'jwtEncodedString' is null.</exception>
        /// <exception cref="ArgumentException">'jwtEncodedString' contains only whitespace.</exception>
        /// <exception cref="ArgumentException">'jwtEncodedString' is not in JWS Compact serialized format.</exception>
        /// <remarks>
        /// The contents of the returned <see cref="JsonWebToken"/> have not been validated, the JSON Web Token is simply decoded. Validation can be accomplished using the validation methods in <see cref="JsonWebTokenHandler"/>
        /// </remarks>
        public JsonWebToken(string jwtEncodedString)
        {
            if (string.IsNullOrEmpty(jwtEncodedString))
                throw new ArgumentNullException(nameof(jwtEncodedString));

            int count = 0;
            int next = -1;
            while ((next = jwtEncodedString.IndexOf('.', next + 1)) != -1)
            {
                count++;
                if (count > 5)
                    break;
            }

            // JWS or JWE
            if (count == 2 || count == 5)
            {
                var tokenParts = jwtEncodedString.Split('.');
                Decode(tokenParts, jwtEncodedString);
            } else
                throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(LogMessages.IDX14100, jwtEncodedString)));
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="JsonWebToken"/> class where the header contains the crypto algorithms applied to the encoded header and payload. The jwtEncodedString is the result of those operations.
        /// </summary>
        /// <param name="header">Contains JSON objects representing the cryptographic operations applied to the JWT and optionally any additional properties of the JWT</param>
        /// <param name="payload">Contains JSON objects representing the claims contained in the JWT. Each claim is a JSON object of the form { Name, Value }</param>
        /// <exception cref="ArgumentNullException">'header' is null.</exception>
        /// <exception cref="ArgumentNullException">'payload' is null.</exception>
        public JsonWebToken(JObject header, JObject payload)
        {
            Header = header ?? throw LogHelper.LogArgumentNullException(nameof(header));
            Payload = payload ?? throw LogHelper.LogArgumentNullException(nameof(payload));
        }

        /// <summary>
        /// Gets the 'value' of the 'actor' claim { actort, 'value' }.
        /// </summary>
        /// <remarks>If the 'actor' claim is not found, an empty string is returned.</remarks> 
        public string Actor => Payload.Value<string>(JwtRegisteredClaimNames.Actort) ?? String.Empty;

        /// <summary>
        /// Gets the 'value' of the 'alg' claim { alg, 'value' }.
        /// </summary>
        /// <remarks>If the 'alg' claim is not found, an empty string is returned.</remarks>   
        public string Alg => Header.Value<string>(JwtHeaderParameterNames.Alg) ?? String.Empty;

        /// <summary>
        /// Gets the list of 'audience' claim { aud, 'value' }.
        /// </summary>
        /// <remarks>If the 'audience' claim is not found, enumeration will be empty.</remarks>
        public IEnumerable<string> Audiences
        {
            get
            {
                if (Payload != null)
                {
                    var value = Payload.GetValue(JwtRegisteredClaimNames.Aud);
                    var stringValue = value.ToObject<string>();
                    if (stringValue != null)
                        return new List<string> { stringValue };
                    var listValue = value as IEnumerable<string>;
                    if (listValue != null)
                        return listValue;
                }

                return new List<string>();
            }
        }

        /// <summary>
        /// Gets a <see cref="IEnumerable{Claim}"/><see cref="Claim"/> for each JSON { name, value }.
        /// </summary>
        public virtual IEnumerable<Claim> Claims
        {
            get
            {
                List<Claim> claims = new List<Claim>();
                string issuer = this.Issuer ?? ClaimsIdentity.DefaultIssuer;

                // there is some code redundancy here that was not factored as this is a high use method. Each identity received from the host will pass through here.
                foreach (var jProperty in Payload)
                {
                    if (jProperty.Value == null)
                    {
                        claims.Add(new Claim(jProperty.Key, string.Empty, JsonClaimValueTypes.JsonNull, issuer, issuer));
                        continue;
                    }

                    var claimValue = jProperty.Value.ToObject<string>();
                    if (jProperty.Value.Type.Equals(typeof(string)))
                    {
                        claims.Add(new Claim(jProperty.Key, claimValue, ClaimValueTypes.String, issuer, issuer));
                        continue;
                    }

                    var jtoken = jProperty.Value;
                    if (jtoken != null)
                    {
                        AddClaimsFromJToken(claims, jProperty.Key, jtoken, issuer);
                        continue;
                    }

                }

                return claims;
            }
        }

        /// <summary>
        /// Gets the 'value' of the 'cty' claim { cty, 'value' }.
        /// </summary>
        /// <remarks>If the 'cty' claim is not found, an empty string is returned.</remarks>   
        public string Cty => Header.Value<string>(JwtHeaderParameterNames.Cty) ?? String.Empty;

        /// <summary>
        /// Represents the cryptographic operations applied to the JWT and optionally any additional properties of the JWT. 
        /// </summary>
        public JObject Header
        {
            get;
            private set;
        }

        /// <summary>
        /// Gets the 'value' of the 'JWT ID' claim { jti, ''value' }.
        /// </summary>
        /// <remarks>If the 'JWT ID' claim is not found, an empty string is returned.</remarks>
        public override string Id => Payload.Value<string>(JwtRegisteredClaimNames.Jti) ?? String.Empty;

        /// <summary>
        /// Gets the 'value' of the 'iat' claim { iat, 'value' } converted to a <see cref="DateTime"/> assuming 'value' is seconds since UnixEpoch (UTC 1970-01-01T0:0:0Z).
        /// </summary>
        /// <remarks>If the 'exp' claim is not found, then <see cref="DateTime.MinValue"/> is returned.</remarks>
        public DateTime IssuedAt => Payload.Value<DateTime?>(JwtRegisteredClaimNames.Iat) ?? DateTime.MinValue;

        /// <summary>
        /// Gets the 'value' of the 'issuer' claim { iss, 'value' }.
        /// </summary>
        /// <remarks>If the 'issuer' claim is not found, an empty string is returned.</remarks>   
        public override string Issuer => Payload.Value<string>(JwtRegisteredClaimNames.Iss) ?? String.Empty;

        /// <summary>
        /// Gets the 'value' of the 'kid' claim { kid, 'value' }.
        /// </summary>
        /// <remarks>If the 'kid' claim is not found, an empty string is returned.</remarks>   
        public string Kid => Header.Value<string>(JwtHeaderParameterNames.Kid) ?? String.Empty;

        /// <summary>
        /// Represents the JSON payload.
        /// </summary>
        public JObject Payload
        {
            get;
            private set;
        }

        /// <summary>
        /// Gets the original raw data of this instance when it was created.
        /// </summary>
        public string EncodedToken { get; private set; }

        /// <summary>
        /// Not implemented.
        /// </summary>
        public override SecurityKey SecurityKey { get; }

        /// <summary>
        /// Not implemented.
        /// </summary>
        public override SecurityKey SigningKey
        {
            set;
            get;
        }

        /// <summary>
        /// Gets the 'value' of the 'sub' claim { sub, 'value' }.
        /// </summary>
        /// <remarks>If the 'sub' claim is not found, an empty string is returned.</remarks>   
        public string Subject => Payload.Value<string>(JwtRegisteredClaimNames.Sub) ?? String.Empty;

        /// <summary>
        /// Gets the 'value' of the 'typ' claim { typ, 'value' }.
        /// </summary>
        /// <remarks>If the 'typ' claim is not found, an empty string is returned.</remarks>   
        public string Typ => Header.Value<string>(JwtHeaderParameterNames.Typ) ?? String.Empty;

        /// <summary>
        /// Gets the 'value' of the 'notbefore' claim { nbf, 'value' } converted to a <see cref="DateTime"/> assuming 'value' is seconds since UnixEpoch (UTC 1970-01-01T0:0:0Z).
        /// </summary>
        /// <remarks>If the 'notbefore' claim is not found, then <see cref="DateTime.MinValue"/> is returned.</remarks>
        public override DateTime ValidFrom => Payload.Value<DateTime?>(JwtRegisteredClaimNames.Nbf) ?? DateTime.MinValue;

        /// <summary>
        /// Gets the 'value' of the 'exp' claim { exp, 'value' } converted to a <see cref="DateTime"/> assuming 'value' is seconds since UnixEpoch (UTC 1970-01-01T0:0:0Z).
        /// </summary>
        /// <remarks>If the 'exp' claim is not found, then <see cref="DateTime.MinValue"/> is returned.</remarks>
        public override DateTime ValidTo => Payload.Value<DateTime?>(JwtRegisteredClaimNames.Exp) ?? DateTime.MinValue;

        /// <summary>
        /// Gets the 'value' of the 'x5t' claim { x5t, 'value' }.
        /// </summary>
        /// <remarks>If the 'x5t' claim is not found, an empty string is returned.</remarks>   
        public string X5t => Header.Value<string>(JwtHeaderParameterNames.X5t) ?? String.Empty;

        /// <summary>
        /// Decodes the string into the header, payload and signature.
        /// </summary>
        /// <param name="tokenParts">the tokenized string.</param>
        /// <param name="rawData">the original token.</param>
        private void Decode(string[] tokenParts, string rawData)
        {
            LogHelper.LogInformation(LogMessages.IDX14106, rawData);
            if (!JsonWebTokenManager.RawHeaderToJObjectCache.TryGetValue(tokenParts[0], out var header))
            {
                try
                {
                    Header = JObject.Parse(Base64UrlEncoder.Decode(tokenParts[0]));
                    JsonWebTokenManager.RawHeaderToJObjectCache.TryAdd(tokenParts[0], Header);
                }
                catch (Exception ex)
                {
                    throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(LogMessages.IDX14102, tokenParts[0], rawData), ex));
                }
            }
            else
                Header = header;
           
            if (tokenParts.Length == JwtConstants.JwsSegmentCount)
                DecodeJws(tokenParts);
                
            EncodedToken = rawData;
        }

        private void AddClaimsFromJToken(List<Claim> claims, string claimType, JToken jtoken, string issuer)
        {
            if (jtoken.Type == JTokenType.Object)
            {
                claims.Add(new Claim(claimType, jtoken.ToString(Newtonsoft.Json.Formatting.None), JsonClaimValueTypes.Json, issuer, issuer));
            }
            else if (jtoken.Type == JTokenType.Array)
            {
                var jarray = jtoken as JArray;
                foreach (var item in jarray)
                {
                    switch (item.Type)
                    {
                        case JTokenType.Object:
                            claims.Add(new Claim(claimType, item.ToString(Newtonsoft.Json.Formatting.None), JsonClaimValueTypes.Json, issuer, issuer));
                            break;

                        // only go one level deep on arrays.
                        case JTokenType.Array:
                            claims.Add(new Claim(claimType, item.ToString(Newtonsoft.Json.Formatting.None), JsonClaimValueTypes.JsonArray, issuer, issuer));
                            break;

                        default:
                            AddDefaultClaimFromJToken(claims, claimType, item, issuer);
                            break;
                    }
                }
            }
            else
            {
                AddDefaultClaimFromJToken(claims, claimType, jtoken, issuer);
            }
        }

        private void AddDefaultClaimFromJToken(List<Claim> claims, string claimType, JToken jtoken, string issuer)
        {
            JValue jvalue = jtoken as JValue;
            if (jvalue != null)
            {
                // String is special because item.ToString(Formatting.None) will result in "/"string/"". The quotes will be added.
                // Boolean needs item.ToString otherwise 'true' => 'True'
                if (jvalue.Type == JTokenType.String)
                    claims.Add(new Claim(claimType, jvalue.Value.ToString(), ClaimValueTypes.String, issuer, issuer));
                else
                    claims.Add(new Claim(claimType, jtoken.ToString(Newtonsoft.Json.Formatting.None), GetClaimValueType(jvalue.Value), issuer, issuer));
            }
            else
                claims.Add(new Claim(claimType, jtoken.ToString(Newtonsoft.Json.Formatting.None), GetClaimValueType(jtoken), issuer, issuer));
        }

        /// <summary>
        /// Decodes the payload and signature from the JWS parts.
        /// </summary>
        /// <param name="tokenParts">Parts of the JWS including the header.</param>
        /// <remarks>Assumes Header has already been set.</remarks>
        private void DecodeJws(string[] tokenParts)
        {
            // Log if CTY is set, assume compact JWS
            if (Cty != String.Empty)
                LogHelper.LogVerbose(LogHelper.FormatInvariant(LogMessages.IDX14105, Payload.Value<string>(JwtHeaderParameterNames.Cty)));

            try
            {
                Payload = JObject.Parse(Base64UrlEncoder.Decode(tokenParts[1]));
            }
            catch (Exception ex)
            {
                throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(LogMessages.IDX14101, tokenParts[1], EncodedToken), ex));
            }
        }

        private static string GetClaimValueType(object obj)
        {
            if (obj == null)
                return JsonClaimValueTypes.JsonNull;

            var objType = obj.GetType();

            if (objType == typeof(string))
                return ClaimValueTypes.String;

            if (objType == typeof(int))
                return ClaimValueTypes.Integer;

            if (objType == typeof(bool))
                return ClaimValueTypes.Boolean;

            if (objType == typeof(double))
                return ClaimValueTypes.Double;

            if (objType == typeof(long))
            {
                long l = (long)obj;
                if (l >= int.MinValue && l <= int.MaxValue)
                    return ClaimValueTypes.Integer;

                return ClaimValueTypes.Integer64;
            }

            if (objType == typeof(JObject))
                return JsonClaimValueTypes.Json;

            if (objType == typeof(JArray))
                return JsonClaimValueTypes.JsonArray;

            return objType.ToString();
        }     
    }
}
