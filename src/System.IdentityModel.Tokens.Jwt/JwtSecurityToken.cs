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

using System.Collections.Generic;
using System.Security.Claims;
using System.Text.RegularExpressions;
using System.Threading;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using System.Globalization;

namespace System.IdentityModel.Tokens.Jwt
{
    /// <summary>
    /// A <see cref="SecurityToken"/> designed for representing a JSON Web Token (JWT).
    /// </summary>
    public class JwtSecurityToken : SecurityToken
    {
        /// <summary>
        /// Initializes a new instance of <see cref="JwtSecurityToken"/> from a string in JWS Compact serialized format.
        /// </summary>
        /// <param name="jwtEncodedString">A JSON Web Token that has been serialized in JWS Compact serialized format.</param>
        /// <exception cref="ArgumentNullException">'jwtEncodedString' is null.</exception>
        /// <exception cref="ArgumentException">'jwtEncodedString' contains only whitespace.</exception>
        /// <exception cref="ArgumentException">'jwtEncodedString' is not in JWS Compact serialized format.</exception>
        /// <remarks>
        /// The contents of this <see cref="JwtSecurityToken"/> have not been validated, the JSON Web Token is simply decoded. Validation can be accomplished using <see cref="JwtSecurityTokenHandler.ValidateToken(String, TokenValidationParameters, out SecurityToken)"/>
        /// </remarks>
        public JwtSecurityToken(string jwtEncodedString)
        {
            if (string.IsNullOrWhiteSpace(jwtEncodedString))
                throw LogHelper.LogExceptionMessage(new ArgumentNullException(nameof(jwtEncodedString), String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10000, nameof(jwtEncodedString)))); 

            // Quick fix prior to beta8, will add configuration in RC
            var regex = new Regex(JwtConstants.JsonCompactSerializationRegex);
            if (regex.MatchTimeout == Timeout.InfiniteTimeSpan)
            {
                regex = new Regex(JwtConstants.JsonCompactSerializationRegex, RegexOptions.None, TimeSpan.FromMilliseconds(100));
            }

            if (!regex.IsMatch(jwtEncodedString))
                throw LogHelper.LogExceptionMessage(new ArgumentException(String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10709, "jwtEncodedString", jwtEncodedString)));

            Decode(jwtEncodedString);
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="JwtSecurityToken"/> class where the <see cref="JwtHeader"/> contains the crypto algorithms applied to the encoded <see cref="JwtHeader"/> and <see cref="JwtPayload"/>. The jwtEncodedString is the result of those operations.
        /// </summary>
        /// <param name="header">Contains JSON objects representing the cryptographic operations applied to the JWT and optionally any additional properties of the JWT</param>
        /// <param name="payload">Contains JSON objects representing the claims contained in the JWT. Each claim is a JSON object of the form { Name, Value }</param>
        /// <param name="rawHeader">base64urlencoded JwtHeader</param>
        /// <param name="rawPayload">base64urlencoded JwtPayload</param>
        /// <param name="rawSignature">base64urlencoded JwtSignature</param>
        /// <exception cref="ArgumentNullException">'header' is null.</exception>
        /// <exception cref="ArgumentNullException">'payload' is null.</exception>
        /// <exception cref="ArgumentNullException">'rawSignature' is null.</exception>
        /// <exception cref="ArgumentException">'rawHeader' or 'rawPayload' is null or whitespace.</exception>
        public JwtSecurityToken(JwtHeader header, JwtPayload payload, string rawHeader, string rawPayload, string rawSignature)
        {
            if (header == null)
                throw LogHelper.LogExceptionMessage(new ArgumentNullException(nameof(header), String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10000, nameof(header)))); 

            if (payload == null)
                throw LogHelper.LogExceptionMessage(new ArgumentNullException(nameof(payload), String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10000, nameof(payload)))); 

            if (string.IsNullOrWhiteSpace(rawHeader))
                throw LogHelper.LogExceptionMessage(new ArgumentNullException(nameof(rawHeader), String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10000, nameof(rawHeader)))); 

            if (string.IsNullOrWhiteSpace(rawPayload))
                throw LogHelper.LogExceptionMessage(new ArgumentNullException(nameof(rawPayload), String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10000, nameof(rawPayload)))); 

            if (rawSignature == null)
                throw LogHelper.LogExceptionMessage(new ArgumentNullException(nameof(rawSignature), String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10000, nameof(rawSignature)))); 

            Header = header;
            Payload = payload;
            RawData = string.Concat(rawHeader, ".", rawPayload, ".", rawSignature);

            RawHeader = rawHeader;
            RawPayload = rawPayload;
            RawSignature = rawSignature;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="JwtSecurityToken"/> class where the <see cref="JwtHeader"/> contains the crypto algorithms applied to the encoded <see cref="JwtHeader"/> and <see cref="JwtPayload"/>. The jwtEncodedString is the result of those operations.
        /// </summary>
        /// <param name="header">Contains JSON objects representing the cryptographic operations applied to the JWT and optionally any additional properties of the JWT</param>
        /// <param name="payload">Contains JSON objects representing the claims contained in the JWT. Each claim is a JSON object of the form { Name, Value }</param>
        /// <exception cref="ArgumentNullException">'header' is null.</exception>
        /// <exception cref="ArgumentNullException">'payload' is null.</exception>
        public JwtSecurityToken(JwtHeader header, JwtPayload payload)
        {
            if (header == null)
                throw LogHelper.LogExceptionMessage(new ArgumentNullException("header", String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10000, "header"))); 

            if (payload == null)
                throw LogHelper.LogExceptionMessage(new ArgumentNullException("payload", String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10000, "payload"))); 

            Header = header;
            Payload = payload;
            RawSignature = string.Empty;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="JwtSecurityToken"/> class specifying optional parameters.
        /// </summary>
        /// <param name="issuer">If this value is not null, a { iss, 'issuer' } claim will be added.</param>
        /// <param name="audience">If this value is not null, a { aud, 'audience' } claim will be added</param>
        /// <param name="claims">If this value is not null then for each <see cref="Claim"/> a { 'Claim.Type', 'Claim.Value' } is added. If duplicate claims are found then a { 'Claim.Type', List&lt;object&gt; } will be created to contain the duplicate values.</param>
        /// <param name="expires">If expires.HasValue a { exp, 'value' } claim is added.</param>
        /// <param name="notBefore">If notbefore.HasValue a { nbf, 'value' } claim is added.</param>
        /// <param name="signingCredentials">The <see cref="SigningCredentials"/> that will be used to sign the <see cref="JwtSecurityToken"/>. See <see cref="JwtHeader(SigningCredentials)"/> for details pertaining to the Header Parameter(s).</param>
        /// <exception cref="ArgumentException">If 'expires' &lt;= 'notbefore'.</exception>
        public JwtSecurityToken(string issuer = null, string audience = null, IEnumerable<Claim> claims = null, DateTime? notBefore = null, DateTime? expires = null, SigningCredentials signingCredentials = null)
        {
            if (expires.HasValue && notBefore.HasValue)
            {
                if (notBefore >= expires)
                    throw LogHelper.LogExceptionMessage(new ArgumentException(String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10401, expires.Value, notBefore.Value)));
            }

            Payload = new JwtPayload(issuer, audience, claims, notBefore, expires);
            Header = signingCredentials == null ? new JwtHeader() : new JwtHeader(signingCredentials);
            RawSignature = string.Empty;
        }

        /// <summary>
        /// Gets the 'value' of the 'actor' claim { actort, 'value' }.
        /// </summary>
        /// <remarks>If the 'actor' claim is not found, null is returned.</remarks> 
        public string Actor
        {
            get { return Payload.Actort; }
        }

        /// <summary>
        /// Gets the list of 'audience' claim { aud, 'value' }.
        /// </summary>
        /// <remarks>If the 'audience' claim is not found, enumeration will be empty.</remarks>
        public IEnumerable<string> Audiences
        {
            get { return Payload.Aud; }
        }

        /// <summary>
        /// Gets the <see cref="Claim"/>(s) for this token.
        /// </summary>
        /// <remarks><para><see cref="Claim"/>(s) returned will NOT have the <see cref="Claim.Type"/> translated according to <see cref="JwtSecurityTokenHandler.InboundClaimTypeMap"/></para></remarks>
        public IEnumerable<Claim> Claims
        {
            get { return Payload.Claims; }
        }

        /// <summary>
        /// Gets the Base64UrlEncoded <see cref="JwtHeader"/> associated with this instance.
        /// </summary>
        public virtual string EncodedHeader
        {
            get { return Header.Base64UrlEncode(); }
        }

        /// <summary>
        /// Gets the Base64UrlEncoded <see cref="JwtPayload"/> associated with this instance.
        /// </summary>
        public virtual string EncodedPayload
        {
            get { return Payload.Base64UrlEncode(); }
        }

        /// <summary>
        /// Gets the <see cref="JwtHeader"/> associated with this instance.
        /// </summary>
        public JwtHeader Header { get; private set; }

        /// <summary>
        /// Gets the 'value' of the 'JWT ID' claim { jti, ''value' }.
        /// </summary>
        /// <remarks>If the 'JWT ID' claim is not found, null is returned.</remarks>
        public override string Id
        {
            get { return Payload.Jti; }
        }

        /// <summary>
        /// Gets the 'value' of the 'issuer' claim { iss, 'value' }.
        /// </summary>
        /// <remarks>If the 'issuer' claim is not found, null is returned.</remarks>
        public override string Issuer
        {
            get { return Payload.Iss; }
        }

        /// <summary>
        /// Gets the <see cref="JwtPayload"/> associated with this instance.
        /// </summary>
        public JwtPayload Payload { get; private set; }

        /// <summary>
        /// Gets the original raw data of this instance when it was created.
        /// </summary>
        /// <remarks>The original JSON Compact serialized format passed to one of the two constructors <see cref="JwtSecurityToken(string)"/>
        /// or <see cref="JwtSecurityToken( JwtHeader, JwtPayload, string, string, string )"/></remarks>
        public string RawData { get; private set; }

        /// <summary>
        /// Gets the original raw data of this instance when it was created.
        /// </summary>
        /// <remarks>The original JSON Compact serialized format passed to one of the two constructors <see cref="JwtSecurityToken(string)"/>
        /// or <see cref="JwtSecurityToken( JwtHeader, JwtPayload, string, string, string )"/></remarks>
        public string RawHeader { get; private set; }

        /// <summary>
        /// Gets the original raw data of this instance when it was created.
        /// </summary>
        /// <remarks>The original JSON Compact serialized format passed to one of the two constructors <see cref="JwtSecurityToken(string)"/>
        /// or <see cref="JwtSecurityToken( JwtHeader, JwtPayload, string, string, string )"/></remarks>
        public string RawPayload { get; private set; }

        /// <summary>
        /// Gets the original raw data of this instance when it was created.
        /// </summary>
        /// <remarks>The original JSON Compact serialized format passed to one of the two constructors <see cref="JwtSecurityToken(string)"/>
        /// or <see cref="JwtSecurityToken( JwtHeader, JwtPayload, string, string, string )"/></remarks>
        public string RawSignature { get; private set; }

        /// <summary>
        /// Gets the <see cref="SecurityKey"/>s for this instance.
        /// </summary>
        public override SecurityKey SecurityKey
        {
            get { return null; }
        }

        /// <summary>
        /// Gets the signature algorithm associated with this instance.
        /// </summary>
        /// <remarks>If there is a <see cref="SigningCredentials"/> associated with this instance, a value will be returned.  Null otherwise.</remarks>
        public string SignatureAlgorithm
        {
            get { return Header.Alg; }
        }

        /// <summary>
        /// Gets the <see cref="SigningCredentials"/> associated with this instance.
        /// </summary>
        public SigningCredentials SigningCredentials
        {
            get { return Header.SigningCredentials; }
        }

        /// <summary>
        /// Gets or sets the <see cref="SecurityKey"/> that signed this instance.
        /// </summary>
        /// <remarks><see cref="JwtSecurityTokenHandler"/>.ValidateSignature(...) sets this value when a <see cref="SecurityKey"/> is used to successfully validate a signature.</remarks>
        public override SecurityKey SigningKey { get; set; }

        /// <summary>
        /// Gets the "value" of the 'subject' claim { sub, 'value' }.
        /// </summary>
        /// <remarks>If the 'subject' claim is not found, null is returned.</remarks>
        public string Subject
        {
            get { return Payload.Sub; }
        }

        /// <summary>
        /// Gets the 'value' of the 'notbefore' claim { nbf, 'value' } converted to a <see cref="DateTime"/> assuming 'value' is seconds since UnixEpoch (UTC 1970-01-01T0:0:0Z).
        /// </summary>
        /// <remarks>If the 'notbefore' claim is not found, then <see cref="DateTime.MinValue"/> is returned.</remarks>
        public override DateTime ValidFrom
        {
            get { return Payload.ValidFrom; }
        }

        /// <summary>
        /// Gets the 'value' of the 'expiration' claim { exp, 'value' } converted to a <see cref="DateTime"/> assuming 'value' is seconds since UnixEpoch (UTC 1970-01-01T0:0:0Z).
        /// </summary>
        /// <remarks>If the 'expiration' claim is not found, then <see cref="DateTime.MinValue"/> is returned.</remarks>
        public override DateTime ValidTo
        {
            get { return Payload.ValidTo; }
        }

        /// <summary>
        /// Serializes the <see cref="JwtHeader"/> and <see cref="JwtPayload"/>
        /// </summary>
        /// <returns>A string containing the header and payload in JSON format</returns>
        public override string ToString()
        {
            return Header.SerializeToJson() + "." + Payload.SerializeToJson();
        }

        /// <summary>
        /// Decodes the string into the header, payload and signature
        /// </summary>
        /// <param name="jwtEncodedString">Base64Url encoded string.</param>
        internal void Decode(string jwtEncodedString)
        {
            IdentityModelEventSource.Logger.WriteInformation(LogMessages.IDX10716, jwtEncodedString);
            string[] tokenParts = jwtEncodedString.Split(new char[] { '.' }, 4);
            if (tokenParts.Length != 3)
                throw LogHelper.LogExceptionMessage(new ArgumentException(String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10709, "jwtEncodedString", jwtEncodedString)));

            try
            {
                IdentityModelEventSource.Logger.WriteVerbose(LogMessages.IDX10717, tokenParts[0]);
                Header = JwtHeader.Base64UrlDeserialize(tokenParts[0]);

                // if present, "typ" should be set to "JWT" or "http://openid.net/specs/jwt/1.0"
                string type = Header.Typ;
                if (type != null)
                {
                    if (!(StringComparer.Ordinal.Equals(type, JwtConstants.HeaderType) || StringComparer.Ordinal.Equals(type, JwtConstants.HeaderTypeAlt)))
                        throw LogHelper.LogExceptionMessage(new SecurityTokenException(String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10702, JwtConstants.HeaderType, JwtConstants.HeaderTypeAlt, type)));
                }
            }
            catch (Exception ex)
            {
                throw LogHelper.LogExceptionMessage(new ArgumentException(String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10703, "header", tokenParts[0], jwtEncodedString), ex));
            }

            try
            {
                IdentityModelEventSource.Logger.WriteVerbose(LogMessages.IDX10718, tokenParts[1]);
                Payload = JwtPayload.Base64UrlDeserialize(tokenParts[1]);
            }
            catch (Exception ex)
            {
                throw LogHelper.LogExceptionMessage(new ArgumentException(String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10703, "payload", tokenParts[1], jwtEncodedString), ex));
            }

            if (!string.IsNullOrEmpty(tokenParts[2]))
            {
                try
                {
                    Base64UrlEncoder.DecodeBytes(tokenParts[2]);
                }
                catch (Exception ex)
                {
                    throw LogHelper.LogExceptionMessage(new ArgumentException(String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10703, "signature", tokenParts[2], jwtEncodedString), ex));
                }
            }

            RawData = jwtEncodedString;
            RawHeader = tokenParts[0];
            RawPayload = tokenParts[1];
            RawSignature = tokenParts[2];
        }
    }
}
