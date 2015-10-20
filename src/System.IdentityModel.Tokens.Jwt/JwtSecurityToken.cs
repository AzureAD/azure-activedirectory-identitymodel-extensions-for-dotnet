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
using System.Diagnostics.Tracing;
using System.Globalization;
using System.Security.Claims;
using System.Text.RegularExpressions;
using Microsoft.IdentityModel.Logging;
using System.Threading;

namespace System.IdentityModel.Tokens.Jwt
{
    /// <summary>
    /// A <see cref="SecurityToken"/> designed for representing a JSON Web Token (JWT).
    /// </summary>
    public class JwtSecurityToken : SecurityToken
    {
        private JwtHeader header;
        private string id;
        private JwtPayload payload;
        private string rawData;
        private string rawHeader;
        private string rawPayload;
        private string rawSignature = string.Empty;

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
            if (null == jwtEncodedString)
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10000, GetType() + ": jwtEncodedString"), typeof(ArgumentNullException), EventLevel.Verbose);
            }

            if (string.IsNullOrWhiteSpace(jwtEncodedString))
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10002, GetType() + ": jwtEncodedString"), typeof(ArgumentException), EventLevel.Verbose);
            }

            // Quick fix prior to beta8, will add configuration in RC
            var regex = new Regex(JwtConstants.JsonCompactSerializationRegex);
            if (regex.MatchTimeout == Timeout.InfiniteTimeSpan)
            {
                regex = new Regex(JwtConstants.JsonCompactSerializationRegex, RegexOptions.None, TimeSpan.FromSeconds(2));
            }

            if (!regex.IsMatch(jwtEncodedString))
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10709, GetType() + ": jwtEncodedString", jwtEncodedString), typeof(ArgumentException), EventLevel.Error);
            }

            this.Decode(jwtEncodedString);
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
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10000, GetType() + ": header"), typeof(ArgumentNullException), EventLevel.Verbose);
            }

            if (payload == null)
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10000, GetType() + ": payload"), typeof(ArgumentNullException), EventLevel.Verbose);
            }

            if (rawSignature == null)
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10000, GetType() + ": rawSignature"), typeof(ArgumentNullException), EventLevel.Verbose);
            }

            if (string.IsNullOrWhiteSpace(rawHeader))
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10002, GetType() + ": rawHeader"), typeof(ArgumentException), EventLevel.Verbose);
            }

            if (string.IsNullOrWhiteSpace(rawPayload))
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10002, GetType() + ": rawPayload"), typeof(ArgumentException), EventLevel.Verbose);
            }

            this.header = header;
            this.payload = payload;
            this.rawData = string.Concat(rawHeader, ".", rawPayload, ".", rawSignature);
            this.rawHeader = rawHeader;
            this.rawPayload = rawPayload;
            this.rawSignature = rawSignature;
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
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10000, GetType() + ": header"), typeof(ArgumentNullException), EventLevel.Verbose);
            }

            if (payload == null)
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10000, GetType() + ": payload"), typeof(ArgumentNullException), EventLevel.Verbose);
            }

            this.header = header;
            this.payload = payload;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="JwtSecurityToken"/> class specifying optional parameters.
        /// </summary>
        /// <param name="issuer">if this value is not null, a { iss, 'issuer' } claim will be added.</param>
        /// <param name="audience">if this value is not null, a { aud, 'audience' } claim will be added</param>
        /// <param name="claims">if this value is not null then for each <see cref="Claim"/> a { 'Claim.Type', 'Claim.Value' } is added. If duplicate claims are found then a { 'Claim.Type', List&lt;object> } will be created to contain the duplicate values.</param>
        /// <param name="expires">if expires.HasValue a { exp, 'value' } claim is added.</param>
        /// <param name="notBefore">if notbefore.HasValue a { nbf, 'value' } claim is added.</param>
        /// <param name="signingCredentials">The <see cref="SigningCredentials"/> that will be used to sign the <see cref="JwtSecurityToken"/>. See <see cref="JwtHeader(SigningCredentials)"/> for details pertaining to the Header Parameter(s).</param>
        /// <exception cref="ArgumentException">if 'expires' &lt;= 'notbefore'.</exception>
        public JwtSecurityToken(string issuer = null, string audience = null, IEnumerable<Claim> claims = null, DateTime? notBefore = null, DateTime? expires = null, SigningCredentials signingCredentials = null)
        {
            if (expires.HasValue && notBefore.HasValue)
            {
                if (notBefore >= expires)
                {
                    LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10401, expires.Value, notBefore.Value), typeof(ArgumentException), EventLevel.Error);
                }
            }

            this.payload = new JwtPayload(issuer: issuer, audience: audience, claims: claims, notBefore: notBefore, expires: expires);
            this.header = new JwtHeader(signingCredentials);
        }

        /// <summary>
        /// Gets the 'value' of the 'actor' claim { actort, 'value' }.
        /// </summary>
        /// <remarks>If the 'actor' claim is not found, null is returned.</remarks> 
        public string Actor
        {
            get { return this.payload.Actort; }
        }

        /// <summary>
        /// Gets the list of 'audience' claim { aud, 'value' }.
        /// </summary>
        /// <remarks>If the 'audience' claim is not found, enumeration will be empty.</remarks>
        public IEnumerable<string> Audiences
        {
            get { return this.payload.Aud; }
        }

        /// <summary>
        /// Gets the <see cref="Claim"/>(s) for this token.
        /// </summary>
        /// <remarks><para><see cref="Claim"/>(s) returned will NOT have the <see cref="Claim.Type"/> translated according to <see cref="JwtSecurityTokenHandler.InboundClaimTypeMap"/></para></remarks>
        public IEnumerable<Claim> Claims
        {
            get { return this.payload.Claims; }
        }

        /// <summary>
        /// Gets the Base64UrlEncoded <see cref="JwtHeader"/> associated with this instance.
        /// </summary>
        public virtual string EncodedHeader
        {
            get { return this.header.Base64UrlEncode(); }
        }

        /// <summary>
        /// Gets the Base64UrlEncoded <see cref="JwtPayload"/> associated with this instance.
        /// </summary>
        public virtual string EncodedPayload
        {
            get { return this.payload.Base64UrlEncode(); }
        }

        /// <summary>
        /// Gets the <see cref="JwtHeader"/> associated with this instance.
        /// </summary>
        public JwtHeader Header
        {
            get { return this.header; }
        }

        /// <summary>
        /// Gets the 'value' of the 'JWT ID' claim { jti, ''value' }.
        /// </summary>
        /// <remarks>If the 'JWT ID' claim is not found, null is returned.</remarks>
        public override string Id
        {
            get { return this.payload.Jti; }
        }

        /// <summary>
        /// Gets the 'value' of the 'issuer' claim { iss, 'value' }.
        /// </summary>
        /// <remarks>If the 'issuer' claim is not found, null is returned.</remarks>
        public override string Issuer
        {
            get { return this.payload.Iss; }
        }

        /// <summary>
        /// Gets the <see cref="JwtPayload"/> associated with this instance.
        /// </summary>
        public JwtPayload Payload
        {
            get { return this.payload; }
        }

        /// <summary>
        /// Gets the original raw data of this instance when it was created.
        /// </summary>
        /// <remarks>The original JSON Compact serialized format passed to one of the two constructors <see cref="JwtSecurityToken(string)"/>
        /// or <see cref="JwtSecurityToken( JwtHeader, JwtPayload, string, string, string )"/></remarks>
        public string RawData
        {
            get { return this.rawData; }
        }

        /// <summary>
        /// Gets the original raw data of this instance when it was created.
        /// </summary>
        /// <remarks>The original JSON Compact serialized format passed to one of the two constructors <see cref="JwtSecurityToken(string)"/>
        /// or <see cref="JwtSecurityToken( JwtHeader, JwtPayload, string, string, string )"/></remarks>
        public string RawHeader
        {
            get { return this.rawHeader; }
        }

        /// <summary>
        /// Gets the original raw data of this instance when it was created.
        /// </summary>
        /// <remarks>The original JSON Compact serialized format passed to one of the two constructors <see cref="JwtSecurityToken(string)"/>
        /// or <see cref="JwtSecurityToken( JwtHeader, JwtPayload, string, string, string )"/></remarks>
        public string RawPayload
        {
            get { return this.rawPayload; }
        }

        /// <summary>
        /// Gets the original raw data of this instance when it was created.
        /// </summary>
        /// <remarks>The original JSON Compact serialized format passed to one of the two constructors <see cref="JwtSecurityToken(string)"/>
        /// or <see cref="JwtSecurityToken( JwtHeader, JwtPayload, string, string, string )"/></remarks>
        public string RawSignature
        {
            get { return this.rawSignature; }
        }

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
        /// <remarks>if there is a <see cref="SigningCredentials"/> associated with this instance, a value will be returned.  Null otherwise.</remarks>
        public string SignatureAlgorithm
        {
            get { return this.header.Alg; }
        }

        /// <summary>
        /// Gets the <see cref="SigningCredentials"/> associated with this instance.
        /// </summary>
        public SigningCredentials SigningCredentials
        {
            get { return this.header.SigningCredentials; }
        }

        /// <summary>
        /// Gets or sets the <see cref="SecurityKey"/> that signed this instance.
        /// </summary>
        /// <remarks><see cref="JwtSecurityTokenHandler"/>.ValidateSignature(...) sets this value when a <see cref="SecurityKey"/> is used to successfully validate a signature.</remarks>
        public override SecurityKey SigningKey
        {
            get;
            set;
        }

        /// <summary>
        /// Gets "value" of the 'subject' claim { sub, 'value' }.
        /// </summary>
        /// <remarks>If the 'subject' claim is not found, null is returned.</remarks>
        public string Subject
        {
            get
            {
                return this.payload.Sub;
            }
        }

        /// <summary>
        /// Gets 'value' of the 'notbefore' claim { nbf, 'value' } converted to a <see cref="DateTime"/> assuming 'value' is seconds since UnixEpoch (UTC 1970-01-01T0:0:0Z).
        /// </summary>
        /// <remarks>If the 'notbefore' claim is not found, then <see cref="DateTime.MinValue"/> is returned.</remarks>
        public override DateTime ValidFrom
        {
            get { return this.payload.ValidFrom; }
        }

        /// <summary>
        /// Gets 'value' of the 'expiration' claim { exp, 'value' } converted to a <see cref="DateTime"/> assuming 'value' is seconds since UnixEpoch (UTC 1970-01-01T0:0:0Z).
        /// </summary>
        /// <remarks>If the 'expiration' claim is not found, then <see cref="DateTime.MinValue"/> is returned.</remarks>
        public override DateTime ValidTo
        {
            get { return this.payload.ValidTo; }
        }

        /// <summary>
        /// Decodes the <see cref="JwtHeader"/> and <see cref="JwtPayload"/>
        /// </summary>
        /// <returns>A string containing the header and payload in JSON format</returns>
        public override string ToString()
        {
            return string.Format(CultureInfo.InvariantCulture, "{0}.{1}", this.header.SerializeToJson(), this.payload.SerializeToJson());
        }

        /// <summary>
        /// Decodes the string into the header, payload and signature
        /// </summary>
        /// <param name="jwtEncodedString">Base64Url encoded string.</param>
        internal void Decode(string jwtEncodedString)
        {
            IdentityModelEventSource.Logger.WriteInformation(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10716, jwtEncodedString));
            string[] tokenParts = jwtEncodedString.Split(new char[] { '.' }, 4);
            if (tokenParts.Length != 3)
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10709, GetType() + ": jwtEncodedString", jwtEncodedString), typeof(ArgumentException), EventLevel.Error);
            }

            try
            {
                IdentityModelEventSource.Logger.WriteVerbose(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10717, tokenParts[0]));
                this.header = JwtHeader.Base64UrlDeserialize(tokenParts[0]);

                // if present, "typ" should be set to "JWT" or "http://openid.net/specs/jwt/1.0"
                string type = this.header.Typ;
                if (type != null)
                {
                    if (!(StringComparer.Ordinal.Equals(type, JwtConstants.HeaderType) || StringComparer.Ordinal.Equals(type, JwtConstants.HeaderTypeAlt)))
                    {
                        LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10702, JwtConstants.HeaderType, JwtConstants.HeaderTypeAlt, type), typeof(SecurityTokenException), EventLevel.Error);
                    }
                }
            }
            catch (Exception ex)
            {
                if (DiagnosticUtility.IsFatal(ex))
                {
                    throw;
                }

                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10703, "header", tokenParts[0], jwtEncodedString), typeof(ArgumentException), EventLevel.Error, ex);
            }

            try
            {
                IdentityModelEventSource.Logger.WriteVerbose(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10718, tokenParts[1]));
                this.payload = JwtPayload.Base64UrlDeserialize(tokenParts[1]);
            }
            catch (Exception ex)
            {
                if (DiagnosticUtility.IsFatal(ex))
                {
                    throw;
                }

                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10703, "payload", tokenParts[1], jwtEncodedString), typeof(ArgumentException), EventLevel.Error, ex);
            }

            if (!string.IsNullOrEmpty(tokenParts[2]))
            {
                try
                {
                    Base64UrlEncoder.DecodeBytes(tokenParts[2]);
                }
                catch (Exception ex)
                {
                    if (DiagnosticUtility.IsFatal(ex))
                    {
                        throw;
                    }

                    LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10703, "signature", tokenParts[2], jwtEncodedString), typeof(ArgumentException), EventLevel.Error, ex);
                }
            }

            this.rawData = jwtEncodedString;
            this.rawHeader = tokenParts[0];
            this.rawPayload = tokenParts[1];
            this.rawSignature = tokenParts[2];
        }

        internal void SetId(string id)
        {
            this.id = id;
        }
    }
}
