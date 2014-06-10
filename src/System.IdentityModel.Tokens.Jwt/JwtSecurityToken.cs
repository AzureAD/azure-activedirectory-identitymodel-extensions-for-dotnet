//-----------------------------------------------------------------------
// Copyright (c) Microsoft Open Technologies, Inc.
// All Rights Reserved
// Apache License 2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
// http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//-----------------------------------------------------------------------

namespace System.IdentityModel.Tokens
{
    using Microsoft.IdentityModel;
    using System.Collections.Generic;
    using System.Collections.ObjectModel;
    using System.Diagnostics.CodeAnalysis;
    using System.Globalization;
    using System.Security.Claims;
    using System.Text.RegularExpressions;

    /// <summary>
    /// A <see cref="SecurityToken"/> designed for representing a JSON Web Token (JWT).
    /// </summary>
    [SuppressMessage("StyleCop.CSharp.DocumentationRules", "SA1600:ElementsMustBeDocumented", Justification = "Suppressed for internal or private fields.")]
    public class JwtSecurityToken : SecurityToken
    {
        private JwtHeader header;
        private string id;
        private JwtPayload payload;
        private string rawData;
        private string signature = string.Empty;

        /// <summary>
        /// Initializes a new instance of <see cref="JwtSecurityToken"/> from a string in JWS Compact serialized format.
        /// </summary>
        /// <param name="jwtEncodedString">A JSON Web Token that has been serialized in JWS Compact serialized format.</param>
        /// <exception cref="ArgumentNullException">'jwtEncodedString' is null.</exception>
        /// <exception cref="ArgumentException">'jwtEncodedString' contains only whitespace.</exception>
        /// <exception cref="ArgumentException">'jwtEncodedString' is not in JWS Compact serialized format.</exception>
        /// <remarks>
        /// The contents of this <see cref="JwtSecurityToken"/> have not been validated, the JSON Web Token is simply decoded. Validation can be accomplished using <see cref="JwtSecurityTokenHandler.ValidateToken(String, TokenValidationParameters, out SecurityToken)"/>
        /// </remarks>>
        [SuppressMessage("StyleCop.CSharp.DocumentationRules", "SA1642:ConstructorSummaryDocumentationMustBeginWithStandardText", Justification = "Reviewed. Suppression is OK here."), SuppressMessage("StyleCop.CSharp.DocumentationRules", "SA1650:ElementDocumentationMustBeSpelledCorrectly", Justification = "Reviewed. Suppression is OK here.")]
        public JwtSecurityToken(string jwtEncodedString)
        {
            if (null == jwtEncodedString)
            {
                throw new ArgumentNullException("jwtEncodedString");
            }

            if (string.IsNullOrWhiteSpace(jwtEncodedString))
            {
                throw new ArgumentException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10002, "jwtEncodedString"));
            }

            if (!Regex.IsMatch(jwtEncodedString, JwtConstants.JsonCompactSerializationRegex))
            {
                throw new ArgumentException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10709, "jwtEncodedString", jwtEncodedString));
            }

            this.Decode(jwtEncodedString);
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="JwtSecurityToken"/> class where the <see cref="JwtHeader"/> contains the crypto algorithms applied to the encoded <see cref="JwtHeader"/> and <see cref="JwtPayload"/>. The jwtEncodedString is the result of those operations.
        /// </summary>
        /// <param name="header">Contains JSON objects representing the cryptographic operations applied to the JWT and optionally any additional properties of the JWT</param>
        /// <param name="payload">Contains JSON objects representing the claims contained in the JWT. Each claim is a JSON object of the form { Name, Value }</param>
        /// <param name="jwtEncodedString">The results of encoding and applying the cryptographic operations to the <see cref="JwtHeader"/> and <see cref="JwtPayload"/>.</param>
        /// <exception cref="ArgumentNullException">'header' is null.</exception>        
        /// <exception cref="ArgumentNullException">'payload' is null.</exception>
        /// <exception cref="ArgumentNullException">'jwtEncodedString' is null.</exception>        
        /// <exception cref="ArgumentException">'jwtEncodedString' contains only whitespace.</exception>        
        /// <exception cref="ArgumentException">'jwtEncodedString' is not in JWS Compact serialized format.</exception>
        public JwtSecurityToken(JwtHeader header, JwtPayload payload, string jwtEncodedString)
        {
            if (header == null)
            {
                throw new ArgumentNullException("header");
            }

            if (payload == null)
            {
                throw new ArgumentNullException("payload");
            }

            if (jwtEncodedString == null)
            {
                throw new ArgumentNullException("jwtEncodedString");
            }

            if (string.IsNullOrWhiteSpace(jwtEncodedString))
            {
                throw new ArgumentException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10102, "jwtEncodedString"));
            }

            if (!Regex.IsMatch(jwtEncodedString, JwtConstants.JsonCompactSerializationRegex))
            {
                throw new ArgumentException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10709, "jwtEncodedString", jwtEncodedString));
            }

            string[] tokenParts = jwtEncodedString.Split('.');
            if (tokenParts.Length != 3)
            {
                throw new ArgumentException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10709, "jwtEncodedString", jwtEncodedString));
            }

            this.header = header;
            this.payload = payload;
            this.rawData = jwtEncodedString;
            this.signature = tokenParts[2];
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
                    throw new ArgumentException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10401, expires.Value, notBefore.Value));
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
            get { return this.header.Encode(); }
        }

        /// <summary>
        /// Gets the Base64UrlEncoded <see cref="JwtPayload"/> associated with this instance.
        /// </summary>
        public virtual string EncodedPayload
        {
            get { return this.payload.Encode(); }
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
        public string Issuer
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
        /// or <see cref="JwtSecurityToken( JwtHeader, JwtPayload, string )"/></remarks>
        public string RawData
        {
            get { return this.rawData; }
        }

        /// <summary>
        /// Gets the current signature over the jwt
        /// </summary>
        public string EncodedSignature
        {
            get { return this.signature; }
        }

        /// <summary>
        /// Gets the <see cref="SecurityKey"/>s for this instance.
        /// </summary>
        /// <remarks>By default an empty collection is returned.</remarks>
        public override ReadOnlyCollection<SecurityKey> SecurityKeys
        {
            get { return new ReadOnlyCollection<SecurityKey>(new List<SecurityKey>()); }
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
        public SecurityKey SigningKey
        {
            get;
            set;
        }

        /// <summary>
        /// Gets or sets the <see cref="SecurityToken"/> that contains a <see cref="SecurityKey"/> that signed this instance.
        /// </summary>
        /// <remarks><see cref="JwtSecurityTokenHandler"/>.ValidateSignature(...) sets this value when a <see cref="SecurityKey"/> is used to successfully validate a signature.</remarks>
        public SecurityToken SigningToken
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
            return string.Format(CultureInfo.InvariantCulture, "{0}.{1}\nRawData: {2}", this.header.SerializeToJson(), this.payload.SerializeToJson(), rawData ?? "Empty");
        }

        /// <summary>
        /// Decodes the string into the header, payload and signature
        /// </summary>
        /// <param name="jwtEncodedString">Base64Url encoded string.</param>
        internal void Decode(string jwtEncodedString)
        {
            string[] tokenParts = jwtEncodedString.Split('.');
            if (tokenParts.Length != 3)
            {
                throw new ArgumentException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10709, "jwtEncodedString", jwtEncodedString));
            }

            try
            {
                this.header = Base64UrlEncoder.Decode(tokenParts[0]).DeserializeJwtHeader();

                // if present, "typ" should be set to "JWT" or "http://openid.net/specs/jwt/1.0"
                string type = null;
                if (this.header.TryGetValue(JwtHeaderParameterNames.Typ, out type))
                {
                    if (!(StringComparer.Ordinal.Equals(type, JwtConstants.HeaderType) || StringComparer.Ordinal.Equals(type, JwtConstants.HeaderTypeAlt)))
                    {
                        throw new SecurityTokenException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10702, JwtConstants.HeaderType, JwtConstants.HeaderTypeAlt, type));
                    }
                }
            }
            catch (Exception ex)
            {
                if (DiagnosticUtility.IsFatal(ex))
                {
                    throw;
                }

                throw new ArgumentException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10703, "header", tokenParts[0], jwtEncodedString), ex);
            }

            try
            {
                this.payload = Base64UrlEncoder.Decode(tokenParts[1]).DeserializeJwtPayload();
            }
            catch (Exception ex)
            {
                if (DiagnosticUtility.IsFatal(ex))
                {
                    throw;
                }

                throw new ArgumentException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10703, "payload", tokenParts[1], jwtEncodedString), ex);
            }

            this.rawData = jwtEncodedString;
            this.signature = tokenParts[2];
        }

        internal void SetId(string id)
        {
            this.id = id;
        }
    }
}
