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
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;

namespace System.IdentityModel.Tokens.Jwt
{
    /// <summary>
    /// A <see cref="SecurityToken"/> designed for representing a JSON Web Token (JWT).
    /// </summary>
    public class JwtSecurityToken : SecurityToken, IJsonWebToken
    {
        private JwtPayload _payload;

        /// <summary>
        /// Initializes a new instance of <see cref="JwtSecurityToken"/> from a string in JWS Compact serialized format.
        /// </summary>
        /// <param name="jwtEncodedString">A JSON Web Token that has been serialized in JWS Compact serialized format.</param>
        /// <exception cref="ArgumentNullException">'jwtEncodedString' is null.</exception>
        /// <exception cref="ArgumentException">'jwtEncodedString' contains only whitespace.</exception>
        /// <exception cref="ArgumentException">'jwtEncodedString' is not in JWS Compact serialized format.</exception>
        /// <remarks>
        /// The contents of this <see cref="JwtSecurityToken"/> have not been validated, the JSON Web Token is simply decoded. Validation can be accomplished using <see cref="JwtSecurityTokenHandler.ValidateToken(String, TokenValidationParameters, out SecurityToken)"/>
        /// We recommend using the <see cref="JsonWebToken"/> class over the JwtSecurityToken class as it is newer, faster, and has more functionality.
        /// </remarks>
        public JwtSecurityToken(string jwtEncodedString)
        {
            if (string.IsNullOrWhiteSpace(jwtEncodedString))
                throw LogHelper.LogArgumentNullException(nameof(jwtEncodedString));

            // Set the maximum number of segments to MaxJwtSegmentCount + 1. This controls the number of splits and allows detecting the number of segments is too large.
            // For example: "a.b.c.d.e.f.g.h" => [a], [b], [c], [d], [e], [f.g.h]. 6 segments.
            // If just MaxJwtSegmentCount was used, then [a], [b], [c], [d], [e.f.g.h] would be returned. 5 segments.
            string[] tokenParts = jwtEncodedString.Split(new char[] { '.' }, JwtConstants.MaxJwtSegmentCount + 1);
            if (tokenParts.Length == JwtConstants.JwsSegmentCount)
            {
                if (!JwtTokenUtilities.RegexJws.IsMatch(jwtEncodedString))
                    throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(LogMessages.IDX12739, jwtEncodedString)));
            }
            else if (tokenParts.Length == JwtConstants.JweSegmentCount)
            {
                if (!JwtTokenUtilities.RegexJwe.IsMatch(jwtEncodedString))
                    throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(LogMessages.IDX12740, jwtEncodedString)));
            }
            else
                throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(LogMessages.IDX12741, jwtEncodedString)));

            Decode(tokenParts, jwtEncodedString);
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
                throw LogHelper.LogArgumentNullException(nameof(header));

            if (payload == null)
                throw LogHelper.LogArgumentNullException(nameof(payload));

            if (string.IsNullOrWhiteSpace(rawHeader))
                throw LogHelper.LogArgumentNullException(nameof(rawHeader));

            if (string.IsNullOrWhiteSpace(rawPayload))
                throw LogHelper.LogArgumentNullException(nameof(rawPayload));

            if (rawSignature == null)
                throw LogHelper.LogArgumentNullException(nameof(rawSignature));

            Header = header;
            Payload = payload;
            RawData = string.Concat(rawHeader, ".", rawPayload, ".", rawSignature);

            RawHeader = rawHeader;
            RawPayload = rawPayload;
            RawSignature = rawSignature;
        }

        /// <summary>
        /// Initializes an instance of <see cref="JwtSecurityToken"/> where the <see cref="JwtHeader"/> contains the crypto algorithms applied to the innerToken <see cref="JwtSecurityToken"/>.
        /// </summary>
        /// <param name="header">Defines cryptographic operations applied to the 'innerToken'.</param>
        /// <param name="innerToken"></param>
        /// <param name="rawEncryptedKey">base64urlencoded key</param>
        /// <param name="rawHeader">base64urlencoded JwtHeader</param>
        /// <param name="rawInitializationVector">base64urlencoded initialization vector.</param>
        /// <param name="rawCiphertext">base64urlencoded encrypted innerToken</param>
        /// <param name="rawAuthenticationTag">base64urlencoded authentication tag.</param>
        /// <exception cref="ArgumentNullException">'header' is null.</exception>
        /// <exception cref="ArgumentNullException">'innerToken' is null.</exception>
        /// <exception cref="ArgumentNullException">'rawHeader' is null.</exception>
        /// <exception cref="ArgumentNullException">'rawEncryptedKey' is null.</exception>
        /// <exception cref="ArgumentNullException">'rawInitialVector' is null or empty.</exception>
        /// <exception cref="ArgumentNullException">'rawCiphertext' is null or empty.</exception>
        /// <exception cref="ArgumentNullException">'rawAuthenticationTag' is null or empty.</exception>
        public JwtSecurityToken(JwtHeader header,
                                JwtSecurityToken innerToken,
                                string rawHeader,
                                string rawEncryptedKey,
                                string rawInitializationVector,
                                string rawCiphertext,
                                string rawAuthenticationTag)
        {
            if (header == null)
                throw LogHelper.LogArgumentNullException(nameof(header));

            if (innerToken == null)
                throw LogHelper.LogArgumentNullException(nameof(innerToken));

            if (rawEncryptedKey == null)
                throw LogHelper.LogArgumentNullException(nameof(rawEncryptedKey));

            if (string.IsNullOrEmpty(rawInitializationVector))
                throw LogHelper.LogArgumentNullException(nameof(rawInitializationVector));

            if (string.IsNullOrEmpty(rawCiphertext))
                throw LogHelper.LogArgumentNullException(nameof(rawCiphertext));

            if (string.IsNullOrEmpty(rawAuthenticationTag))
                throw LogHelper.LogArgumentNullException(nameof(rawAuthenticationTag));

            Header = header;
            InnerToken = innerToken;
            RawData = string.Join(".", rawHeader, rawEncryptedKey, rawInitializationVector, rawCiphertext, rawAuthenticationTag);
            RawHeader = rawHeader;
            RawEncryptedKey = rawEncryptedKey;
            RawInitializationVector = rawInitializationVector;
            RawCiphertext = rawCiphertext;
            RawAuthenticationTag = rawAuthenticationTag;
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
                throw LogHelper.LogArgumentNullException(nameof(header));

            if (payload == null)
                throw LogHelper.LogArgumentNullException(nameof(payload));

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
                    throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(LogMessages.IDX12401, expires.Value, notBefore.Value)));
            }

            Payload = new JwtPayload(issuer, audience, claims, notBefore, expires);
            Header = new JwtHeader(signingCredentials);
            RawSignature = string.Empty;
        }

        /// <summary>
        /// Gets the 'value' of the 'actor' claim { actort, 'value' }.
        /// </summary>
        /// <remarks>If the 'actor' claim is not found, an empty string is returned.</remarks> 
        public string Actor
        {
            get
            {
                if (Payload != null)
                    return Payload.Actort;

                return string.Empty;
            }
        }


        /// <summary>
        /// Gets the 'value' of the 'alg' claim { alg, 'value' } from the <see cref="JwtHeader"/>.
        /// </summary>
        /// <remarks>If the 'alg' claim is not found, an empty string is returned.</remarks> 
        public string Alg
        {
            get
            {
                if (Header != null)
                    return Header.Alg;

                return string.Empty;
            }
        }

        /// <summary>
        /// Gets the list of 'audience' claim { aud, 'value' }.
        /// </summary>
        /// <remarks>If the 'audience' claim is not found, enumeration will be empty.</remarks>
        public IEnumerable<string> Audiences
        {
            get
            {
                if (Payload != null)
                    return Payload.Aud;

                return new List<string>();
            }
        }

        /// <summary>
        /// Gets the <see cref="Claim"/>(s) for this token.
        /// If this is a JWE token, this property only returns the encrypted claims;
        ///  the unencrypted claims should be read from the header seperately.
        /// </summary>
        /// <remarks><para><see cref="Claim"/>(s) returned will NOT have the <see cref="Claim.Type"/> translated according to <see cref="JwtSecurityTokenHandler.InboundClaimTypeMap"/></para></remarks>
        public IEnumerable<Claim> Claims
        {
            get
            {
                if (Payload != null)
                    return Payload.Claims;

                return new List<Claim>();
            }
        }

        /// <summary>
        /// Gets the 'value' of the 'cty' claim { cty, 'value' } from the <see cref="JwtHeader"/>.
        /// </summary>
        /// <remarks>If the 'cty' claim is not found, an empty string is returned.</remarks> 
        public string Cty
        {
            get
            {
                if (Header != null)
                    return Header.Cty;

                return string.Empty;
            }
        }

        /// <summary>
        /// Gets the 'value' of the 'enc' claim { enc, 'value' } from the <see cref="JwtHeader"/>.
        /// </summary>
        /// <remarks>If the 'enc' claim is not found, an empty string is returned.</remarks> 
        public string Enc
        {
            get
            {
                if (Header != null)
                    return Header.Enc;

                return string.Empty;
            }
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
            get
            {
                if (Payload != null)
                    return Payload.Base64UrlEncode();

                return string.Empty;
            }
        }

        /// <summary>
        /// Gets the <see cref="JwtHeader"/> associated with this instance if the token is signed.
        /// </summary>
        public JwtHeader Header { get; internal set; }

        /// <summary>
        /// Gets the 'value' of the 'JWT ID' claim { jti, ''value' }.
        /// </summary>
        /// <remarks>If the 'JWT ID' claim is not found, an empty string is returned.</remarks>
        public override string Id
        {
            get
            {
                if (Payload != null)
                    return Payload.Jti;

                return string.Empty;

            }
        }

        /// <summary>
        /// Gets the 'value' of the 'issuer' claim { iss, 'value' }.
        /// </summary>
        /// <remarks>If the 'issuer' claim is not found, an empty string is returned.</remarks>
        public override string Issuer
        {
            get
            {
                if (Payload != null)
                    return Payload.Iss;

                return string.Empty;
            }
        }

        /// <summary>
        /// Gets the <see cref="JwtPayload"/> associated with this instance.
        /// Note that if this JWT is nested ( <see cref="JwtSecurityToken.InnerToken"/> != null, this property represnts the payload of the most inner token.
        /// This property can be null if the content type of the most inner token is unrecognized, in that case
        ///  the content of the token is the string returned by PlainText property.
        /// </summary>
        public JwtPayload Payload
        {
            get
            {
                if (InnerToken != null)
                    return InnerToken.Payload;

                return _payload;
            }
            internal set
            {
                _payload = value;
            }
        }

        /// <summary>
        /// Gets the <see cref="JwtSecurityToken"/> associated with this instance.
        /// </summary>
        public JwtSecurityToken InnerToken { get; internal set; }

        /// <summary>
        /// Gets the 'value' of the 'kid' claim { kid, 'value' } from the <see cref="JwtHeader"/>.  
        /// </summary>
        /// <remarks>If the 'kid' claim is not found, an empty string is returned.</remarks>
        public string Kid
        {
            get
            { 
                if (Header != null)
                    return Header.Kid;

                return string.Empty;
            }
        }

        /// <summary>
        /// Gets the original raw data of this instance when it was created.
        /// </summary>
        /// <remarks>The original JSON Compact serialized format passed to one of the two constructors <see cref="JwtSecurityToken(string)"/>
        /// or <see cref="JwtSecurityToken( JwtHeader, JwtPayload, string, string, string )"/></remarks>
        public string RawAuthenticationTag { get; private set; }

        /// <summary>
        /// Gets the original raw data of this instance when it was created.
        /// </summary>
        /// <remarks>The original JSON Compact serialized format passed to one of the two constructors <see cref="JwtSecurityToken(string)"/>
        /// or <see cref="JwtSecurityToken( JwtHeader, JwtPayload, string, string, string )"/></remarks>
        public string RawCiphertext { get; private set; }

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
        public string RawEncryptedKey { get; private set; }

        /// <summary>
        /// Gets the original raw data of this instance when it was created.
        /// </summary>
        /// <remarks>The original JSON Compact serialized format passed to one of the two constructors <see cref="JwtSecurityToken(string)"/>
        /// or <see cref="JwtSecurityToken( JwtHeader, JwtPayload, string, string, string )"/></remarks>
        public string RawInitializationVector { get; private set; }

        /// <summary>
        /// Gets the original raw data of this instance when it was created.
        /// </summary>
        /// <remarks>The original JSON Compact serialized format passed to one of the two constructors <see cref="JwtSecurityToken(string)"/>
        /// or <see cref="JwtSecurityToken( JwtHeader, JwtPayload, string, string, string )"/></remarks>
        public string RawHeader { get; internal set; }

        /// <summary>
        /// Gets the original raw data of this instance when it was created.
        /// </summary>
        /// <remarks>The original JSON Compact serialized format passed to one of the two constructors <see cref="JwtSecurityToken(string)"/>
        /// or <see cref="JwtSecurityToken( JwtHeader, JwtPayload, string, string, string )"/></remarks>
        public string RawPayload { get; internal set; }

        /// <summary>
        /// Gets the original raw data of this instance when it was created.
        /// </summary>
        /// <remarks>The original JSON Compact serialized format passed to one of the two constructors <see cref="JwtSecurityToken(string)"/>
        /// or <see cref="JwtSecurityToken( JwtHeader, JwtPayload, string, string, string )"/></remarks>
        public string RawSignature { get; internal set; }

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
        /// Gets the <see cref="SigningCredentials"/> to use when writing this token.
        /// </summary>
        public SigningCredentials SigningCredentials
        {
            get { return Header.SigningCredentials; }
        }

        /// <summary>
        /// Gets the 'value' of the 'typ' claim { typ, 'value' } from the <see cref="JwtHeader"/>.
        /// </summary>
        /// <remarks>If the 'typ' claim is not found, an empty string is returned.</remarks>
        public string Typ
        {
            get
            {
                if (Header != null)
                    return Header.Typ;

                return string.Empty;
            }
        }

        /// <summary>
        /// Gets the <see cref="EncryptingCredentials"/> to use when writing this token.
        /// </summary>
        public EncryptingCredentials EncryptingCredentials
        {
            get { return Header.EncryptingCredentials;  }
        }

        /// <summary>
        /// Gets or sets the <see cref="SecurityKey"/> that signed this instance.
        /// </summary>
        /// <remarks><see cref="JwtSecurityTokenHandler"/>.ValidateSignature(...) sets this value when a <see cref="SecurityKey"/> is used to successfully validate a signature.</remarks>
        public override SecurityKey SigningKey { get; set; }

        /// <summary>
        /// Gets the "value" of the 'subject' claim { sub, 'value' }.
        /// </summary>
        /// <remarks>If the 'subject' claim is not found, an empty string is returned.</remarks>
        public string Subject
        {
            get
            {
                if (Payload != null)
                    return Payload.Sub;

                return string.Empty;
            }
        }

        /// <summary>
        /// Gets the 'value' of the 'notbefore' claim { nbf, 'value' } converted to a <see cref="DateTime"/> assuming 'value' is seconds since UnixEpoch (UTC 1970-01-01T0:0:0Z).
        /// </summary>
        /// <remarks>If the 'notbefore' claim is not found, then <see cref="DateTime.MinValue"/> is returned.</remarks>
        public override DateTime ValidFrom
        {
            get
            {
                if (Payload != null)
                    return Payload.ValidFrom;

                return DateTime.MinValue;
            }
        }

        /// <summary>
        /// Gets the 'value' of the 'expiration' claim { exp, 'value' } converted to a <see cref="DateTime"/> assuming 'value' is seconds since UnixEpoch (UTC 1970-01-01T0:0:0Z).
        /// </summary>
        /// <remarks>If the 'expiration' claim is not found, then <see cref="DateTime.MinValue"/> is returned.</remarks>
        public override DateTime ValidTo
        {
            get
            {
                if (Payload != null)
                    return Payload.ValidTo;

                return DateTime.MinValue;
            }
        }
		
        /// <summary>
        /// Gets the 'value' of the 'issued at' claim { iat, 'value' } converted to a <see cref="DateTime"/> assuming 'value' is seconds since UnixEpoch (UTC 1970-01-01T0:0:0Z).
        /// </summary>
        /// <remarks>If the 'issued at' claim is not found, then <see cref="DateTime.MinValue"/> is returned.</remarks>
        public virtual DateTime IssuedAt
        {
            get
            {
                if (Payload != null)
                    return Payload.IssuedAt;

                return DateTime.MinValue;
            }
        }

        /// <summary>
        /// Gets the 'value' of the 'x5t' claim { x5t, 'value' } from the <see cref="JwtHeader"/>.
        /// </summary>
        /// <remarks>If the 'x5t' claim is not found, an empty string is returned.</remarks>
        public string X5t
        {
            get
            {
                if (Header != null)
                    return Header.X5t;

                return string.Empty;
            }
        }

        /// <summary>
        /// Serializes the <see cref="JwtHeader"/> and <see cref="JwtPayload"/>
        /// </summary>
        /// <returns>A string containing the header and payload in JSON format.</returns>
        public override string ToString()
        {
            if (Payload != null)
                return Header.SerializeToJson() + "." + Payload.SerializeToJson();
            else
                return Header.SerializeToJson() + ".";
        }

        /// <summary>
        /// Decodes the string into the header, payload and signature.
        /// </summary>
        /// <param name="tokenParts">the tokenized string.</param>
        /// <param name="rawData">the original token.</param>
        internal void Decode(string[] tokenParts, string rawData)
        {
            LogHelper.LogInformation(LogMessages.IDX12716, rawData);
            try
            {
                Header = JwtHeader.Base64UrlDeserialize(tokenParts[0]);
            }
            catch (Exception ex)
            {
                throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(LogMessages.IDX12729, tokenParts[0], rawData), ex));
            }

            if (tokenParts.Length == JwtConstants.JweSegmentCount)
                DecodeJwe(tokenParts);
            else
                DecodeJws(tokenParts);

            RawData = rawData;
        }

        /// <summary>
        /// Decodes the payload and signature from the JWS parts.
        /// </summary>
        /// <param name="tokenParts">Parts of the JWS including the header.</param>
        /// <remarks>Assumes Header has already been set.</remarks>
        private void DecodeJws(string[] tokenParts)
        {
            // Log if CTY is set, assume compact JWS
            if (Header.Cty != null)
                LogHelper.LogVerbose(LogHelper.FormatInvariant(LogMessages.IDX12738, Header.Cty));

            try
            {
                Payload = JwtPayload.Base64UrlDeserialize(tokenParts[1]);
            }
            catch (Exception ex)
            {
                throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(LogMessages.IDX12723, tokenParts[1], RawData), ex));
            }

            RawHeader = tokenParts[0];
            RawPayload = tokenParts[1];
            RawSignature = tokenParts[2];
        }

        /// <summary>
        /// Decodes the payload and signature from the JWE parts.
        /// </summary>
        /// <param name="tokenParts">Parts of the JWE including the header.</param>
        /// <remarks>Assumes Header has already been set.</remarks>
        private void DecodeJwe(string[] tokenParts)
        {
            RawHeader = tokenParts[0];
            RawEncryptedKey = tokenParts[1];
            RawInitializationVector = tokenParts[2];
            RawCiphertext = tokenParts[3];
            RawAuthenticationTag = tokenParts[4];
        }

        /// <summary>
        /// Gets the 'value' corresponding to the provided key { key, 'value' } from the <see cref="JwtPayload"/>.
        /// </summary>
        /// <remarks>If the key has no corresponding value, returns null. </remarks>   
        public T GetPayloadValue<T>(string key)
        {
            if (string.IsNullOrEmpty(key))
                throw LogHelper.LogArgumentNullException(nameof(key));

            if (!Payload.TryGetValue(key, out var payloadValue))
                throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(LogMessages.IDX12801, key)));

            T value;
            try
            {
                value = (T)payloadValue;
            }
            catch (Exception ex)
            {
                throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(LogMessages.IDX12802, key, typeof(T), payloadValue.GetType()), ex));
            }

            return value;
        }

        /// <summary>
        /// Tries to get the 'value' corresponding to the provided key { key, 'value' } from the <see cref="JwtPayload"/>. 
        /// </summary>
        /// <remarks>If the key has no corresponding value, returns false. Otherwise returns true. </remarks>   
        public bool TryGetPayloadValue<T>(string key, out T value)
        {
            if (string.IsNullOrEmpty(key))
            {
                value = default(T);
                return false;
            }

            if (!Payload.TryGetValue(key, out var payloadValue))
            {
                value = default(T);
                return false;
            }

            try
            {
                value = (T)payloadValue;
            }
            catch (Exception)
            {
                value = default(T);
                return false;
            }

            return true;
        }

        /// <summary>
        /// Gets the 'value' corresponding to the provided key { key, 'value' } from the <see cref="JwtHeader"/>.
        /// </summary>
        /// <remarks>If the key has no corresponding value, returns null. </remarks>   
        public T GetHeaderValue<T>(string key)
        {
            if (string.IsNullOrEmpty(key))
                throw LogHelper.LogArgumentNullException(nameof(key));

            if (!Header.TryGetValue(key, out var headerValue))
                throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(LogMessages.IDX12800, key)));

            T value;
            try
            {
                value = (T)headerValue;
            }
            catch (Exception ex)
            {
                throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(LogMessages.IDX12802, key, typeof(T), headerValue.GetType()), ex));
            }

            return value; 
        }

        /// <summary>
        /// Tries to get the value corresponding to the provided key from the <see cref="JwtHeader"/> { key, 'value' }.
        /// </summary>
        /// <remarks>If the key has no corresponding value, returns false. Otherwise returns true. </remarks>   
        public bool TryGetHeaderValue<T>(string key, out T value)
        {
            if (string.IsNullOrEmpty(key))
            {
                value = default(T);
                return false;
            }

            if (!Header.TryGetValue(key, out var headerValue))
            {
                value = default(T);
                return false;
            }

            try
            {
                value = (T)headerValue;
            }
            catch (Exception)
            {
                value = default(T);
                return false;
            }

            return true;
        }
    }
}
