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
using System.Text;

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
                throw LogHelper.LogArgumentNullException(nameof(jwtEncodedString));

            // Quick fix prior to beta8, will add configuration in RC
            var regex = new Regex(JwtConstants.JsonCompactSerializationRegex);
            if (regex.MatchTimeout == Timeout.InfiniteTimeSpan)
            {
                regex = new Regex(JwtConstants.JsonCompactSerializationRegex, RegexOptions.None, TimeSpan.FromMilliseconds(100));
            }

            if (!regex.IsMatch(jwtEncodedString))
                throw LogHelper.LogException<ArgumentException>(LogMessages.IDX10709, "jwtEncodedString", jwtEncodedString);

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
        /// Initializes a new instance of the <see cref="JwtSecurityToken"/> class where the <see cref="JwtHeader"/> contains the crypto algorithms applied to the encoded <see cref="JwtHeader"/> and <see cref="JwtPayload"/>. The jwtEncodedString is the result of those operations.
        /// </summary>
        /// <param name="header">Contains JSON objects representing the cryptographic operations applied to the JWT and optionally any additional properties of the JWT</param>
        /// <param name="payload">Contains JSON objects representing the claims contained in the JWT. Each claim is a JSON object of the form { Name, Value }</param>
        /// <param name="rawHeader">base64urlencoded JwtHeader</param>
        /// <param name="rawPayload">base64urlencoded JwtPayload</param>
        /// <param name="rawSignature">base64urlencoded JwtSignature</param>
        /// <exception cref="ArgumentNullException">'encryptionHeader' is null.</exception>
        /// <exception cref="ArgumentNullException">'payload' is null.</exception>
        /// <exception cref="ArgumentNullException">'rawInitialVector' is null.</exception>
        /// <exception cref="ArgumentNullException">'rawCiphertext' is null.</exception>
        /// <exception cref="ArgumentNullException">'rawAuthenticationTag' is null.</exception>
        /// <exception cref="ArgumentException">'rawEncryptionHeader' or 'rawPayload' or is null or whitespace.</exception>
        public JwtSecurityToken(JwtHeader header, JwtPayload payload, string rawHeader, string rawPayload, string rawSignature,
            JwtHeader encryptionHeader, string rawEncryptionHeader, string rawEncryptedKey, string rawInitialVector, string rawCiphertext, string rawAuthenticationTag)
        {
            if (encryptionHeader == null)
                throw LogHelper.LogArgumentNullException(nameof(encryptionHeader));

            if (payload == null)
                throw LogHelper.LogArgumentNullException(nameof(payload));

            if (string.IsNullOrWhiteSpace(rawEncryptionHeader))
                throw LogHelper.LogArgumentNullException(nameof(rawEncryptionHeader));

            if (string.IsNullOrWhiteSpace(rawPayload))
                throw LogHelper.LogArgumentNullException(nameof(rawPayload));

            if (rawInitialVector == null)
                throw LogHelper.LogArgumentNullException(nameof(rawInitialVector));

            if (rawCiphertext == null)
                throw LogHelper.LogArgumentNullException(nameof(rawCiphertext));

            if (rawAuthenticationTag == null)
                throw LogHelper.LogArgumentNullException(nameof(rawAuthenticationTag));

            EncryptionHeader = encryptionHeader;
            Header = header;
            Payload = payload;
            RawData = string.Join(".", rawEncryptionHeader, rawEncryptedKey, rawInitialVector, rawCiphertext, rawAuthenticationTag);

            RawHeader = rawHeader;
            RawPayload = rawPayload;
            RawSignature = rawSignature;
            RawEncryptionHeader = rawEncryptionHeader;
            RawEncryptedKey = rawEncryptedKey;
            RawInitializationVector = rawInitialVector;
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
                throw LogHelper.LogArgumentNullException("header");

            if (payload == null)
                throw LogHelper.LogArgumentNullException("payload");

            if (header.Enc != null)
            {
                EncryptionHeader = header;
            }
            else
            {
                Header = header;
            }

            Payload = payload;
            RawSignature = string.Empty;
        }

        public JwtSecurityToken(JwtHeader header, JwtHeader encryptionHeader, JwtPayload payload)
        {
            if (header == null)
                throw LogHelper.LogArgumentNullException("header");

            if (encryptionHeader == null)
                throw LogHelper.LogArgumentNullException("encryptHeader");

            if (payload == null)
                throw LogHelper.LogArgumentNullException("payload");

            Header = header;
            EncryptionHeader = encryptionHeader;
            Payload = payload;
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
                    throw LogHelper.LogException<ArgumentException>(LogMessages.IDX10401, expires.Value, notBefore.Value);
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
            get { return Payload != null ? Payload.Actort : null; }
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
        /// If this is a JWE token, this property only returns the encrypted claims;
        ///  the unencrypted claims should be read from the header seperately.
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
            get { return IsSigned ? Header.Base64UrlEncode() : string.Empty; }
        }

        /// <summary>
        /// Gets the Base64UrlEncoded <see cref="JwtHeader"/> associated with this instance.
        /// </summary>
        public virtual string EncodedEncryptionHeader
        {
            get { return IsEncrypted ? EncryptionHeader.Base64UrlEncode() : string.Empty; }
        }

        /// <summary>
        /// Gets the Base64UrlEncoded <see cref="JwtPayload"/> associated with this instance.
        /// </summary>
        public virtual string EncodedPayload
        {
            get { return Payload.Base64UrlEncode(); }
        }

        /// <summary>
        /// Gets the <see cref="JwtHeader"/> associated with this instance if the token is signed.
        /// </summary>
        public JwtHeader Header { get; private set; }

        /// <summary>
        /// Gets the <see cref="JwtHeader"/> associated with this instance if the token is encrypted.
        /// </summary>
        public JwtHeader EncryptionHeader { get; private set; }

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
        /// Note that if this JWT is nested, this property represnts the payload of the most inner token.
        /// This property can be null if the content type of the most inner token is unrecognized, in that case
        ///  the content of the token is the string returned by PlainText property.
        /// </summary>
        public JwtPayload Payload { get; internal set; }

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
        public string RawEncryptionHeader { get; private set; }

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
        /// Gets a flag indicating whether this token is signed(JWS).
        /// </summary>
        public bool IsSigned => Header != null;

        /// <summary>
        /// Gets a flag indicating whether this token is encrypted.
        /// </summary>
        public bool IsEncrypted => EncryptionHeader != null;

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
            get { return IsSigned ? Header.Alg : null; }
        }

        /// <summary>
        /// Gets the <see cref="SigningCredentials"/> associated with this instance.
        /// </summary>
        public SigningCredentials SigningCredentials
        {
            get { return IsSigned ? Header.SigningCredentials : null; }
        }

        public EncryptingCredentials EncryptingCredentials
        {
            get { return IsEncrypted ? EncryptionHeader.EncryptingCredentials : null;  }
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
            if (IsEncrypted)
            {
                return string.Join(".", EncryptionHeader.SerializeToJson(), IsSigned ? Header.SerializeToJson() : string.Empty, Payload.SerializeToJson());
            }
            else
            {
                return Header.SerializeToJson() + "." + Payload.SerializeToJson();
            }
        }

        /// <summary>
        /// Decodes the string into the header, payload and signature.
        /// </summary>
        /// <param name="jwtEncodedString">Base64Url encoded string.</param>
        /// <param name="isNested">A flag indicating if jwtEncodedString is nested to this token.</param>
        internal void Decode(string jwtEncodedString, bool isNested = false)
        {
            IdentityModelEventSource.Logger.WriteInformation(LogMessages.IDX10716, jwtEncodedString);
            string[] tokenParts = jwtEncodedString.Split(new char[] { '.' }, JwtConstants.MaxJwtPartNumber + 1);
            if (tokenParts.Length == 1)
            {
                // TODO (Yan): Add a new log message for this
                throw new ArgumentException("No parts found for this token. It could have been formatted in JSON which is currently nor supported.",
                    nameof(jwtEncodedString));
            }

            // Numbers of parts exceeds maximum
            if (tokenParts.Length > JwtConstants.MaxJwtPartNumber)
            {
                throw LogHelper.LogException<ArgumentException>(LogMessages.IDX10709, nameof(jwtEncodedString), jwtEncodedString);
            }


            // Decode the header
            JwtHeader header;
            try
            {
                IdentityModelEventSource.Logger.WriteVerbose(LogMessages.IDX10717, tokenParts[0]);
                header = JwtHeader.Base64UrlDeserialize(tokenParts[0]);
            }
            catch (Exception ex)
            {
                throw LogHelper.LogException<ArgumentException>(ex, LogMessages.IDX10703, "header", tokenParts[0], jwtEncodedString);
            }

            if (isNested)
            {
                if (!string.IsNullOrWhiteSpace(header.Enc))
                {
                    // TODO (Yan): Add log message for this
                    throw LogHelper.LogException<ArgumentException>("The nested token must be JWS.");
                }

                Header = header;
                DecodeJws(tokenParts);
            }
            else
            {
                RawData = jwtEncodedString;

                // Determine the token type
                if (string.IsNullOrWhiteSpace(header.Enc))
                {
                    // The token is JWS
                    Header = header;
                    DecodeJws(tokenParts);
                }
                else
                {
                    // The token is JWE
                    EncryptionHeader = header;
                    DecodeJwe(tokenParts);
                }
            }
        }

        /// <summary>
        /// Decrypts this token.
        /// </summary>
        /// <param name="cryptoProviderFactory">The <see cref="CryptoProviderFactory"/> istance used to create the decryption provider.</param>
        /// <param name="cek">The CEK.</param>
        //internal void Decrypt(CryptoProviderFactory cryptoProviderFactory, byte[] cek)
        //{
        //    if (!IsEncrypted)
        //    {
        //        // Nothing to do if the token is not encrypted.
        //        return;
        //    }

        //    if (cryptoProviderFactory == null)
        //    {
        //        throw LogHelper.LogException<ArgumentNullException>(nameof(cryptoProviderFactory));
        //    }

        //    // Decrypt plaintext
        //    AuthenticatedEncryptionParameters param = new AuthenticatedEncryptionParameters
        //    {
        //        CEK = cek,
        //        InitialVector = Base64UrlEncoder.DecodeBytes(RawInitializationVector),
        //        AuthenticationTag = Base64UrlEncoder.DecodeBytes(RawAuthenticationTag)
        //    };
        //    EncryptionProvider decryptionProvider = cryptoProviderFactory.CreateAuthenticatedDecryptionProvider(EncryptionHeader.Enc, param, Encoding.ASCII.GetBytes(EncodedEncryptionHeader));
        //    if (decryptionProvider == null)
        //    {
        //        // TODO (Yan): Add exception message.
        //        throw LogHelper.LogException<InvalidOperationException>("Failed to create decryption provider.");
        //    }

        //    byte[] plaintextBytes;
        //    try
        //    {
        //        plaintextBytes = decryptionProvider.Decrypt(Base64UrlEncoder.DecodeBytes(RawCiphertext));
        //    }
        //    finally
        //    {
        //        cryptoProviderFactory.ReleaseDecryptionProvider(decryptionProvider);
        //    }

        //    string plaintext = Encoding.ASCII.GetString(plaintextBytes);

        //    // Decode plaintext, it's either payload JSON or a nested JWS token
        //    if (EncryptionHeader.Cty != null)
        //    {
        //        // Decode nested JWS
        //        Decode(plaintext, true);
        //    }
        //    else
        //    {
        //        try
        //        {
        //            IdentityModelEventSource.Logger.WriteVerbose(LogMessages.IDX10718, plaintext);
        //            Payload = JwtPayload.Base64UrlDeserialize(plaintext);
        //        }
        //        catch (Exception ex)
        //        {
        //            throw LogHelper.LogException<ArgumentException>(ex, LogMessages.IDX10703, "payload", plaintext, RawData);
        //        }
        //    }
        //}

        /// <summary>
        /// Decodes the payload and signature from the JWS parts.
        /// </summary>
        /// <param name="tokenParts">Parts of the JWS including the header.</param>
        private void DecodeJws(string[] tokenParts)
        {
            // Verify the part number
            if (tokenParts.Length != JwtConstants.JwsPartNumber)
            {
                throw LogHelper.LogException<ArgumentException>(LogMessages.IDX10709, nameof(RawData), RawData);
            }

            // Decode the payload.
            // If the media type of the payload is unspecified or "JSON", it should be able to be deserialized to JwtPayload property bag.
            // We do not support other content types for JWS.
            if (Header.Cty != null)
            {
                // Don't support nested JWS
                // TODO(Yan): Add a new error message indicating that nested token is not supported of JWS.
                    throw LogHelper.LogException<ArgumentException>(LogMessages.IDX10703, "payload", tokenParts[1], RawData);
            }
            else
            {
                try
                {
                    IdentityModelEventSource.Logger.WriteVerbose(LogMessages.IDX10718, tokenParts[1]);
                    Payload = JwtPayload.Base64UrlDeserialize(tokenParts[1]);
                }
                catch (Exception ex)
                {
                    throw LogHelper.LogException<ArgumentException>(ex, LogMessages.IDX10703, "payload", tokenParts[1], RawData);
                }
            }

            this.VerifyBase64UrlString(tokenParts[2], "signature", canBeEmpty: true);

            RawHeader = tokenParts[0];
            RawPayload = tokenParts[1];
            RawSignature = tokenParts[2];
        }

        /// <summary>
        /// Decodes the payload and signature from the JWE parts.
        /// </summary>
        /// <param name="tokenParts">Parts of the JWE including the header.</param>
        private void DecodeJwe(string[] tokenParts)
        {
            // Verify the part number
            if (tokenParts.Length != JwtConstants.JwePartNumber)
            {
                // TODO (Yan): exception message
                throw LogHelper.LogException<ArgumentException>(LogMessages.IDX10709, nameof(RawData), RawData);
            }

            this.VerifyBase64UrlString(tokenParts[1], "encrypted key");
            this.VerifyBase64UrlString(tokenParts[2], "initial vector");
            this.VerifyBase64UrlString(tokenParts[3], "cyphertext");
            this.VerifyBase64UrlString(tokenParts[4], "authentication tag");

            RawEncryptionHeader = tokenParts[0];
            RawEncryptedKey = tokenParts[1];
            RawInitializationVector = tokenParts[2];
            RawCiphertext = tokenParts[3];
            RawAuthenticationTag = tokenParts[4];
        }

        /// <summary>
        /// Verifies that the given string is BASE64URL encoded.
        /// </summary>
        /// <param name="str">The string to verify.</param>
        /// <param name="description">The description of the string part.</param>
        /// <param name="canBeEmpty">A flag indicating wether the string can be null or empty.</param>
        private void VerifyBase64UrlString(string str, string description, bool canBeEmpty = false)
        {
            if (string.IsNullOrEmpty(str))
            {
                if (canBeEmpty)
                {
                    return;
                }

                throw LogHelper.LogException<ArgumentException>(LogMessages.IDX10703, description, str, RawData);
            }

            try
            {
                Base64UrlEncoder.DecodeBytes(str);
            }
            catch (Exception ex)
            {
                throw LogHelper.LogException<ArgumentException>(ex, LogMessages.IDX10703, description, str, RawData);
            }
        }
    }
}
