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
using System.ComponentModel;
using System.Globalization;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;

namespace System.IdentityModel.Tokens.Jwt
{
    /// <summary>
    /// A <see cref="SecurityTokenHandler"/> designed for creating and validating Json Web Tokens. See: http://tools.ietf.org/html/rfc7519 and http://www.rfc-editor.org/info/rfc7515
    /// </summary>
    public class JwtSecurityTokenHandler : SecurityTokenHandler, ISecurityTokenValidator
    {
        private delegate bool CertMatcher(X509Certificate2 cert);

        private int _defaultTokenLifetimeInMinutes = DefaultTokenLifetimeInMinutes;
        private ISet<string> _inboundClaimFilter;
        private IDictionary<string, string> _inboundClaimTypeMap;
        private static string _jsonClaimTypeProperty = _namespace + "/json_type";
        private int _maximumTokenSizeInBytes = TokenValidationParameters.DefaultMaximumTokenSizeInBytes;
        private const string _namespace = "http://schemas.xmlsoap.org/ws/2005/05/identity/claimproperties";
        private IDictionary<string, string> _outboundClaimTypeMap;
        private IDictionary<string, string> _outboundAlgorithmMap = null;
        private static string _shortClaimTypeProperty = _namespace + "/ShortTypeName";

        /// <summary>
        /// Default lifetime of tokens created. When creating tokens, if 'expires' and 'notbefore' are both null, then a default will be set to: expires = DateTime.UtcNow, notbefore = DateTime.UtcNow + TimeSpan.FromMinutes(TokenLifetimeInMinutes).
        /// </summary>
        public static readonly int DefaultTokenLifetimeInMinutes = 60;

        /// <summary>
        /// Default claim type mapping for inbound claims.
        /// </summary>
        public static IDictionary<string, string> DefaultInboundClaimTypeMap = ClaimTypeMapping.InboundClaimTypeMap;

        /// <summary>
        /// Default claim type maping for outbound claims.
        /// </summary>
        public static IDictionary<string, string> DefaultOutboundClaimTypeMap = ClaimTypeMapping.OutboundClaimTypeMap;

        /// <summary>
        /// Default claim type filter list.
        /// </summary>
        public static ISet<string> DefaultInboundClaimFilter = ClaimTypeMapping.InboundClaimFilter;

        /// <summary>
        /// Default JwtHeader algorithm mapping
        /// </summary>
        public static IDictionary<string, string> DefaultOutboundAlgorithmMap;

        /// <summary>
        /// Static initializer for a new object. Static initializers run before the first instance of the type is created.
        /// </summary>
        static JwtSecurityTokenHandler()
        {
            IdentityModelEventSource.Logger.WriteVerbose("Assembly version info: " + typeof(JwtSecurityTokenHandler).AssemblyQualifiedName);
            DefaultOutboundAlgorithmMap = new Dictionary<string, string>
            {
                 { SecurityAlgorithms.EcdsaSha256Signature, SecurityAlgorithms.EcdsaSha256 },
                 { SecurityAlgorithms.EcdsaSha384Signature, SecurityAlgorithms.EcdsaSha384 },
                 { SecurityAlgorithms.EcdsaSha512Signature, SecurityAlgorithms.EcdsaSha512 },
                 { SecurityAlgorithms.HmacSha256Signature, SecurityAlgorithms.HmacSha256 },
                 { SecurityAlgorithms.HmacSha384Signature, SecurityAlgorithms.HmacSha384 },
                 { SecurityAlgorithms.HmacSha512Signature, SecurityAlgorithms.HmacSha512 },
                 { SecurityAlgorithms.RsaSha256Signature, SecurityAlgorithms.RsaSha256 },
                 { SecurityAlgorithms.RsaSha384Signature, SecurityAlgorithms.RsaSha384 },
                 { SecurityAlgorithms.RsaSha512Signature, SecurityAlgorithms.RsaSha512 },
             };
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="JwtSecurityTokenHandler"/> class.
        /// </summary>
        public JwtSecurityTokenHandler()
        {
            _inboundClaimTypeMap = new Dictionary<string, string>(DefaultInboundClaimTypeMap);
            _outboundClaimTypeMap = new Dictionary<string, string>(DefaultOutboundClaimTypeMap);
            _inboundClaimFilter = new HashSet<string>(DefaultInboundClaimFilter);
            _outboundAlgorithmMap = new Dictionary<string, string>(DefaultOutboundAlgorithmMap);
        }

        /// <summary>
        /// Gets or sets the <see cref="InboundClaimTypeMap"/> which is used when setting the <see cref="Claim.Type"/> for claims in the <see cref="ClaimsPrincipal"/> extracted when validating a <see cref="JwtSecurityToken"/>. 
        /// <para>The <see cref="Claim.Type"/> is set to the JSON claim 'name' after translating using this mapping.</para>
        /// <para>The default value is ClaimTypeMapping.InboundClaimTypeMap</para>
        /// </summary>
        /// <exception cref="ArgumentNullException">'value is null.</exception>
        public IDictionary<string, string> InboundClaimTypeMap
        {
            get
            {
                return _inboundClaimTypeMap;
            }

            set
            {
                if (value == null)
                    throw LogHelper.LogArgumentNullException("value");

                _inboundClaimTypeMap = value;
            }
        }

        /// <summary>
        /// <para>Gets or sets the <see cref="OutboundClaimTypeMap"/> which is used when creating a <see cref="JwtSecurityToken"/> from <see cref="Claim"/>(s).</para>
        /// <para>The JSON claim 'name' value is set to <see cref="Claim.Type"/> after translating using this mapping.</para>
        /// <para>The default value is ClaimTypeMapping.OutboundClaimTypeMap</para>
        /// </summary>
        /// <remarks>This mapping is applied only when using <see cref="JwtPayload.AddClaim"/> or <see cref="JwtPayload.AddClaims"/>. Adding values directly will not result in translation.</remarks>
        /// <exception cref="ArgumentNullException">'value' is null.</exception>
        public IDictionary<string, string> OutboundClaimTypeMap
        {
            get
            {
                return _outboundClaimTypeMap;
            }

            set
            {
                if (value == null)
                    throw LogHelper.LogArgumentNullException("value");

                _outboundClaimTypeMap = value;
            }
        }

        /// <summary>
        /// Gets the outbound algorithm map that is passed to the <see cref="JwtHeader"/> constructor.
        /// </summary>
        public IDictionary<string, string> OutboundAlgorithmMap
        {
            get
            {
                return _outboundAlgorithmMap;
            }
        }


        /// <summary>Gets or sets the <see cref="ISet{String}"/> used to filter claims when populating a <see cref="ClaimsIdentity"/> claims form a <see cref="JwtSecurityToken"/>.
        /// When a <see cref="JwtSecurityToken"/> is validated, claims with types found in this <see cref="ISet{String}"/> will not be added to the <see cref="ClaimsIdentity"/>.
        /// <para>The default value is ClaimTypeMapping.InboundClaimFliter</para>
        /// </summary>
        /// <exception cref="ArgumentNullException">'value' is null.</exception>
        public ISet<string> InboundClaimFilter
        {
            get
            {
                return _inboundClaimFilter;
            }

            set
            {
                if (value == null)
                    throw LogHelper.LogArgumentNullException("value");

                _inboundClaimFilter = value;
            }
        }

        /// <summary>
        /// Gets or sets the property name of <see cref="Claim.Properties"/> the will contain the original JSON claim 'name' if a mapping occurred when the <see cref="Claim"/>(s) were created.
        /// <para>See <seealso cref="InboundClaimTypeMap"/> for more information.</para>
        /// </summary>
        /// <exception cref="ArgumentException">If <see cref="string"/>.IsIsNullOrWhiteSpace('value') is true.</exception>
        public static string ShortClaimTypeProperty
        {
            get
            {
                return _shortClaimTypeProperty;
            }

            set
            {
                if (string.IsNullOrWhiteSpace(value))
                    throw LogHelper.LogArgumentNullException("value");

                _shortClaimTypeProperty = value;
            }
        }

        /// <summary>
        /// Gets or sets the property name of <see cref="Claim.Properties"/> the will contain .Net type that was recogninzed when JwtPayload.Claims serialized the value to JSON.
        /// <para>See <seealso cref="InboundClaimTypeMap"/> for more information.</para>
        /// </summary>
        /// <exception cref="ArgumentException">If <see cref="string"/>.IsIsNullOrWhiteSpace('value') is true.</exception>
        public static string JsonClaimTypeProperty
        {
            get
            {
                return _jsonClaimTypeProperty;
            }

            set
            {
                if (string.IsNullOrWhiteSpace(value))
                    throw LogHelper.LogArgumentNullException("value");

                _jsonClaimTypeProperty = value;
            }
        }

        /// <summary>
        /// Returns 'true' which indicates this instance can validate a <see cref="JwtSecurityToken"/>.
        /// </summary>
        public override bool CanValidateToken
        {
            get { return true; }
        }

        /// <summary>
        /// Gets a value indicating whether the class provides serialization functionality to serialize token handled 
        /// by this instance.
        /// </summary>
        /// <returns>true if the WriteToken method can serialize this token.</returns>
        public override bool CanWriteToken
        {
            get { return true; }
        }

        /// <summary>
        /// Gets or sets the token lifetime in minutes.
        /// </summary>
        /// <remarks>Used by <see cref="CreateToken(SecurityTokenDescriptor)"/> to set the default expiration ('exp'). <see cref="DefaultTokenLifetimeInMinutes"/> for the default.</remarks>
        /// <exception cref="ArgumentOutOfRangeException">'value' less than 1.</exception>
        public int TokenLifetimeInMinutes
        {
            get
            {
                return _defaultTokenLifetimeInMinutes;
            }

            set
            {
                if (value < 1)
                    throw LogHelper.LogExceptionMessage(new ArgumentOutOfRangeException("value", String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10104, value)));

                _defaultTokenLifetimeInMinutes = value;
            }
        }

        /// <summary>
        /// Gets the type of the <see cref="System.IdentityModel.Tokens.Jwt.JwtSecurityToken"/>.
        /// </summary>
        /// <return>The type of <see cref="System.IdentityModel.Tokens.Jwt.JwtSecurityToken"/></return>
        public override Type TokenType
        {
            get { return typeof(JwtSecurityToken); }
        }

        /// <summary>
        /// Gets and sets the maximum size in bytes, that a will be processed.
        /// </summary>
        /// <exception cref="ArgumentOutOfRangeException">'value' less than 1.</exception>
        public int MaximumTokenSizeInBytes
        {
            get
            {
                return _maximumTokenSizeInBytes;
            }

            set
            {
                if (value < 1)
                    throw LogHelper.LogExceptionMessage(new ArgumentOutOfRangeException("value", String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10101, value)));

                _maximumTokenSizeInBytes = value;
            }
        }

        /// <summary>
        /// Determines if the string is a well formed Json Web Token (JWT).
        /// <para>see: http://tools.ietf.org/html/rfc7519 </para>
        /// </summary>
        /// <param name="tokenString">String that should represent a valid JWT.</param>
        /// <remarks>A JWT can be validated via the following RegExes:
        /// <para>JWS: @"^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*$"</para>
        /// <para>JWE: @"^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$"</para>
        /// </remarks>
        /// <returns>
        /// <para>'false' if the token is null or whitespace.</para>
        /// <para>'false' if token.Length * 2 >  <see cref="MaximumTokenSizeInBytes"/>.</para>
        /// <para>'true' if the token is in JSON compact serialization format.</para>
        /// </returns>
        public override bool CanReadToken(string tokenString)
        {
            if (string.IsNullOrWhiteSpace(tokenString))
                return false;

            if (tokenString.Length * 2 > MaximumTokenSizeInBytes)
            {
                IdentityModelEventSource.Logger.WriteInformation(LogMessages.IDX10209, tokenString.Length, MaximumTokenSizeInBytes);
                return false;
            }

            // Set the maximum number of segments to MaxJwtSegmentCount + 1. This controls the number of splits and allows detecting the number of segments is too large.
            // For example: "a.b.c.d.e.f.g.h" => [a], [b], [c], [d], [e], [f.g.h]. 6 segments.
            // If just MaxJwtSegmentCount was used, then [a], [b], [c], [d], [e.f.g.h] would be returned. 5 segments.
            string[] tokenParts = tokenString.Split(new char[] { '.' }, JwtConstants.MaxJwtSegmentCount + 1);
            if (tokenParts.Length == JwtConstants.JwsSegmentCount)
            {
                return Regex.IsMatch(tokenString, JwtConstants.JsonCompactSerializationRegex, RegexOptions.Compiled, TimeSpan.FromMilliseconds(100));
            }
            else if (tokenParts.Length == JwtConstants.JweSegmentCount)
            {
                return Regex.IsMatch(tokenString, JwtConstants.JweCompactSerializationRegex, RegexOptions.Compiled, TimeSpan.FromMilliseconds(100));
            }

            IdentityModelEventSource.Logger.WriteInformation(LogMessages.IDX10720);
            return false;
        }

        /// <summary>
        /// Returns a Json Web Token (JWT).
        /// </summary>
        /// <param name="tokenDescriptor">A <see cref="SecurityTokenDescriptor"/> that contains details of contents of the token.</param>
        /// <remarks>A JWS and JWE can be returned.
        /// <para>If <see cref="SecurityTokenDescriptor.EncryptingCredentials"/>is provided, then a JWE will be created.</para>
        /// <para>If <see cref="SecurityTokenDescriptor.SigningCredentials"/> is provided then a JWS will be created.</para>
        /// <para>If both are provided then a JWE with an embeded JWS will be created.</para>
        /// </remarks>
        public virtual string CreateEncodedJwt(SecurityTokenDescriptor tokenDescriptor)
        {
            if (tokenDescriptor == null)
                throw LogHelper.LogArgumentNullException(nameof(tokenDescriptor));

            return CreateJwtSecurityTokenPrivate(
                tokenDescriptor.Issuer,
                tokenDescriptor.Audience,
                tokenDescriptor.Subject,
                tokenDescriptor.NotBefore,
                tokenDescriptor.Expires,
                tokenDescriptor.IssuedAt,
                tokenDescriptor.SigningCredentials,
                tokenDescriptor.EncryptingCredentials).RawData;
        }

        /// <summary>
        /// Creates a JWT in 'Compact Serialization Format'.
        /// </summary>
        /// <param name="issuer">The issuer of the token.</param>
        /// <param name="audience">The audience for this token.</param>
        /// <param name="subject">The source of the <see cref="Claim"/>(s) for this token.</param>
        /// <param name="notBefore">The notbefore time for this token.</param>
        /// <param name="expires">The expiration time for this token.</param>
        /// <param name="issuedAt">The issue time for this token.</param>
        /// <param name="signingCredentials">Contains cryptographic material for generating a signature.</param>
        /// <remarks>If <see cref="ClaimsIdentity.Actor"/> is not null, then a claim { actort, 'value' } will be added to the payload. See <see cref="CreateActorValue"/> for details on how the value is created.
        /// <para>See <seealso cref="JwtHeader"/> for details on how the HeaderParameters are added to the header.</para>
        /// <para>See <seealso cref="JwtPayload"/> for details on how the values are added to the payload.</para>
        /// <para>Each <see cref="Claim"/> in the <paramref name="subject"/> will map <see cref="Claim.Type"/> by applying <see cref="OutboundClaimTypeMap"/>. Modifying <see cref="OutboundClaimTypeMap"/> could change outbound Json .</para>
        /// <para>If <see cref="SigningCredentials"/> is provided, then a JWS will be created.</para>
        /// </remarks>
        /// <returns>A Base64UrlEncoded string in 'Compact Serialization Format'.</returns>
        public virtual string CreateEncodedJwt(string issuer, string audience, ClaimsIdentity subject, DateTime? notBefore, DateTime? expires, DateTime? issuedAt, SigningCredentials signingCredentials)
        {
            return CreateJwtSecurityTokenPrivate(issuer, audience, subject, notBefore, expires, issuedAt, signingCredentials, null).RawData;
        }

        /// <summary>
        /// Creates a JWT in 'Compact Serialization Format'.
        /// </summary>
        /// <param name="issuer">The issuer of the token.</param>
        /// <param name="audience">The audience for this token.</param>
        /// <param name="subject">The source of the <see cref="Claim"/>(s) for this token.</param>
        /// <param name="notBefore">Translated into 'epoch time' and assigned to 'nbf'.</param>
        /// <param name="expires">Translated into 'epoch time' and assigned to 'exp'.</param>
        /// <param name="issuedAt">Translated into 'epoch time' and assigned to 'iat'.</param>
        /// <param name="signingCredentials">Contains cryptographic material for signint.</param>
        /// <param name="encryptingCredentials">Contains cryptographic material for encrypting.</param>
        /// <remarks>If <see cref="ClaimsIdentity.Actor"/> is not null, then a claim { actort, 'value' } will be added to the payload. <see cref="CreateActorValue"/> for details on how the value is created.
        /// <para>See <seealso cref="JwtHeader"/> for details on how the HeaderParameters are added to the header.</para>
        /// <para>See <seealso cref="JwtPayload"/> for details on how the values are added to the payload.</para>
        /// <para>Each <see cref="Claim"/> in the <paramref name="subject"/> will map <see cref="Claim.Type"/> by applying <see cref="OutboundClaimTypeMap"/>. Modifying <see cref="OutboundClaimTypeMap"/> could change outbound Json .</para>
        /// </remarks>
        /// <returns>A Base64UrlEncoded string in 'Compact Serialization Format'.</returns>
        /// <exception cref="ArgumentException">If 'expires' &lt;= 'notBefore'.</exception>
        public virtual string CreateEncodedJwt(string issuer, string audience, ClaimsIdentity subject, DateTime? notBefore, DateTime? expires, DateTime? issuedAt, SigningCredentials signingCredentials, EncryptingCredentials encryptingCredentials)
        {
            return CreateJwtSecurityTokenPrivate(issuer, audience, subject, notBefore, expires, issuedAt, signingCredentials, encryptingCredentials).RawData;
        }

        /// <summary>
        /// Creates a Json Web Token (JWT).
        /// </summary>
        /// <param name="tokenDescriptor"> A <see cref="SecurityTokenDescriptor"/> that contains details of contents of the token.</param>
        /// <remarks><see cref="SecurityTokenDescriptor.SigningCredentials"/> is used to sign <see cref="JwtSecurityToken.RawData"/>.</remarks>
        public virtual JwtSecurityToken CreateJwtSecurityToken(SecurityTokenDescriptor tokenDescriptor)
        {
            if (tokenDescriptor == null)
                throw LogHelper.LogArgumentNullException(nameof(tokenDescriptor));

            return CreateJwtSecurityTokenPrivate(
                tokenDescriptor.Issuer,
                tokenDescriptor.Audience,
                tokenDescriptor.Subject,
                tokenDescriptor.NotBefore,
                tokenDescriptor.Expires,
                tokenDescriptor.IssuedAt,
                tokenDescriptor.SigningCredentials,
                tokenDescriptor.EncryptingCredentials);
        }

        /// <summary>
        /// Creates a <see cref="JwtSecurityToken"/>
        /// </summary>
        /// <param name="issuer">The issuer of the token.</param>
        /// <param name="audience">The audience for this token.</param>
        /// <param name="subject">The source of the <see cref="Claim"/>(s) for this token.</param>
        /// <param name="notBefore">The notbefore time for this token.</param>
        /// <param name="expires">The expiration time for this token.</param>
        /// <param name="issuedAt">The issue time for this token.</param>
        /// <param name="signingCredentials">Contains cryptographic material for generating a signature.</param>
        /// <param name="encryptingCredentials">Contains cryptographic material for encrypting the token.</param>
        /// <remarks>If <see cref="ClaimsIdentity.Actor"/> is not null, then a claim { actort, 'value' } will be added to the payload. <see cref="CreateActorValue"/> for details on how the value is created.
        /// <para>See <seealso cref="JwtHeader"/> for details on how the HeaderParameters are added to the header.</para>
        /// <para>See <seealso cref="JwtPayload"/> for details on how the values are added to the payload.</para>
        /// <para>Each <see cref="Claim"/> on the <paramref name="subject"/> added will have <see cref="Claim.Type"/> translated according to the mapping found in
        /// <see cref="OutboundClaimTypeMap"/>. Adding and removing to <see cref="OutboundClaimTypeMap"/> will affect the name component of the Json claim.</para>
        /// <para><see cref="SigningCredentials.SigningCredentials(SecurityKey, string)"/> is used to sign <see cref="JwtSecurityToken.RawData"/>.</para>
        /// <para><see cref="EncryptingCredentials.EncryptingCredentials(SecurityKey, string, string)"/> is used to encrypt <see cref="JwtSecurityToken.RawData"/> or <see cref="JwtSecurityToken.RawPayload"/> .</para>
        /// </remarks>
        /// <returns>A <see cref="JwtSecurityToken"/>.</returns>
        /// <exception cref="ArgumentException">If 'expires' &lt;= 'notBefore'.</exception>
        public virtual JwtSecurityToken CreateJwtSecurityToken(string issuer = null, string audience = null, ClaimsIdentity subject = null, DateTime? notBefore = null, DateTime? expires = null, DateTime? issuedAt = null, SigningCredentials signingCredentials = null, EncryptingCredentials encryptingCredentials = null)
        {
            return CreateJwtSecurityTokenPrivate(issuer, audience, subject, notBefore, expires, issuedAt, signingCredentials, encryptingCredentials);
        }

        /// <summary>
        /// Creates a Json Web Token (JWT).
        /// </summary>
        /// <param name="tokenDescriptor"> A <see cref="SecurityTokenDescriptor"/> that contains details of contents of the token.</param>
        /// <remarks><see cref="SecurityTokenDescriptor.SigningCredentials"/> is used to sign <see cref="JwtSecurityToken.RawData"/>.</remarks>
        public override SecurityToken CreateToken(SecurityTokenDescriptor tokenDescriptor)
        {
            if (tokenDescriptor == null)
                throw LogHelper.LogArgumentNullException(nameof(tokenDescriptor));

            return CreateJwtSecurityTokenPrivate(
                tokenDescriptor.Issuer,
                tokenDescriptor.Audience,
                tokenDescriptor.Subject,
                tokenDescriptor.NotBefore,
                tokenDescriptor.Expires,
                tokenDescriptor.IssuedAt,
                tokenDescriptor.SigningCredentials,
                tokenDescriptor.EncryptingCredentials);
        }

        private JwtSecurityToken CreateJwtSecurityTokenPrivate(string issuer, string audience, ClaimsIdentity subject, DateTime? notBefore, DateTime? expires, DateTime? issuedAt, SigningCredentials signingCredentials, EncryptingCredentials encryptingCredentials)
        {
            if (SetDefaultTimesOnTokenCreation && (!expires.HasValue || !issuedAt.HasValue || !notBefore.HasValue))
            {
                DateTime now = DateTime.UtcNow;
                if (!expires.HasValue)
                    expires = now + TimeSpan.FromMinutes(TokenLifetimeInMinutes);

                if (!issuedAt.HasValue)
                    issuedAt = now;

                if (!notBefore.HasValue)
                    notBefore = now;
            }

            IdentityModelEventSource.Logger.WriteVerbose(LogMessages.IDX10721, (audience ?? "null"), (issuer ?? "null"));
            JwtPayload payload = new JwtPayload(issuer, audience, (subject == null ? null : OutboundClaimTypeTransform(subject.Claims)), notBefore, expires, issuedAt);
            JwtHeader header = signingCredentials == null ? new JwtHeader() : new JwtHeader(signingCredentials, OutboundAlgorithmMap);

            if (subject?.Actor != null)
                payload.AddClaim(new Claim(JwtRegisteredClaimNames.Actort, CreateActorValue(subject.Actor)));

            string rawHeader = header.Base64UrlEncode();
            string rawPayload = payload.Base64UrlEncode();
            string rawSignature = signingCredentials == null ? string.Empty : CreateEncodedSignature(string.Concat(rawHeader, ".", rawPayload), signingCredentials);

            IdentityModelEventSource.Logger.WriteInformation(LogMessages.IDX10722, rawHeader, rawPayload, rawSignature);

            if (encryptingCredentials != null)
                return CreateEncryptedToken(new JwtSecurityToken(header, payload, rawHeader, rawPayload, rawSignature), encryptingCredentials);
            else
                return new JwtSecurityToken(header, payload, rawHeader, rawPayload, rawSignature);
        }

        private JwtSecurityToken CreateEncryptedToken(JwtSecurityToken innerJwt, EncryptingCredentials encryptingCredentials)
        {
            var cryptoProviderFactory = encryptingCredentials.CryptoProviderFactory ?? encryptingCredentials.Key.CryptoProviderFactory;

            if (cryptoProviderFactory == null)
                throw LogHelper.LogExceptionMessage(new ArgumentException(LogMessages.IDX10733));

            if (!cryptoProviderFactory.IsSupportedAlgorithm(encryptingCredentials.Enc, encryptingCredentials.Key))
                throw LogHelper.LogExceptionMessage(new SecurityTokenEncryptionFailedException(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10615, innerJwt.Header.Enc, encryptingCredentials.Key)));

            var header = new JwtHeader(encryptingCredentials, OutboundAlgorithmMap);
            if (!JwtConstants.DirectKeyUseAlg.Equals(encryptingCredentials.Alg, StringComparison.Ordinal))
                throw LogHelper.LogExceptionMessage(new SecurityTokenEncryptionFailedException(LogMessages.IDX10734));

            var encryptionProvider = cryptoProviderFactory.CreateAuthenticatedEncryptionProvider(encryptingCredentials.Key, encryptingCredentials.Enc);
            if (encryptionProvider == null)
                throw LogHelper.LogExceptionMessage(new SecurityTokenEncryptionFailedException(LogMessages.IDX10730));

            try
            {
                var encryptionResult = encryptionProvider.Encrypt(Encoding.UTF8.GetBytes(innerJwt.RawData), Encoding.ASCII.GetBytes(header.Base64UrlEncode()));
                return new JwtSecurityToken(
                                header,
                                innerJwt,
                                header.Base64UrlEncode(),
                                string.Empty,
                                Base64UrlEncoder.Encode(encryptionResult.IV),
                                Base64UrlEncoder.Encode(encryptionResult.Ciphertext),
                                Base64UrlEncoder.Encode(encryptionResult.AuthenticationTag));
            }
            catch (Exception ex)
            {
                throw LogHelper.LogExceptionMessage(new SecurityTokenEncryptionFailedException(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10616, encryptingCredentials.Enc, encryptingCredentials.Key), ex));
            }
        }

        private IEnumerable<Claim> OutboundClaimTypeTransform(IEnumerable<Claim> claims)
        {
            foreach (Claim claim in claims)
            {
                string type = null;
                if (_outboundClaimTypeMap.TryGetValue(claim.Type, out type))
                {
                    yield return new Claim(type, claim.Value, claim.ValueType, claim.Issuer, claim.OriginalIssuer, claim.Subject);
                }
                else
                {
                    yield return claim;
                }
            }
        }

        /// <summary>
        /// Converts a string into an instance of <see cref="JwtSecurityToken"/>.
        /// </summary>
        /// <param name="token">A 'JSON Web Token' (JWT) in JWS or JWE Compact Serialization Format.</param>
        /// <returns>A <see cref="JwtSecurityToken"/></returns>
        /// <exception cref="ArgumentNullException">'token' is null or empty.</exception>
        /// <exception cref="ArgumentException">'token.Length * 2' > MaximumTokenSizeInBytes.</exception>
        /// <exception cref="ArgumentException"><see cref="CanReadToken(string)"/></exception>
        /// <remarks><para>If the 'token' is in JWE Compact Serialization format, only the protected header will be deserialized.</para>
        /// This method is unable to decrypt the payload. Use <see cref="ValidateToken(string, TokenValidationParameters, out SecurityToken)"/>to obtain the payload.</remarks>
        public JwtSecurityToken ReadJwtToken(string token)
        {
            if (string.IsNullOrEmpty(token))
                throw LogHelper.LogArgumentNullException(nameof(token));

            if (token.Length * 2 > MaximumTokenSizeInBytes)
                throw LogHelper.LogExceptionMessage(new ArgumentException(String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10209, token.Length, MaximumTokenSizeInBytes)));

            if (!CanReadToken(token))
                throw LogHelper.LogExceptionMessage(new ArgumentException(String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10709, token)));

            var jwt = new JwtSecurityToken();
            jwt.Decode(token.Split('.'), token);
            return jwt;
        }

        /// <summary>
        /// Converts a string into an instance of <see cref="JwtSecurityToken"/>.
        /// </summary>
        /// <param name="token">A 'JSON Web Token' (JWT) in JWS or JWE Compact Serialization Format.</param>
        /// <returns>A <see cref="JwtSecurityToken"/></returns>
        /// <exception cref="ArgumentNullException">'token' is null or empty.</exception>
        /// <exception cref="ArgumentException">'token.Length * 2' > MaximumTokenSizeInBytes.</exception>
        /// <exception cref="ArgumentException"><see cref="CanReadToken(string)"/></exception>
        /// <remarks><para>If the 'token' is in JWE Compact Serialization format, only the protected header will be deserialized.</para>
        /// This method is unable to decrypt the payload. Use <see cref="ValidateToken(string, TokenValidationParameters, out SecurityToken)"/>to obtain the payload.</remarks>
        public override SecurityToken ReadToken(string token)
        {
            return ReadJwtToken(token);
        }
        
        /// <summary>
        /// Deserializes token with the provided <see cref="TokenValidationParameters"/>.
        /// </summary>
        /// <param name="reader"><see cref="XmlReader"/>.</param>
        /// <param name="validationParameters">The current <see cref="TokenValidationParameters"/>.</param>
        /// <returns>The <see cref="SecurityToken"/></returns>
        /// <remarks>This method is not current supported.</remarks>
        public override SecurityToken ReadToken(XmlReader reader, TokenValidationParameters validationParameters)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Reads and validates a 'JSON Web Token' (JWT) encoded as a JWS or JWE in Compact Serialized Format.
        /// </summary>
        /// <param name="token">the JWT encoded as JWE or JWS</param>
        /// <param name="validationParameters">Contains validation parameters for the <see cref="JwtSecurityToken"/>.</param>
        /// <param name="validatedToken">The <see cref="JwtSecurityToken"/> that was validated.</param>
        /// <exception cref="ArgumentNullException">'token' is null or whitespace.</exception>
        /// <exception cref="ArgumentNullException">'validationParameters' is null.</exception>
        /// <exception cref="ArgumentNullException">token.Length * 2 > MamimumTokenSizeInBytes.</exception>
        /// <exception cref="ArgumentException">'token' does not have 3 or 5 parts.</exception>
        /// <returns>A <see cref="ClaimsPrincipal"/> from the jwt. Does not include the header claims.</returns>
        /// <remarks><see cref="ReadToken(string)"/> for additional exceptions.</remarks>
        public virtual ClaimsPrincipal ValidateToken(string token, TokenValidationParameters validationParameters, out SecurityToken validatedToken)
        {
            if (string.IsNullOrWhiteSpace(token))
                throw LogHelper.LogArgumentNullException(nameof(token));

            if (validationParameters == null)
                throw LogHelper.LogArgumentNullException(nameof(validationParameters));

            if (token.Length * 2 > MaximumTokenSizeInBytes)
                throw LogHelper.LogExceptionMessage(new ArgumentException(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10209, token.Length, MaximumTokenSizeInBytes)));

            var tokenParts = token.Split(new char[] { '.' }, JwtConstants.MaxJwtSegmentCount + 1);
            if (tokenParts.Length != JwtConstants.JwsSegmentCount && tokenParts.Length != JwtConstants.JweSegmentCount)
                throw LogHelper.LogExceptionMessage(new ArgumentException(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10709, token)));

            if (tokenParts.Length == JwtConstants.JweSegmentCount)
            {
                var jwtToken = ReadJwtToken(token);
                var decryptedJwt = DecryptToken(jwtToken, validationParameters);
                var innerToken = ValidateSignature(decryptedJwt, validationParameters);
                ValidateTokenPayload(innerToken, validationParameters);
                jwtToken.InnerToken = innerToken;
                validatedToken = jwtToken;
                return ValidateTokenPayload(innerToken, validationParameters);
            }
            else
            {
                validatedToken = ValidateSignature(token, validationParameters);
                return ValidateTokenPayload(validatedToken as JwtSecurityToken, validationParameters);
            }
        }

        /// <summary>
        /// Validates the JSON payload of a <see cref="JwtSecurityToken"/>.
        /// </summary>
        /// <param name="jwt">The token to validate.</param>
        /// <param name="validationParameters">Contains validation parameters for the <see cref="JwtSecurityToken"/>.</param>
        /// <returns>A <see cref="ClaimsPrincipal"/> from the jwt. Does not include the header claims.</returns>
        private ClaimsPrincipal ValidateTokenPayload(JwtSecurityToken jwt, TokenValidationParameters validationParameters)
        {
            DateTime? expires = (jwt.Payload.Exp == null) ? null : new DateTime?(jwt.ValidTo);
            DateTime? notBefore = (jwt.Payload.Nbf == null) ? null : new DateTime?(jwt.ValidFrom);

            if (validationParameters.ValidateLifetime)
            {
                if (validationParameters.LifetimeValidator != null)
                {
                    if (!validationParameters.LifetimeValidator(notBefore: notBefore, expires: expires, securityToken: jwt, validationParameters: validationParameters))
                        throw LogHelper.LogExceptionMessage(new SecurityTokenInvalidLifetimeException(String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10230, jwt))
                        { NotBefore = notBefore, Expires = expires });
                }
                else
                {
                    ValidateLifetime(notBefore: notBefore, expires: expires, securityToken: jwt, validationParameters: validationParameters);
                }
            }

            if (validationParameters.ValidateAudience)
            {
                if (validationParameters.AudienceValidator != null)
                {
                    if (!validationParameters.AudienceValidator(jwt.Audiences, jwt, validationParameters))
                        throw LogHelper.LogExceptionMessage(new SecurityTokenInvalidAudienceException(String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10231, jwt.ToString())));
                }
                else
                {
                    ValidateAudience(jwt.Audiences, jwt, validationParameters);
                }
            }

            string issuer = jwt.Issuer;
            if (validationParameters.ValidateIssuer)
            {
                if (validationParameters.IssuerValidator != null)
                {
                    issuer = validationParameters.IssuerValidator(issuer, jwt, validationParameters);
                }
                else
                {
                    issuer = ValidateIssuer(issuer, jwt, validationParameters);
                }
            }

            Validators.ValidateTokenReplay(jwt.RawData, expires, validationParameters);
            if (validationParameters.ValidateActor && !string.IsNullOrWhiteSpace(jwt.Actor))
            {
                SecurityToken actor = null;
                ValidateToken(jwt.Actor, validationParameters.ActorValidationParameters ?? validationParameters, out actor);
            }

            if (jwt.SigningKey != null && validationParameters.ValidateIssuerSigningKey)
            {
                if (validationParameters.IssuerSigningKeyValidator != null)
                {
                    if (!validationParameters.IssuerSigningKeyValidator(jwt.SigningKey, jwt, validationParameters))
                        throw LogHelper.LogExceptionMessage(new SecurityTokenInvalidSigningKeyException(String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10232, jwt.SigningKey)){ SigningKey = jwt.SigningKey });
                }
                else
                {
                    ValidateIssuerSecurityKey(jwt.SigningKey, jwt, validationParameters);
                }
            }

            ClaimsIdentity identity = CreateClaimsIdentity(jwt, issuer, validationParameters);
            if (validationParameters.SaveSigninToken)
                identity.BootstrapContext = jwt.RawData;

            IdentityModelEventSource.Logger.WriteInformation(LogMessages.IDX10241, jwt.RawData);
            return new ClaimsPrincipal(identity);
        }

        /// <summary>
        /// Serializes a <see cref="JwtSecurityToken"/> into a JWT in Compact Serialization Format.
        /// </summary>
        /// <param name="token"><see cref="JwtSecurityToken"/> to serialize.</param>
        /// <remarks>
        /// <para>The JWT will be serialized as a JWE or JWS.</para>
        /// <para><see cref="JwtSecurityToken.Payload"/> will be used to create the JWT. If there is an inner token, the inner token's payload will be used.</para>
        /// <para>If either <see cref="JwtSecurityToken.SigningCredentials"/> or <see cref="JwtSecurityToken.InnerToken"/>.SigningCredentials are set, the JWT will be signed.</para>
        /// <para>If <see cref="JwtSecurityToken.EncryptingCredentials"/> is set, a JWE will be created using the JWT above as the plaintext.</para>
        /// </remarks>
        /// <exception cref="ArgumentNullException">'token' is null.</exception>
        /// <exception cref="ArgumentException">'token' is not a not <see cref="JwtSecurityToken"/>.</exception>
        /// <exception cref="SecurityTokenEncryptionFailedException">both <see cref="JwtSecurityToken.SigningCredentials"/> and <see cref="JwtSecurityToken.InnerToken"/> are set.</exception>
        /// <exception cref="SecurityTokenEncryptionFailedException">both <see cref="JwtSecurityToken.InnerToken"/> and <see cref="JwtSecurityToken.InnerToken"/>.EncryptingCredentials are set.</exception>
        /// <exception cref="SecurityTokenEncryptionFailedException">if <see cref="JwtSecurityToken.InnerToken"/> is set and <see cref="JwtSecurityToken.EncryptingCredentials"/> is not set.</exception>
        /// <returns>A JWE or JWS in 'Compact Serialization Format'.</returns>
        public override string WriteToken(SecurityToken token)
        {
            if (token == null)
                throw LogHelper.LogArgumentNullException("token");

            JwtSecurityToken jwtToken = token as JwtSecurityToken;
            if (jwtToken == null)
                throw LogHelper.LogExceptionMessage(new ArgumentException(String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10706, GetType(), typeof(JwtSecurityToken), token.GetType()), nameof(token)));

            var encodedPayload = jwtToken.EncodedPayload;
            var encodedSignature = string.Empty;
            var encodedHeader = string.Empty;
            if (jwtToken.InnerToken != null)
            {
                if (jwtToken.SigningCredentials != null)
                    throw LogHelper.LogExceptionMessage(new SecurityTokenEncryptionFailedException(LogMessages.IDX10736));

                if (jwtToken.InnerToken.Header.EncryptingCredentials != null)
                    throw LogHelper.LogExceptionMessage(new SecurityTokenEncryptionFailedException(LogMessages.IDX10737));

                if (jwtToken.Header.EncryptingCredentials == null)
                    throw LogHelper.LogExceptionMessage(new SecurityTokenEncryptionFailedException(LogMessages.IDX10735));

                if (jwtToken.InnerToken.SigningCredentials != null)
                    encodedSignature = CreateEncodedSignature(string.Concat(jwtToken.InnerToken.EncodedHeader, ".", jwtToken.EncodedPayload), jwtToken.InnerToken.SigningCredentials);

                return CreateEncryptedToken(new JwtSecurityToken(jwtToken.InnerToken.Header, jwtToken.InnerToken.Payload, jwtToken.InnerToken.EncodedHeader, encodedPayload, encodedSignature), jwtToken.EncryptingCredentials).RawData;
            }

            // if EncryptingCredentials isn't set, then we need to create JWE
            // first create a new header with the SigningCredentials, Create a JWS then wrap it in a JWE
            var header = jwtToken.EncryptingCredentials == null ? jwtToken.Header : new JwtHeader(jwtToken.SigningCredentials);
            encodedHeader = header.Base64UrlEncode();
            if (jwtToken.SigningCredentials != null)
                encodedSignature =  CreateEncodedSignature(string.Concat(encodedHeader, ".", encodedPayload), jwtToken.SigningCredentials);

            if (jwtToken.EncryptingCredentials != null)
                return CreateEncryptedToken(new JwtSecurityToken(header, jwtToken.Payload, encodedHeader, encodedPayload, encodedSignature), jwtToken.EncryptingCredentials).RawData;
            else
                return string.Concat(encodedHeader, ".", encodedPayload, ".", encodedSignature);
        }

        /// <summary>
        /// Produces a signature over the 'input'.
        /// </summary>
        /// <param name="input">String to be signed</param>
        /// <param name="signingCredentials">The <see cref="SigningCredentials"/> that contain crypto specs used to sign the token.</param>
        /// <returns>The bse64urlendcoded signature over the bytes obtained from UTF8Encoding.GetBytes( 'input' ).</returns>
        /// <exception cref="ArgumentNullException">'input' or 'signingCredentials' is null.</exception>
        internal static string CreateEncodedSignature(string input, SigningCredentials signingCredentials)
        {
            if (input == null)
                throw LogHelper.LogArgumentNullException(nameof(input));

            if (signingCredentials == null)
                throw LogHelper.LogArgumentNullException(nameof(signingCredentials));

            var cryptoProviderFactory = signingCredentials.CryptoProviderFactory ?? signingCredentials.Key.CryptoProviderFactory;
            var signatureProvider = cryptoProviderFactory.CreateForSigning(signingCredentials.Key, signingCredentials.Algorithm);
            if (signatureProvider == null)
                throw LogHelper.LogExceptionMessage(new InvalidOperationException(String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10636, (signingCredentials.Key == null ? "Null" : signingCredentials.Key.ToString()), (signingCredentials.Algorithm ?? "Null"))));

            try
            {
                IdentityModelEventSource.Logger.WriteVerbose(LogMessages.IDX10645);
                return Base64UrlEncoder.Encode(signatureProvider.Sign(Encoding.UTF8.GetBytes(input)));
            }
            finally
            {
                cryptoProviderFactory.ReleaseSignatureProvider(signatureProvider);
            }
        }

        /// <summary>
        /// Obtains a SignatureProvider and validates the signature.
        /// </summary>
        /// <param name="encodedBytes">bytes to validate.</param>
        /// <param name="signature">signature to compare against.</param>
        /// <param name="key"><see cref="SecurityKey"/> to use.</param>
        /// <param name="algorithm">crypto algorithm to use.</param>
        /// <param name="validationParameters">priority will be given to <see cref="TokenValidationParameters.CryptoProviderFactory"/> over <see cref="SecurityKey.CryptoProviderFactory"/>.</param>
        /// <returns>true if signature is valid.</returns>
        private bool ValidateSignature(byte[] encodedBytes, byte[] signature, SecurityKey key, string algorithm, TokenValidationParameters validationParameters)
        {
            var cryptoProviderFactory = validationParameters.CryptoProviderFactory ?? key.CryptoProviderFactory;
            if (!cryptoProviderFactory.IsSupportedAlgorithm(algorithm, key))
            {
                IdentityModelEventSource.Logger.WriteInformation(LogMessages.IDX10508, algorithm, key);
                return false;
            }

            var signatureProvider = cryptoProviderFactory.CreateForVerifying(key, algorithm);
            if (signatureProvider == null)
                throw LogHelper.LogExceptionMessage(new InvalidOperationException(String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10636, (key == null ? "Null" : key.ToString()), (algorithm == null ? "Null" : algorithm))));

            try
            {
                return signatureProvider.Verify(encodedBytes, signature);
            }
            finally
            {
                cryptoProviderFactory.ReleaseSignatureProvider(signatureProvider);
            }
        }

        /// <summary>
        /// Validates that the signature, if found or required, is valid.
        /// </summary>
        /// <param name="token">A JWS token.</param>
        /// <param name="validationParameters"><see cref="TokenValidationParameters"/> that contains signing keys.</param>
        /// <exception cref="ArgumentNullException">If 'jwt' is null or whitespace.</exception>
        /// <exception cref="ArgumentNullException">If 'validationParameters' is null.</exception>
        /// <exception cref="SecurityTokenValidationException">If a signature is not found and <see cref="TokenValidationParameters.RequireSignedTokens"/> is true.</exception>
        /// <exception cref="SecurityTokenSignatureKeyNotFoundException">If the 'token' has a key identifier and none of the <see cref="SecurityKey"/>(s) provided result in a validated signature. 
        /// This can indicate that a key refresh is required.</exception>
        /// <exception cref="SecurityTokenInvalidSignatureException">If after trying all the <see cref="SecurityKey"/>(s), none result in a validated signture AND the 'token' does not have a key identifier.</exception>
        /// <returns><see cref="JwtSecurityToken"/> that has the signature validated if token was signed and <see cref="TokenValidationParameters.RequireSignedTokens"/> is true.</returns>
        /// <remarks><para>If the 'token' is signed, the signature is validated even if <see cref="TokenValidationParameters.RequireSignedTokens"/> is false.</para>
        /// <para>If the 'token' signature is validated, then the <see cref="JwtSecurityToken.SigningKey"/> will be set to the key that signed the 'token'.</para></remarks>
        protected virtual JwtSecurityToken ValidateSignature(string token, TokenValidationParameters validationParameters)
        {
            if (string.IsNullOrWhiteSpace(token))
                throw LogHelper.LogArgumentNullException(nameof(token));

            if (validationParameters == null)
                throw LogHelper.LogArgumentNullException(nameof(validationParameters));

            if (validationParameters.SignatureValidator != null)
            {
                var validatedJwtToken = validationParameters.SignatureValidator(token, validationParameters);
                if (validatedJwtToken == null)
                    throw LogHelper.LogExceptionMessage(new SecurityTokenInvalidSignatureException(String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10505, token)));

                var validatedJwt = validatedJwtToken as JwtSecurityToken;
                if (validatedJwt == null)
                    throw LogHelper.LogExceptionMessage(new SecurityTokenInvalidSignatureException(String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10506, typeof(JwtSecurityToken), validatedJwtToken.GetType(), token)));

                return validatedJwt;
            }

            JwtSecurityToken jwt = ReadJwtToken(token);
            byte[] encodedBytes = Encoding.UTF8.GetBytes(jwt.RawHeader + "." + jwt.RawPayload);
            if (string.IsNullOrEmpty(jwt.RawSignature))
            {
                if (validationParameters.RequireSignedTokens)
                    throw LogHelper.LogExceptionMessage(new SecurityTokenInvalidSignatureException(String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10504, token)));
                else
                    return jwt;
            }

            bool keyMatched = false;           
            IEnumerable<SecurityKey> securityKeys = null;
            if (validationParameters.IssuerSigningKeyResolver != null)
            {
                securityKeys = validationParameters.IssuerSigningKeyResolver(token, jwt, jwt.Header.Kid, validationParameters);
            }
            else
            {
                var securityKey = ResolveIssuerSigningKey(token, jwt, validationParameters);
                if (securityKey != null)
                {
                    keyMatched = true;
                    securityKeys = new List<SecurityKey> { securityKey };
                }
            }

            if (securityKeys == null)
            {
                // control gets here if:
                // 1. User specified delegate: IssuerSigningKeyResolver returned null
                // 2. ResolveIssuerSigningKey returned null
                // Try all the keys. This is the degenerate case, not concerned about perf.
                securityKeys = GetAllKeys(token, jwt, jwt.Header.Kid, validationParameters);
            }

            // keep track of exceptions thrown, keys that were tried
            StringBuilder exceptionStrings = new StringBuilder();
            StringBuilder keysAttempted = new StringBuilder();

            bool canMatchKey = !string.IsNullOrEmpty(jwt.Header.Kid);
            byte[] signatureBytes = Base64UrlEncoder.DecodeBytes(jwt.RawSignature);
            foreach (SecurityKey securityKey in securityKeys)
            {
                try
                {
                    if (ValidateSignature(encodedBytes, signatureBytes, securityKey, jwt.Header.Alg, validationParameters))
                    {
                        IdentityModelEventSource.Logger.WriteInformation(LogMessages.IDX10242, token);
                        jwt.SigningKey = securityKey;
                        return jwt;
                    }
                }
                catch (Exception ex)
                {
                    exceptionStrings.AppendLine(ex.ToString());
                }

                if (securityKey != null)
                {
                    keysAttempted.AppendLine(securityKey.ToString() + " , KeyId: " + securityKey.KeyId);
                    if (canMatchKey && !keyMatched)
                        keyMatched = jwt.Header.Kid.Equals(securityKey.KeyId, StringComparison.Ordinal);
                }
            }

            // if the kid != null and the signature fails, throw SecurityTokenSignatureKeyNotFoundException
            if (!keyMatched && canMatchKey && keysAttempted.Length > 0)
                throw LogHelper.LogExceptionMessage(new SecurityTokenSignatureKeyNotFoundException(String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10501, jwt.Header.Kid, jwt)));

            if (keysAttempted.Length > 0)
                throw LogHelper.LogExceptionMessage(new SecurityTokenInvalidSignatureException(String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10503, keysAttempted, exceptionStrings, jwt)));

            throw LogHelper.LogExceptionMessage(new SecurityTokenInvalidSignatureException(LogMessages.IDX10500));
        }

        private IEnumerable<SecurityKey> GetAllKeys(string token, JwtSecurityToken securityToken, string kid, TokenValidationParameters validationParameters)
        {
            IdentityModelEventSource.Logger.WriteInformation(LogMessages.IDX10243);
            if (validationParameters.IssuerSigningKey != null)
                yield return validationParameters.IssuerSigningKey;

            if (validationParameters.IssuerSigningKeys != null)
                foreach (SecurityKey securityKey in validationParameters.IssuerSigningKeys)
                    yield return securityKey;
        }
        
        private IEnumerable<SecurityKey> GetAllDecryptionKeys(TokenValidationParameters validationParameters)
        {
            if (validationParameters.TokenDecryptionKey != null)
                yield return validationParameters.TokenDecryptionKey;

            if (validationParameters.TokenDecryptionKeys != null)
                foreach (SecurityKey securityKey in validationParameters.TokenDecryptionKeys)
                    yield return securityKey;
        }

        /// <summary>
        /// Creates a <see cref="ClaimsIdentity"/> from a <see cref="JwtSecurityToken"/>.
        /// </summary>
        /// <param name="jwt">The <see cref="JwtSecurityToken"/> to use as a <see cref="Claim"/> source.</param>
        /// <param name="issuer">The value to set <see cref="Claim.Issuer"/></param>
        /// <param name="validationParameters"> Contains parameters for validating the token.</param>
        /// <returns>A <see cref="ClaimsIdentity"/> containing the <see cref="JwtSecurityToken.Claims"/>.</returns>
        protected virtual ClaimsIdentity CreateClaimsIdentity(JwtSecurityToken jwt, string issuer, TokenValidationParameters validationParameters)
        {
            if (jwt == null)
                throw LogHelper.LogArgumentNullException("jwt");

            if (string.IsNullOrWhiteSpace(issuer))
                IdentityModelEventSource.Logger.WriteVerbose(LogMessages.IDX10244, ClaimsIdentity.DefaultIssuer);

            ClaimsIdentity identity = validationParameters.CreateClaimsIdentity(jwt, issuer);
            foreach (Claim jwtClaim in jwt.Claims)
            {
                if (_inboundClaimFilter.Contains(jwtClaim.Type))
                {
                    continue;
                }

                string claimType;
                bool wasMapped = true;
                if (!_inboundClaimTypeMap.TryGetValue(jwtClaim.Type, out claimType))
                {
                    claimType = jwtClaim.Type;
                    wasMapped = false;
                }

                if (claimType == ClaimTypes.Actor)
                {
                    if (identity.Actor != null)
                        throw LogHelper.LogExceptionMessage(new InvalidOperationException(String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10710, JwtRegisteredClaimNames.Actort, jwtClaim.Value)));

                    if (CanReadToken(jwtClaim.Value))
                    {
                        JwtSecurityToken actor = ReadToken(jwtClaim.Value) as JwtSecurityToken;
                        identity.Actor = CreateClaimsIdentity(actor, issuer, validationParameters);
                    }
                }

                Claim c = new Claim(claimType, jwtClaim.Value, jwtClaim.ValueType, issuer, issuer, identity);
                if (jwtClaim.Properties.Count > 0)
                {
                    foreach(var kv in jwtClaim.Properties)
                    {
                        c.Properties[kv.Key] = kv.Value;
                    }
                }

                if (wasMapped)
                {
                    c.Properties[ShortClaimTypeProperty] = jwtClaim.Type;
                }

                identity.AddClaim(c);
            }

            return identity;
        }

        /// <summary>
        /// Creates the 'value' for the actor claim: { actort, 'value' }
        /// </summary>
        /// <param name="actor"><see cref="ClaimsIdentity"/> as actor.</param>
        /// <returns><see cref="string"/> representing the actor.</returns>
        /// <remarks>If <see cref="ClaimsIdentity.BootstrapContext"/> is not null:
        /// <para>&#160;&#160;If 'type' is 'string', return as string.</para>
        /// <para>&#160;&#160;if 'type' is 'BootstrapContext' and 'BootstrapContext.SecurityToken' is 'JwtSecurityToken'</para>
        /// <para>&#160;&#160;&#160;&#160;if 'JwtSecurityToken.RawData' != null, return RawData.</para>        
        /// <para>&#160;&#160;&#160;&#160;else return <see cref="JwtSecurityTokenHandler.WriteToken( SecurityToken )"/>.</para>        
        /// <para>&#160;&#160;if 'BootstrapContext.Token' != null, return 'Token'.</para>
        /// <para>default: <see cref="JwtSecurityTokenHandler.WriteToken(SecurityToken)"/> new ( <see cref="JwtSecurityToken"/>( actor.Claims ).</para>
        /// </remarks>
        /// <exception cref="ArgumentNullException">'actor' is null.</exception>
        protected virtual string CreateActorValue(ClaimsIdentity actor)
        {
            if (actor == null)
                throw LogHelper.LogArgumentNullException(nameof(actor));

            if (actor.BootstrapContext != null)
            {
                string encodedJwt = actor.BootstrapContext as string;
                if (encodedJwt != null)
                {
                    IdentityModelEventSource.Logger.WriteVerbose(LogMessages.IDX10713);
                    return encodedJwt;
                }

                JwtSecurityToken jwt = actor.BootstrapContext as JwtSecurityToken;
                if (jwt != null)
                {
                    if (jwt.RawData != null)
                    {
                        IdentityModelEventSource.Logger.WriteVerbose(LogMessages.IDX10714);
                        return jwt.RawData;
                    }
                    else
                    {
                        IdentityModelEventSource.Logger.WriteVerbose(LogMessages.IDX10715);
                        return this.WriteToken(jwt);
                    }
                }

                IdentityModelEventSource.Logger.WriteVerbose(LogMessages.IDX10711);
            }

            IdentityModelEventSource.Logger.WriteVerbose(LogMessages.IDX10712);
            return WriteToken(new JwtSecurityToken(claims: actor.Claims));
        }

        /// <summary>
        /// Determines if the audiences found in a <see cref="JwtSecurityToken"/> are valid.
        /// </summary>
        /// <param name="audiences">The audiences found in the <see cref="JwtSecurityToken"/>.</param>
        /// <param name="securityToken">The <see cref="JwtSecurityToken"/> being validated.</param>
        /// <param name="validationParameters"><see cref="TokenValidationParameters"/> required for validation.</param>
        /// <remarks>See <see cref="Validators.ValidateAudience"/> for additional details.</remarks>
        protected virtual void ValidateAudience(IEnumerable<string> audiences, JwtSecurityToken securityToken, TokenValidationParameters validationParameters)
        {
            Validators.ValidateAudience(audiences, securityToken, validationParameters);
        }

        /// <summary>
        /// Validates the lifetime of a <see cref="JwtSecurityToken"/>.
        /// </summary>
        /// <param name="notBefore">The <see cref="DateTime"/> value of the 'nbf' claim if it exists in the 'jwt'.</param>
        /// <param name="expires">The <see cref="DateTime"/> value of the 'exp' claim if it exists in the 'jwt'.</param>
        /// <param name="securityToken">The <see cref="JwtSecurityToken"/> being validated.</param>
        /// <param name="validationParameters"><see cref="TokenValidationParameters"/> required for validation.</param>
        /// <remarks><see cref="Validators.ValidateLifetime"/> for additional details.</remarks>
        protected virtual void ValidateLifetime(DateTime? notBefore, DateTime? expires, JwtSecurityToken securityToken, TokenValidationParameters validationParameters)
        {
            Validators.ValidateLifetime(notBefore: notBefore, expires: expires, securityToken: securityToken, validationParameters: validationParameters);
        }

        /// <summary>
        /// Determines if an issuer found in a <see cref="JwtSecurityToken"/> is valid.
        /// </summary>
        /// <param name="issuer">The issuer to validate</param>
        /// <param name="securityToken">The <see cref="JwtSecurityToken"/> that is being validated.</param>
        /// <param name="validationParameters"><see cref="TokenValidationParameters"/> required for validation.</param>
        /// <returns>The issuer to use when creating the <see cref="Claim"/>(s) in the <see cref="ClaimsIdentity"/>.</returns>
        /// <remarks><see cref="Validators.ValidateIssuer"/> for additional details.</remarks>
        protected virtual string ValidateIssuer(string issuer, JwtSecurityToken securityToken, TokenValidationParameters validationParameters)
        {
            return Validators.ValidateIssuer(issuer, securityToken, validationParameters);
        }

        /// <summary>
        /// Returns a <see cref="SecurityKey"/> to use when validating the signature of a token.
        /// </summary>
        /// <param name="token">The <see cref="string"/> representation of the token that is being validated.</param>
        /// <param name="jwtToken">The <see cref="JwtSecurityToken"/> that is being validated.</param>
        /// <param name="validationParameters">A <see cref="TokenValidationParameters"/>  required for validation.</param>
        /// <returns>Returns a <see cref="SecurityKey"/> to use for signature validation.</returns>
        /// <remarks>If key fails to resolve, then null is returned</remarks>
        protected virtual SecurityKey ResolveIssuerSigningKey(string token, JwtSecurityToken jwtToken, TokenValidationParameters validationParameters)
        {
            if (validationParameters == null)
                throw LogHelper.LogArgumentNullException("validationParameters");

            if (jwtToken == null)
                throw LogHelper.LogArgumentNullException("securityToken");

            if (!string.IsNullOrEmpty(jwtToken.Header.Kid))
            {
                string kid = jwtToken.Header.Kid;
                if (validationParameters.IssuerSigningKey != null && string.Equals(validationParameters.IssuerSigningKey.KeyId, kid, StringComparison.Ordinal))
                {
                    return validationParameters.IssuerSigningKey;
                }

                if (validationParameters.IssuerSigningKeys != null)
                {
                    foreach (SecurityKey signingKey in validationParameters.IssuerSigningKeys)
                    {
                        if (signingKey != null && string.Equals(signingKey.KeyId, kid, StringComparison.Ordinal))
                        {
                            return signingKey;
                        }
                    }
                }
            }

            if (!string.IsNullOrEmpty(jwtToken.Header.X5t))
            {
                string x5t = jwtToken.Header.X5t;
                if (validationParameters.IssuerSigningKey != null)
                {
                    if (string.Equals(validationParameters.IssuerSigningKey.KeyId, x5t, StringComparison.Ordinal))
                    {
                        return validationParameters.IssuerSigningKey;
                    }

                    X509SecurityKey x509Key = validationParameters.IssuerSigningKey as X509SecurityKey;
                    if (x509Key != null && string.Equals(x509Key.X5t, x5t, StringComparison.Ordinal))
                    {
                        return validationParameters.IssuerSigningKey;
                    }
                }

                if (validationParameters.IssuerSigningKeys != null)
                {
                    foreach (SecurityKey signingKey in validationParameters.IssuerSigningKeys)
                    {
                        if (signingKey != null && string.Equals(signingKey.KeyId, x5t, StringComparison.Ordinal))
                        {
                            return signingKey;
                        }
                    }
                }
            }

            return null;
        }

        /// <summary>
        /// Returns a <see cref="SecurityKey"/> to use when decryption a JWE.
        /// </summary>
        /// <param name="token">The <see cref="string"/> the token that is being decrypted.</param>
        /// <param name="jwtToken">The <see cref="JwtSecurityToken"/> that is being decrypted.</param>
        /// <param name="validationParameters">A <see cref="TokenValidationParameters"/>  required for validation.</param>
        /// <returns>Returns a <see cref="SecurityKey"/> to use for signature validation.</returns>
        /// <remarks>If key fails to resolve, then null is returned</remarks>
        protected virtual SecurityKey ResolveTokenDecryptionKey(string token, JwtSecurityToken jwtToken, TokenValidationParameters validationParameters)
        {
            if (jwtToken == null)
                throw LogHelper.LogArgumentNullException(nameof(jwtToken));

            if (validationParameters == null)
                throw LogHelper.LogArgumentNullException(nameof(validationParameters));

            if (!string.IsNullOrEmpty(jwtToken.Header.Kid))
            {
                if (validationParameters.TokenDecryptionKey != null && string.Equals(validationParameters.TokenDecryptionKey.KeyId, jwtToken.Header.Kid, StringComparison.Ordinal))
                    return validationParameters.TokenDecryptionKey;

                if (validationParameters.TokenDecryptionKeys != null)
                {
                    foreach (var key in validationParameters.TokenDecryptionKeys)
                    {
                        if (key != null && string.Equals(key.KeyId, jwtToken.Header.Kid, StringComparison.Ordinal))
                            return key;
                    }
                }

                if (!string.IsNullOrEmpty(jwtToken.Header.X5t))
                {
                    if (validationParameters.TokenDecryptionKey != null)
                    {
                        if (string.Equals(validationParameters.TokenDecryptionKey.KeyId, jwtToken.Header.X5t, StringComparison.Ordinal))
                            return validationParameters.TokenDecryptionKey;

                        X509SecurityKey x509Key = validationParameters.TokenDecryptionKey as X509SecurityKey;
                        if (x509Key != null && string.Equals(x509Key.X5t, jwtToken.Header.X5t, StringComparison.Ordinal))
                            return validationParameters.TokenDecryptionKey;
                    }

                    if (validationParameters.TokenDecryptionKeys != null)
                    {
                        foreach (var key in validationParameters.TokenDecryptionKeys)
                        {
                            if (key != null && string.Equals(key.KeyId, jwtToken.Header.X5t, StringComparison.Ordinal))
                                return key;

                            X509SecurityKey x509Key = key as X509SecurityKey;
                            if (x509Key != null && string.Equals(x509Key.X5t, jwtToken.Header.X5t, StringComparison.Ordinal))
                                return key;
                        }
                    }
                }
            }

            return null;
        }

        private string DecryptToken(JwtSecurityToken jwtToken, CryptoProviderFactory cryptoProviderFactory, SecurityKey key)
        {
            var decryptionProvider = cryptoProviderFactory.CreateAuthenticatedEncryptionProvider(key, jwtToken.Header.Enc);
            if (decryptionProvider == null)
                throw LogHelper.LogExceptionMessage(new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10610, key, jwtToken.Header.Enc)));

            return UTF8Encoding.UTF8.GetString(
                decryptionProvider.Decrypt(
                    Base64UrlEncoder.DecodeBytes(jwtToken.RawCiphertext),
                    Encoding.ASCII.GetBytes(jwtToken.RawHeader),
                    Base64UrlEncoder.DecodeBytes(jwtToken.RawInitializationVector),
                    Base64UrlEncoder.DecodeBytes(jwtToken.RawAuthenticationTag)
                ));
        }

        /// <summary>
        /// Decrypts a JWE and returns the clear text 
        /// </summary>
        /// <param name="jwtToken">the JWE that contains the cypher text.</param>
        /// <param name="validationParameters">contains crypto material.</param>
        /// <returns>the decoded / cleartext contents of the JWE.</returns>
        /// <exception cref="ArgumentNullException">if 'jwtToken' is null.</exception>
        /// <exception cref="ArgumentNullException">if 'validationParameters' is null.</exception>
        /// <exception cref="SecurityTokenException">if 'jwtToken.Header.enc' is null or empty.</exception>
        /// <exception cref="SecurityTokenException">if 'jwtToken.Header.alg' is not equal to 'dir'.</exception>
        /// <exception cref="SecurityTokenEncryptionKeyNotFoundException">if 'jwtToken.Header.kid' is not null AND decryption fails.</exception>
        /// <exception cref="SecurityTokenDecryptionFailedException">if the JWE was not able to be decrypted.</exception>
        protected string DecryptToken(JwtSecurityToken jwtToken, TokenValidationParameters validationParameters)
        {
            if (jwtToken == null)
                throw LogHelper.LogArgumentNullException(nameof(jwtToken));

            if (validationParameters == null)
                throw LogHelper.LogArgumentNullException(nameof(validationParameters));

            if (string.IsNullOrEmpty(jwtToken.Header.Enc))
                throw LogHelper.LogExceptionMessage(new SecurityTokenException(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10612)));

            if (!JwtConstants.DirectKeyUseAlg.Equals(jwtToken.Header.Alg, StringComparison.Ordinal))
                throw LogHelper.LogExceptionMessage(new SecurityTokenException(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10605, jwtToken.Header.Alg)));

            IEnumerable<SecurityKey> securityKeys = null;
            if (validationParameters.TokenDecryptionKeyResolver != null)
            {
                securityKeys = validationParameters.TokenDecryptionKeyResolver(jwtToken.RawData, jwtToken, jwtToken.Header.Kid, validationParameters);
            }
            else
            {
                var securityKey = ResolveTokenDecryptionKey(jwtToken.RawData, jwtToken, validationParameters);
                if (securityKey != null)
                    securityKeys = new List<SecurityKey> { securityKey };
            }

            if (securityKeys == null)
            {
                // control gets here if:
                // 1. User specified delegate: TokenDecryptionKeyResolver returned null
                // 2. ResolveTokenDecryptionKey returned null
                // Try all the keys. This is the degenerate case, not concerned about perf.
                securityKeys = GetAllDecryptionKeys(validationParameters);
            }

            // keep track of exceptions thrown, keys that were tried
            StringBuilder exceptionStrings = new StringBuilder();
            StringBuilder keysAttempted = new StringBuilder();
            foreach (SecurityKey key in securityKeys)
            {
                var cryptoProviderFactory = validationParameters.CryptoProviderFactory ?? key.CryptoProviderFactory;
                if (cryptoProviderFactory == null)
                {
                    IdentityModelEventSource.Logger.WriteWarning(LogMessages.IDX10607, key);
                    continue;
                }

                if (!cryptoProviderFactory.IsSupportedAlgorithm(jwtToken.Header.Enc, key))
                {
                    IdentityModelEventSource.Logger.WriteWarning(LogMessages.IDX10611, jwtToken.Header.Enc, key);
                    continue;
                }

                try
                {
                    return DecryptToken(jwtToken, cryptoProviderFactory, key);
                }
                catch (Exception ex)
                {
                    exceptionStrings.AppendLine(ex.ToString());
                }

                if (key != null)
                    keysAttempted.AppendLine(key.ToString());
            }

            if (keysAttempted.Length > 0)
                throw LogHelper.LogExceptionMessage(new SecurityTokenDecryptionFailedException(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10609, keysAttempted, exceptionStrings, jwtToken.RawData)));

            throw LogHelper.LogExceptionMessage(new SecurityTokenDecryptionFailedException(LogMessages.IDX10600));
        }

        private byte[] GetSymmetricSecurityKey(SecurityKey key)
        {
            if (key == null)
                throw LogHelper.LogArgumentNullException("key");

            // try to use the provided key directly.
            SymmetricSecurityKey symmetricSecurityKey = key as SymmetricSecurityKey;
            if (symmetricSecurityKey != null)
                return symmetricSecurityKey.Key;
            else
            {
                JsonWebKey jsonWebKey = key as JsonWebKey;
                if (jsonWebKey != null && jsonWebKey.K != null)
                    return Base64UrlEncoder.DecodeBytes(jsonWebKey.K);
            }

            return null;
        }

        /// <summary>
        /// Gets or sets a bool that controls if token creation will set default 'exp', 'nbf' and 'iat' if not specified.
        /// </summary>
        /// <remarks>See: <see cref="DefaultTokenLifetimeInMinutes"/>, <see cref="TokenLifetimeInMinutes"/> for defaults and configuration.</remarks>
        [DefaultValue(true)]
        public bool SetDefaultTimesOnTokenCreation { get; set; } = true;

        /// <summary>
        /// Validates the <see cref="JwtSecurityToken.SigningKey"/> is an expected value.
        /// </summary>
        /// <param name="securityKey">The <see cref="SecurityKey"/> that signed the <see cref="SecurityToken"/>.</param>
        /// <param name="securityToken">The <see cref="JwtSecurityToken"/> to validate.</param>
        /// <param name="validationParameters">The current <see cref="TokenValidationParameters"/>.</param>
        /// <remarks>If the <see cref="JwtSecurityToken.SigningKey"/> is a <see cref="X509SecurityKey"/> then the X509Certificate2 will be validated using the CertificateValidator.</remarks>
        protected virtual void ValidateIssuerSecurityKey(SecurityKey securityKey, JwtSecurityToken securityToken, TokenValidationParameters validationParameters)
        {
            Validators.ValidateIssuerSecurityKey(securityKey, securityToken, validationParameters);
        }

        /// <summary>
        /// Serializes to XML a token of the type handled by this instance.
        /// </summary>
        /// <param name="writer">The XML writer.</param>
        /// <param name="token">A token of type <see cref="TokenType"/>.</param>
        public override void WriteToken(XmlWriter writer, SecurityToken token)
        {
            throw new NotImplementedException();
        }
    }
}
