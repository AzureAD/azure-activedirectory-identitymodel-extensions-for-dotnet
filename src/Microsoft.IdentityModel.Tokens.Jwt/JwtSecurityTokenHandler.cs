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
    using System.Collections.Generic;
    using System.Diagnostics.Tracing;
    using System.Globalization;
    using System.Security.Claims;
    using System.Security.Cryptography.X509Certificates;
    using System.Text;
    using System.Text.RegularExpressions;
    using Microsoft.IdentityModel.Logging;

    /// <summary>
    /// A <see cref="SecurityTokenHandler"/> designed for creating and validating Json Web Tokens. See http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-07.
    /// </summary>
    public class JwtSecurityTokenHandler : SecurityTokenHandler, ISecurityTokenValidator
    {
        private delegate bool CertMatcher(X509Certificate2 cert);

        // the Sts pipeline expects the first identifier to be a string that 
        // Uri.TryCreate( tokenIdentifiers[0], UriKind.Absolute, out result ) will be true.
        // if that is not true, sts's using the .Net sts class will start failing.

        private static IDictionary<string, string> outboundAlgorithmMap = new Dictionary<string, string>() 
                                                                            { 
                                                                                { SecurityAlgorithms.RsaSha256Signature, JwtAlgorithms.RSA_SHA256 }, 
                                                                                { SecurityAlgorithms.HmacSha256Signature, JwtAlgorithms.HMAC_SHA256 },
                                                                            };

        private static IDictionary<string, string> inboundAlgorithmMap = new Dictionary<string, string>() 
                                                                            { 
                                                                                { JwtAlgorithms.RSA_SHA256, SecurityAlgorithms.RsaSha256Signature }, 
                                                                                { JwtAlgorithms.HMAC_SHA256, SecurityAlgorithms.HmacSha256Signature },
                                                                            };

        // Summary:
        //     The claim properties namespace.
        private const string Namespace = "http://schemas.xmlsoap.org/ws/2005/05/identity/claimproperties";
        private static IDictionary<string, string> inboundClaimTypeMap = ClaimTypeMapping.InboundClaimTypeMap;
        private static IDictionary<string, string> outboundClaimTypeMap = ClaimTypeMapping.OutboundClaimTypeMap;
        private static string shortClaimTypeProperty = Namespace + "/ShortTypeName";
        private static string jsonClaimTypeProperty = Namespace + "/json_type";
        private static ISet<string> inboundClaimFilter = ClaimTypeMapping.InboundClaimFilter;
        private static string[] tokenTypeIdentifiers = { JwtConstants.TokenTypeAlt, JwtConstants.TokenType };
        private SignatureProviderFactory signatureProviderFactory = new SignatureProviderFactory();
        private Int32 _maximumTokenSizeInBytes = TokenValidationParameters.DefaultMaximumTokenSizeInBytes;
        private Int32 _defaultTokenLifetimeInMinutes = DefaultTokenLifetimeInMinutes;


        /// <summary>
        /// Default lifetime of tokens created. When creating tokens, if 'expires' and 'notbefore' are both null, then a default will be set to: expires = DateTime.UtcNow, notbefore = DateTime.UtcNow + TimeSpan.FromMinutes(TokenLifetimeInMinutes).
        /// </summary>
        public static readonly Int32 DefaultTokenLifetimeInMinutes = 60;

        static JwtSecurityTokenHandler()
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="JwtSecurityTokenHandler"/> class.
        /// </summary>
        public JwtSecurityTokenHandler()
        {
        }

        /// <summary>Gets or sets the <see cref="IDictionary{TKey, TValue}"/> used to map Inbound Cryptographic Algorithms.</summary>
        /// <remarks>Strings that describe Cryptographic Algorithms that are understood by the runtime are not necessarily the same values used in the JsonWebToken specification.
        /// <para>When a <see cref="JwtSecurityToken"/> signature is validated, the algorithm is obtained from the HeaderParameter { alg, 'value' }.
        /// The 'value' is translated according to this mapping and the translated 'value' is used when performing cryptographic operations.</para>
        /// <para>Default mapping is:</para>
        /// <para>&#160;&#160;&#160;&#160;RS256 => http://www.w3.org/2001/04/xmldsig-more#rsa-sha256 </para>
        /// <para>&#160;&#160;&#160;&#160;HS256 => http://www.w3.org/2001/04/xmldsig-more#hmac-sha256 </para>
        /// </remarks>
        /// <exception cref="ArgumentNullException">'value' is null.</exception>
        public static IDictionary<string, string> InboundAlgorithmMap
        {
            get
            {
                return inboundAlgorithmMap;
            }

            set
            {
                if (value == null)
                {
                    LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10001, "InboundAlgorithmMap"), typeof(ArgumentNullException), EventLevel.Verbose);
                }

                inboundAlgorithmMap = value;
            }
        }

        /// <summary>Gets or sets the <see cref="IDictionary{TKey, TValue}"/> used to map Outbound Cryptographic Algorithms.</summary>
        /// <remarks>Strings that describe Cryptographic Algorithms understood by the runtime are not necessarily the same in the JsonWebToken specification.
        /// <para>This property contains mappings the will be used to when creating a <see cref="JwtHeader"/> and setting the HeaderParameter { alg, 'value' }. 
        /// The 'value' set is translated according to this mapping.
        /// </para>
        /// <para>Default mapping is:</para>
        /// <para>&#160;&#160;&#160;&#160;http://www.w3.org/2001/04/xmldsig-more#rsa-sha256  => RS256</para>
        /// <para>&#160;&#160;&#160;&#160;http://www.w3.org/2001/04/xmldsig-more#hmac-sha256 => HS256</para>
        /// </remarks>
        /// <exception cref="ArgumentNullException">'value' is null.</exception>
        public static IDictionary<string, string> OutboundAlgorithmMap
        {
            get
            {
                return outboundAlgorithmMap;
            }

            set
            {
                if (value == null)
                {
                    LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10001, "OutboundAlgorithmMap"), typeof(ArgumentNullException), EventLevel.Verbose);
                }

                outboundAlgorithmMap = value;
            }
        }

        /// <summary>
        /// Gets or sets the <see cref="InboundClaimTypeMap"/> that is used when setting the <see cref="Claim.Type"/> for claims in the <see cref="ClaimsPrincipal"/> extracted when validating a <see cref="JwtSecurityToken"/>. 
        /// <para>The <see cref="Claim.Type"/> is set to the JSON claim 'name' after translating using this mapping.</para>
        /// </summary>
        /// <exception cref="ArgumentNullException">'value is null.</exception>
        public static IDictionary<string, string> InboundClaimTypeMap
        {
            get
            {
                return inboundClaimTypeMap;
            }

            set
            {
                if (value == null)
                {
                    LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10001, "InboundClaimTypeMap"), typeof(ArgumentNullException), EventLevel.Verbose);
                }

                inboundClaimTypeMap = value;
            }
        }

        /// <summary>
        /// <para>Gets or sets the <see cref="OutboundClaimTypeMap"/> that is used when creating a <see cref="JwtSecurityToken"/> from <see cref="Claim"/>(s).</para>
        /// <para>The JSON claim 'name' value is set to <see cref="Claim.Type"/> after translating using this mapping.</para>
        /// </summary>
        /// <remarks>This mapping is applied only when using <see cref="JwtPayload.AddClaim"/> or <see cref="JwtPayload.AddClaims"/>. Adding values directly will not result in translation.</remarks>
        /// <exception cref="ArgumentNullException">'value is null.</exception>
        public static IDictionary<string, string> OutboundClaimTypeMap
        {
            get
            {
                return outboundClaimTypeMap;
            }

            set
            {
                if (value == null)
                {
                    LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10001, "OutboundClaimTypeMap"), typeof(ArgumentNullException), EventLevel.Verbose);
                }

                outboundClaimTypeMap = value;
            }
        }

        /// <summary>Gets or sets the <see cref="ISet{String}"/> used to filter claims when populating a <see cref="ClaimsIdentity"/> claims form a <see cref="JwtSecurityToken"/>.
        /// When a <see cref="JwtSecurityToken"/> is validated, claims with types found in this <see cref="ISet{String}"/> will not be added to the <see cref="ClaimsIdentity"/>.</summary>
        /// <exception cref="ArgumentNullException">'value' is null.</exception>
        public static ISet<string> InboundClaimFilter
        {
            get
            {
                return inboundClaimFilter;
            }

            set
            {
                if (value == null)
                {
                    LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10001, "InboundClaimFilter"), typeof(ArgumentNullException), EventLevel.Verbose);
                }

                inboundClaimFilter = value;
            }
        }

        /// <summary>
        /// Gets or sets the property name of <see cref="Claim.Properties"/> the will contain the original JSON claim 'name' if a mapping occurred when the <see cref="Claim"/>(s) were created.
        /// <para>See <seealso cref="InboundClaimTypeMap"/> for more information.</para>
        /// </summary>
        /// <exception cref="ArgumentException">if <see cref="string"/>.IsIsNullOrWhiteSpace('value') is true.</exception>
        public static string ShortClaimTypeProperty
        {
            get
            {
                return shortClaimTypeProperty;
            }

            set
            {
                if (string.IsNullOrWhiteSpace(value))
                {
                    LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10001, "ShortClaimTypeProperty"), typeof(ArgumentNullException), EventLevel.Verbose);
                }

                shortClaimTypeProperty = value;
            }
        }

        /// <summary>
        /// Gets or sets the property name of <see cref="Claim.Properties"/> the will contain .Net type that was recogninzed when JwtPayload.Claims serialized the value to JSON.
        /// <para>See <seealso cref="InboundClaimTypeMap"/> for more information.</para>
        /// </summary>
        /// <exception cref="ArgumentException">if <see cref="string"/>.IsIsNullOrWhiteSpace('value') is true.</exception>
        public static string JsonClaimTypeProperty
        {
            get
            {
                return jsonClaimTypeProperty;
            }

            set
            {
                if (string.IsNullOrWhiteSpace(value))
                {
                    LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10001, "JsonClaimTypeProperty"), typeof(ArgumentNullException), EventLevel.Verbose);
                }

                jsonClaimTypeProperty = value;
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
        /// Gets and sets the token lifetime in minutes.
        /// </summary>
        /// <exception cref="ArgumentOutOfRangeException">'value' less than 1.</exception>
        public Int32 TokenLifetimeInMinutes
        {
            get
            {
                return _defaultTokenLifetimeInMinutes;
            }

            set
            {
                if (value < 1)
                {
                    LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10104, value.ToString(CultureInfo.InvariantCulture)), typeof(ArgumentOutOfRangeException), EventLevel.Error);
                }

                _defaultTokenLifetimeInMinutes = value;
            }
        }

        public override Type TokenType
        {
            get { return typeof(JwtSecurityToken); }
        }

        /// <summary>
        /// Gets and sets the maximum size in bytes, that a will be processed.
        /// </summary>
        /// <exception cref="ArgumentOutOfRangeException">'value' less than 1.</exception>
        public Int32 MaximumTokenSizeInBytes
        {
            get
            {
                return _maximumTokenSizeInBytes;
            }

            set
            {
                if (value < 1)
                {
                    LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10101, value.ToString(CultureInfo.InvariantCulture)), typeof(ArgumentOutOfRangeException), EventLevel.Verbose);
                }

                _maximumTokenSizeInBytes = value;
            }
        }

        /// <summary>
        /// Gets or sets the <see cref="SignatureProviderFactory"/> for creating <see cref="SignatureProvider"/>(s).
        /// </summary>
        /// <remarks>This extensibility point can be used to insert custom <see cref="SignatureProvider"/>(s).
        /// <para><see cref="System.IdentityModel.Tokens.SignatureProviderFactory.CreateForVerifying(SecurityKey, string)"/> is called to obtain a <see cref="SignatureProvider"/>(s) when needed.</para></remarks>
        /// <exception cref="ArgumentNullException">'value' is null.</exception>
        public SignatureProviderFactory SignatureProviderFactory
        {
            get
            {
                return this.signatureProviderFactory;
            }

            set
            {
                if (value == null)
                {
                    LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10001, "SignatureProviderFactory"), typeof(ArgumentNullException), EventLevel.Verbose);
                }

                this.signatureProviderFactory = value;
            }
        }

        /// <summary>
        /// Determines if the string is a well formed Json Web token (see http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-07)
        /// </summary>
        /// <param name="tokenString">string that should represent a valid JSON Web Token.</param>
        /// <remarks>Uses <see cref="Regex.IsMatch(string, string)"/>( token, @"^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*$" ).
        /// </remarks>
        /// <returns>
        /// <para>'true' if the token is in JSON compact serialization format.</para>
        /// <para>'false' if token.Length * 2 >  <see cref="MaximumTokenSizeInBytes"/>.</para>
        /// </returns>
        /// <exception cref="ArgumentNullException">'tokenString' is null.</exception>
        public override bool CanReadToken(string tokenString)
        {
            if (tokenString == null)
            {
               LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10000, "tokenstring"), typeof(ArgumentNullException), EventLevel.Verbose);
            }

            if (tokenString.Length * 2 > this.MaximumTokenSizeInBytes)
            {
                IdentityModelEventSource.Logger.WriteInformation(string.Format(CultureInfo.InvariantCulture, "Token string length greater than maximum length allowed. Token string length: {0}", tokenString.Length));
                return false;
            }

            if (!Regex.IsMatch(tokenString, JwtConstants.JsonCompactSerializationRegex))
            {
                IdentityModelEventSource.Logger.WriteInformation("Token string does not match the token format: header.payload.signature");
                return false;
            }

            return true;
        }

        /// <summary>
        /// Uses the <see cref="JwtSecurityToken(JwtHeader, JwtPayload, string, string, string)"/> constructor, first creating the <see cref="JwtHeader"/> and <see cref="JwtPayload"/>.
        /// <para>If <see cref="SigningCredentials"/> is not null, <see cref="JwtSecurityToken.RawData"/> will be signed.</para>
        /// </summary>
        /// <param name="issuer">the issuer of the token.</param>
        /// <param name="audience">the audience for this token.</param>
        /// <param name="subject">the source of the <see cref="Claim"/>(s) for this token.</param>
        /// <param name="notBefore">the notbefore time for this token.</param> 
        /// <param name="expires">the expiration time for this token.</param>
        /// <param name="signingCredentials">contains cryptographic material for generating a signature.</param>
        /// <param name="signatureProvider">optional <see cref="SignatureProvider"/>.</param>
        /// <remarks>If <see cref="ClaimsIdentity.Actor"/> is not null, then a claim { actort, 'value' } will be added to the payload. <see cref="CreateActorValue"/> for details on how the value is created.
        /// <para>See <seealso cref="JwtHeader"/> for details on how the HeaderParameters are added to the header.</para>
        /// <para>See <seealso cref="JwtPayload"/> for details on how the values are added to the payload.</para></remarks>
        /// <para>If signautureProvider is not null, then it will be used to create the signature and <see cref="System.IdentityModel.Tokens.SignatureProviderFactory.CreateForSigning( SecurityKey, string )"/> will not be called.</para>
        /// <returns>A <see cref="JwtSecurityToken"/>.</returns>
        /// <exception cref="ArgumentException">if 'expires' &lt;= 'notBefore'.</exception>
        public virtual JwtSecurityToken CreateToken(string issuer = null, string audience = null, ClaimsIdentity subject = null, DateTime? notBefore = null, DateTime? expires = null, SigningCredentials signingCredentials = null, SignatureProvider signatureProvider = null)
        {
            if (expires.HasValue && notBefore.HasValue)
            {
                if (notBefore >= expires)
                {
                    LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10401, expires.Value, notBefore.Value), typeof(ArgumentException), EventLevel.Error);
                }
            }

            // if not set, use defaults
            if (!expires.HasValue && !notBefore.HasValue)
            {
                DateTime now = DateTime.UtcNow;
                expires = now + TimeSpan.FromMinutes(TokenLifetimeInMinutes);
                notBefore = now;
            }

            IdentityModelEventSource.Logger.WriteVerbose("Creating payload and header from the passed parameters including issuer, audience, signing credentials and others.");
            JwtPayload payload = new JwtPayload(issuer, audience, subject == null ? null : subject.Claims, notBefore, expires);
            JwtHeader header = new JwtHeader(signingCredentials);

            if (subject != null && subject.Actor != null)
            {
                payload.AddClaim(new Claim(JwtRegisteredClaimNames.Actort, this.CreateActorValue(subject.Actor)));
            }

            string rawHeader = header.Base64UrlEncode();
            string rawPayload = payload.Base64UrlEncode();
            string rawSignature = string.Empty;
            string signingInput = string.Concat(rawHeader, ".", rawPayload);


            if (signatureProvider != null)
            {
                IdentityModelEventSource.Logger.WriteVerbose("Creating signature using the signature provider.");
                rawSignature = Base64UrlEncoder.Encode(this.CreateSignature(signingInput, null, null, signatureProvider));
            }
            else if (signingCredentials != null)
            {
                IdentityModelEventSource.Logger.WriteVerbose("Creating raw signature using signing credentials.");
                rawSignature = Base64UrlEncoder.Encode(this.CreateSignature(signingInput, signingCredentials.SigningKey, signingCredentials.SignatureAlgorithm, signatureProvider));
            }

            IdentityModelEventSource.Logger.WriteInformation("Creating security token from the header, payload and raw signature.");
            return new JwtSecurityToken(header, payload, rawHeader, rawPayload, rawSignature);
        }

        /// <summary>
        /// Reads a token encoded in JSON Compact serialized format.
        /// </summary>
        /// <param name="tokenString">A 'JSON Web Token' (JWT) that has been encoded as a JSON object. May be signed 
        /// using 'JSON Web Signature' (JWS).</param>
        /// <remarks>
        /// The JWT must be encoded using Base64Url encoding of the UTF-8 representation of the JWT: Header, Payload and Signature. 
        /// The contents of the JWT returned are not validated in any way, the token is simply decoded. Use ValidateToken to validate the JWT.
        /// </remarks>
        /// <returns>A <see cref="JwtSecurityToken"/></returns>
        public override SecurityToken ReadToken(string tokenString)
        {
            //IdentityModelEventSource.Logger.WriteInformation(string.Format(CultureInfo.InvariantCulture, "Calling into {0}", MethodBase.GetCurrentMethod()));

            if (tokenString == null)
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10000, GetType() + ": token"), typeof(ArgumentNullException), EventLevel.Verbose);
            }

            if (tokenString.Length * 2 > this.MaximumTokenSizeInBytes)
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10209, tokenString.Length, this.MaximumTokenSizeInBytes), typeof(ArgumentException), EventLevel.Error);
            }

            if (!this.CanReadToken(tokenString))
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10708, GetType(), tokenString), typeof(ArgumentException), EventLevel.Error);
            }

            return new JwtSecurityToken(tokenString);
        }

        /// <summary>
        /// Reads and validates a token encoded in JSON Compact serialized format.
        /// </summary>
        /// <param name="securityToken">A 'JSON Web Token' (JWT) that has been encoded as a JSON object. May be signed using 'JSON Web Signature' (JWS).</param>
        /// <param name="validationParameters">Contains validation parameters for the <see cref="JwtSecurityToken"/>.</param>
        /// <param name="validatedToken">The <see cref="JwtSecurityToken"/> that was validated.</param>
        /// <exception cref="ArgumentNullException">'securityToken' is null or whitespace.</exception>
        /// <exception cref="ArgumentNullException">'validationParameters' is null.</exception>
        /// <exception cref="ArgumentException">'securityToken.Length' > <see cref="MaximumTokenSizeInBytes"/>.</exception>
        /// <returns>A <see cref="ClaimsPrincipal"/> from the jwt. Does not include the header claims.</returns>
        public virtual ClaimsPrincipal ValidateToken(string securityToken, TokenValidationParameters validationParameters, out SecurityToken validatedToken)
        {
            //IdentityModelEventSource.Logger.WriteInformation(string.Format(CultureInfo.InvariantCulture, "Calling into {0}", System.Reflection.MethodBase.GetCurrentMethod()));

            if (string.IsNullOrWhiteSpace(securityToken))
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10000, GetType() + ": securityToken"), typeof(ArgumentNullException), EventLevel.Verbose);
            }

            if (validationParameters == null)
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10000, GetType() + ": validationParameters"), typeof(ArgumentNullException), EventLevel.Verbose);
            }

            if (securityToken.Length > MaximumTokenSizeInBytes)
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10209, securityToken.Length, MaximumTokenSizeInBytes), typeof(ArgumentException), EventLevel.Error);
            }

            JwtSecurityToken jwt = this.ValidateSignature(securityToken, validationParameters);

            if (jwt.SigningKey != null)
            {
                this.ValidateIssuerSecurityKey(jwt.SigningKey, jwt, validationParameters);
            }

            DateTime? notBefore = null;
            if (jwt.Payload.Nbf != null)
            {
                notBefore = new DateTime?(jwt.ValidFrom);
            }

            DateTime? expires = null;
            if (jwt.Payload.Exp != null)
            {
                expires = new DateTime?(jwt.ValidTo);
            }

            Validators.ValidateTokenReplay(securityToken, expires, validationParameters);
            if (validationParameters.ValidateLifetime)
            {
                if (validationParameters.LifetimeValidator != null)
                {
                    if (!validationParameters.LifetimeValidator(notBefore: notBefore, expires: expires, securityToken: jwt, validationParameters: validationParameters))
                    {
                        LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10230, jwt.ToString()), typeof(SecurityTokenInvalidLifetimeException), EventLevel.Error);
                    }
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
                    {
                        LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10231, jwt.ToString()), typeof(SecurityTokenInvalidAudienceException), EventLevel.Error);
                    }
                }
                else
                {
                    this.ValidateAudience(jwt.Audiences, jwt, validationParameters);
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

            if (validationParameters.ValidateActor && !string.IsNullOrWhiteSpace(jwt.Actor))
            {
                SecurityToken actor = null;
                ValidateToken(jwt.Actor, validationParameters, out actor);
            }

            ClaimsIdentity identity = this.CreateClaimsIdentity(jwt, issuer, validationParameters);
            if (validationParameters.SaveSigninToken)
            {
                identity.BootstrapContext = securityToken;
            }

            IdentityModelEventSource.Logger.WriteInformation("Security token validated.");
            validatedToken = jwt;
            return new ClaimsPrincipal(identity);
        }

        /// <summary>
        /// Writes the <see cref="JwtSecurityToken"/> as a JSON Compact serialized format string.
        /// </summary>
        /// <param name="token"><see cref="JwtSecurityToken"/> to serialize.</param>
        /// <remarks>
        /// <para>If the <see cref="JwtSecurityToken.SigningCredentials"/> are not null, the encoding will contain a signature.</para>
        /// </remarks>
        /// <exception cref="ArgumentNullException">'token' is null.</exception>
        /// <exception cref="ArgumentException">'token' is not a not <see cref="JwtSecurityToken"/>.</exception>
        /// <returns>The <see cref="JwtSecurityToken"/> as a signed (if <see cref="SigningCredentials"/> exist) encoded string.</returns>
        public override string WriteToken(SecurityToken token)
        {
            //IdentityModelEventSource.Logger.WriteInformation(string.Format(CultureInfo.InvariantCulture, "Calling into {0}", MethodBase.GetCurrentMethod()));

            if (token == null)
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10000, GetType() + ": token"),typeof(ArgumentNullException), EventLevel.Verbose);
            }

            JwtSecurityToken jwt = token as JwtSecurityToken;
            if (jwt == null)
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10706, GetType(), typeof(JwtSecurityToken), token.GetType()), typeof(ArgumentNullException), EventLevel.Error);
            }

            string signature = string.Empty;
            string signingInput = string.Concat(jwt.EncodedHeader, ".", jwt.EncodedPayload);

            if (jwt.SigningCredentials != null)
            {
                signature = Base64UrlEncoder.Encode(this.CreateSignature(signingInput, jwt.SigningCredentials.SigningKey, jwt.SigningCredentials.SignatureAlgorithm));
            }

            IdentityModelEventSource.Logger.WriteInformation("Adding the signature to the token.");
            return string.Concat(signingInput, ".", signature);
        }

        /// <summary>
        /// Produces a signature over the 'input' using the <see cref="SecurityKey"/> and algorithm specified.
        /// </summary>
        /// <param name="inputString">string to be signed</param>
        /// <param name="key">the <see cref="SecurityKey"/> to use.</param>
        /// <param name="algorithm">the algorithm to use.</param>
        /// <param name="signatureProvider">if provided, the <see cref="SignatureProvider"/> will be used to sign the token</param>
        /// <returns>The signature over the bytes obtained from UTF8Encoding.GetBytes( 'input' ).</returns>
        /// <remarks>The <see cref="SignatureProvider"/> used to created the signature is obtained by calling <see cref="System.IdentityModel.Tokens.SignatureProviderFactory.CreateForSigning(SecurityKey, string)"/>.</remarks>
        /// <exception cref="ArgumentNullException">'input' is null.</exception>
        /// <exception cref="InvalidProgramException"><see cref="System.IdentityModel.Tokens.SignatureProviderFactory.CreateForSigning(SecurityKey, string)"/> returns null.</exception>
        internal byte[] CreateSignature(string inputString, SecurityKey key, string algorithm, SignatureProvider signatureProvider = null)
        {
            //IdentityModelEventSource.Logger.WriteInformation(string.Format(CultureInfo.InvariantCulture, "Calling into {0}", MethodBase.GetCurrentMethod()));

            if (null == inputString)
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10000, GetType() + ": inputString"), typeof(ArgumentNullException), EventLevel.Verbose);
            }

            SignatureProvider provider;
            if (signatureProvider != null)
            {
                return signatureProvider.Sign(Encoding.UTF8.GetBytes(inputString));
            }
            else
            {
                provider = SignatureProviderFactory.CreateForSigning(key, algorithm);
                if (provider == null)
                {
                    LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10635, SignatureProviderFactory.GetType(), typeof(SignatureProvider), key == null ? "<null>" : key.GetType().ToString(), algorithm == null ? "<null>" : algorithm), typeof(InvalidProgramException), EventLevel.Error);
                }

                byte[] bytes = provider.Sign(Encoding.UTF8.GetBytes(inputString));
                SignatureProviderFactory.ReleaseProvider(provider);
                return bytes;
            }
        }

        private bool ValidateSignature(byte[] encodedBytes, byte[] signature, SecurityKey key, string algorithm)
        {
            //IdentityModelEventSource.Logger.WriteInformation(string.Format(CultureInfo.InvariantCulture, "Calling into {0}", MethodBase.GetCurrentMethod()));

            // in the case that a SignatureProviderFactory can handle nulls, just don't check here.
            //SignatureProvider signatureProvider = SignatureProviderFactory.CreateForVerifying(key, algorithm);

#if SignatureProvider
            SignatureProvider signatureProvider = SignatureProviderFactory.CreateForVerifying(key, algorithm);
#else
            SignatureProvider signatureProvider = key.GetSignatureProvider(algorithm, true);
#endif
            if (signatureProvider == null)
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10636, key == null ? "Null" : key.ToString(), algorithm == null ? "Null" : algorithm), typeof(InvalidOperationException), EventLevel.Error);
            }

            return signatureProvider.Verify(encodedBytes, signature);
        }

        /// <summary>
        /// Validates that the signature, if found and / or required is valid.
        /// </summary>
        /// <param name="token">A 'JSON Web Token' (JWT) that has been encoded as a JSON object. May be signed 
        /// using 'JSON Web Signature' (JWS).</param>
        /// <param name="validationParameters"><see cref="TokenValidationParameters"/> that contains signing keys.</param>
        /// <exception cref="ArgumentNullException"> thrown if 'token is null or whitespace.</exception>
        /// <exception cref="ArgumentNullException"> thrown if 'validationParameters is null.</exception>
        /// <exception cref="SecurityTokenValidationException"> thrown if a signature is not found and <see cref="TokenValidationParameters.RequireSignedTokens"/> is true.</exception>
        /// <exception cref="SecurityTokenSignatureKeyNotFoundException"> thrown if the 'token' has a key identifier and none of the <see cref="SecurityKey"/>(s) provided result in a validated signature. 
        /// This can indicate that a key refresh is required.</exception>
        /// <exception cref="SignatureVerificationFailedException"> thrown if after trying all the <see cref="SecurityKey"/>(s), none result in a validated signture AND the 'token' does not have a key identifier.</exception>
        /// <returns><see cref="JwtSecurityToken"/> that has the signature validated if token was signed and <see cref="TokenValidationParameters.RequireSignedTokens"/> is true.</returns>
        /// <remarks><para>If the 'token' is signed, the signature is validated even if <see cref="TokenValidationParameters.RequireSignedTokens"/> is false.</para>
        /// <para>If the 'token' signature is validated, then the <see cref="JwtSecurityToken.SigningKey"/> will be set to the key that signed the 'token'.</para></remarks>
        protected virtual JwtSecurityToken ValidateSignature(string token, TokenValidationParameters validationParameters)
        {
            //IdentityModelEventSource.Logger.WriteInformation(string.Format(CultureInfo.InvariantCulture, "Calling into {0}", MethodBase.GetCurrentMethod()));

            if (string.IsNullOrWhiteSpace(token))
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10000, GetType() + ": token"), typeof(ArgumentNullException), EventLevel.Verbose);
            }

            if (validationParameters == null)
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10000, GetType() + ": validationParameters"), typeof(ArgumentNullException), EventLevel.Verbose);
            }

            JwtSecurityToken jwt = this.ReadToken(token) as JwtSecurityToken;
            byte[] encodedBytes = Encoding.UTF8.GetBytes(jwt.RawHeader + "." + jwt.RawPayload);
            byte[] signatureBytes = Base64UrlEncoder.DecodeBytes(jwt.RawSignature);

            if (signatureBytes == null)
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10000, GetType() + ": signatureBytes"), typeof(ArgumentNullException), EventLevel.Verbose);
            }

            if (signatureBytes.Length == 0)
            {
                if (!validationParameters.RequireSignedTokens)
                {
                    return jwt;
                }
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10504, jwt.ToString()), typeof(SecurityTokenInvalidSignatureException), EventLevel.Error);
            }

            string mappedAlgorithm = jwt.Header.Alg;
            if (mappedAlgorithm != null && InboundAlgorithmMap.ContainsKey(mappedAlgorithm))
            {
                mappedAlgorithm = InboundAlgorithmMap[mappedAlgorithm];
            }

            // if the kid != null and the signature fails, throw SecurityTokenSignatureKeyNotFoundException
            string kid = jwt.Header.Kid;
            SecurityKey securityKey = null;

            if (validationParameters.IssuerSigningKeyResolver != null)
            {
                securityKey = validationParameters.IssuerSigningKeyResolver(token, jwt, kid, validationParameters);
            }
            else
            {
                securityKey = ResolveIssuerSigningKey(token, jwt, kid, validationParameters);
            }

            // if the security key is resolved, try just the one key
            if (securityKey != null)
            { 
                try
                {
                    if (this.ValidateSignature(encodedBytes, signatureBytes, securityKey, mappedAlgorithm))
                    {
                        IdentityModelEventSource.Logger.WriteInformation("Security token has a valid signature.");
                        jwt.SigningKey = securityKey;
                        return jwt;
                    }
                }
                catch (Exception ex)
                {
                    LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10502, CreateKeyString(securityKey), ex.ToString(), jwt.ToString()),typeof(SecurityTokenInvalidSignatureException), EventLevel.Error);
                }

                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10501, CreateKeyString(securityKey), jwt.ToString()), typeof(SecurityTokenInvalidSignatureException), EventLevel.Error);
            }
            else
            {
                Exception firstException = null;
                StringBuilder exceptionStrings = new StringBuilder();
                StringBuilder keysAttempted = new StringBuilder();

                // Try all keys since there is no keyidentifier
                foreach (SecurityKey sk in GetAllKeys(token, jwt, kid, validationParameters))
                {
                    try
                    {
                        if (this.ValidateSignature(encodedBytes, signatureBytes, sk, mappedAlgorithm))
                        {
                            IdentityModelEventSource.Logger.WriteInformation("Security token has a valid signature.");
                            jwt.SigningKey = securityKey;
                            return jwt;
                        }
                    }
                    catch (Exception ex)
                    {
                        if (DiagnosticUtility.IsFatal(ex))
                        {
                            throw;
                        }

                        if (firstException == null)
                        {
                            firstException = ex;
                        }

                        exceptionStrings.AppendLine(ex.ToString());
                    }

                    keysAttempted.AppendLine(CreateKeyString(sk));
                }

                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10503, keysAttempted.ToString(), exceptionStrings.ToString(), jwt.ToString()), typeof(SecurityTokenInvalidSignatureException), EventLevel.Error);
            }
            return null;
        }

        private IEnumerable<SecurityKey> GetAllKeys(string token, SecurityToken securityToken, string kid, TokenValidationParameters validationParameters)
        {
            IdentityModelEventSource.Logger.WriteInformation("Getting issuer signing keys from validaiton parameters.");
            if (validationParameters.IssuerSigningKey != null)
                yield return validationParameters.IssuerSigningKey;

            if (validationParameters.IssuerSigningKeys != null)
                foreach (SecurityKey securityKey in validationParameters.IssuerSigningKeys)
                    yield return securityKey;
        }

        /// <summary>
        /// Produces a readable string for a key, used in error messages.
        /// </summary>
        /// <param name="securityKey"></param>
        /// <returns></returns>
        private static string CreateKeyString(SecurityKey securityKey)
        {
            if (securityKey == null)
            {
                IdentityModelEventSource.Logger.WriteWarning("security key is null");
                return "null";
            }
            else
            {
				X509SecurityKey x509Key = securityKey as X509SecurityKey;
				if (x509Key != null)
				{
					return x509Key.ToString() + " - (thumbprint) : " + x509Key.Certificate.Thumbprint;
				}
                return securityKey.ToString();
            }
        }

        /// <summary>
        /// Creates a <see cref="ClaimsIdentity"/> from a <see cref="JwtSecurityToken"/>.
        /// </summary>
        /// <param name="jwt">The <see cref="JwtSecurityToken"/> to use as a <see cref="Claim"/> source.</param>
        /// <param name="issuer">The value to set <see cref="Claim.Issuer"/></param>
        /// <param name="validationParameters"> contains parameters for validating the token.</param>
        /// <returns>A <see cref="ClaimsIdentity"/> containing the <see cref="JwtSecurityToken.Claims"/>.</returns>
        protected virtual ClaimsIdentity CreateClaimsIdentity(JwtSecurityToken jwt, string issuer, TokenValidationParameters validationParameters)
        {
            //IdentityModelEventSource.Logger.WriteInformation(string.Format(CultureInfo.InvariantCulture, "Calling into {0}", MethodBase.GetCurrentMethod()));
            if (jwt == null)
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10000, GetType() + ": jwt"), typeof(ArgumentNullException), EventLevel.Verbose);
            }

            if (string.IsNullOrWhiteSpace(issuer))
            {
                LogHelper.Throw(ErrorMessages.IDX10221, typeof(ArgumentNullException), EventLevel.Error);
            }

            IdentityModelEventSource.Logger.WriteInformation("Creating claims identity from the validated token.");
            ClaimsIdentity identity = validationParameters.CreateClaimsIdentity(jwt, issuer);
            foreach (Claim jwtClaim in jwt.Claims)
            {
                if (InboundClaimFilter.Contains(jwtClaim.Type))
                {
                    continue;
                }

                string claimType;
                bool wasMapped = true;
                if (!JwtSecurityTokenHandler.InboundClaimTypeMap.TryGetValue(jwtClaim.Type, out claimType))
                {
                    claimType = jwtClaim.Type;
                    wasMapped = false;
                }

                if (claimType == ClaimTypes.Actor)
                {
                    if (identity.Actor != null)
                    {
                        LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10710, JwtRegisteredClaimNames.Actort, jwtClaim.Value), typeof(InvalidOperationException), EventLevel.Error);
                    }

                    if (this.CanReadToken(jwtClaim.Value))
                    {
                        JwtSecurityToken actor = this.ReadToken(jwtClaim.Value) as JwtSecurityToken;
                        identity.Actor = this.CreateClaimsIdentity(actor, issuer, validationParameters);
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
        /// <para>&#160;&#160;if 'type' is 'string', return as string.</para>
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
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10000, GetType() + ": actor"), typeof(ArgumentNullException), EventLevel.Verbose);
            }

            if (actor.BootstrapContext == null)
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10000, GetType() + ": actor.BootstrapContex"), typeof(SecurityTokenException), EventLevel.Verbose);

            }

            string encodedJwt = actor.BootstrapContext as string;
            if (encodedJwt != null)
            {
                return encodedJwt;
            }

            JwtSecurityToken jwt = actor.BootstrapContext as JwtSecurityToken;
            if (jwt != null)
            {
                if (jwt.RawData != null)
                {
                    return jwt.RawData;
                }
                else
                {
                    return this.WriteToken(jwt);
                }
            }

            LogHelper.Throw(ErrorMessages.IDX10711, typeof(SecurityTokenException), EventLevel.Error);
            return null;
        }

        /// <summary>
        /// Determines if the audiences found in a <see cref="JwtSecurityToken"/> are valid.
        /// </summary>
        /// <param name="audiences">The audiences found in the <see cref="JwtSecurityToken"/>.</param>
        /// <param name="securityToken">The <see cref="JwtSecurityToken"/> being validated.</param>
        /// <param name="validationParameters"><see cref="TokenValidationParameters"/> required for validation.</param>
        /// <remarks>see <see cref="Validators.ValidateAudience"/> for additional details.</remarks>
        protected virtual void ValidateAudience(IEnumerable<string> audiences, SecurityToken securityToken, TokenValidationParameters validationParameters)
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
        protected virtual void ValidateLifetime(DateTime? notBefore, DateTime? expires, SecurityToken securityToken, TokenValidationParameters validationParameters)
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
        protected virtual string ValidateIssuer(string issuer, SecurityToken securityToken, TokenValidationParameters validationParameters)
        {
            return Validators.ValidateIssuer(issuer, securityToken, validationParameters);
        }

        /// <summary>
        /// Returns a <see cref="SecurityKey"/> to use when validating the signature of a token.
        /// </summary>
        /// <param name="token">the <see cref="string"/> representation of the token that is being validated.</param>
        /// <param name="securityToken">the <SecurityToken> that is being validated.</SecurityToken></param>
        /// <param name="kid">the key identifier found in the token.</param>
        /// <param name="validationParameters">A <see cref="TokenValidationParameters"/>  required for validation.</param>
        /// <returns>Returns a <see cref="SecurityKey"/> to use for signature validation.</returns>
        /// <remarks>If key fails to resolve, then null is returned</remarks>
        protected virtual SecurityKey ResolveIssuerSigningKey(string token, SecurityToken securityToken, string kid, TokenValidationParameters validationParameters)
        {
            return null;
        }

        /// <summary>
        /// Validates the <see cref="JwtSecurityToken.SigningKey"/> is an expected value.
        /// </summary>
        /// <param name="securityKey">The <see cref="SecurityKey"/> that signed the <see cref="SecurityToken"/>.</param>
        /// <param name="securityToken">The <see cref="JwtSecurityToken"/> to validate.</param>
        /// <param name="validationParameters">the current <see cref="TokenValidationParameters"/>.</param>
        /// <remarks>If the <see cref="JwtSecurityToken.SigningKey"/> is a <see cref="X509SecurityKey"/> then the X509Certificate2 will be validated using <see cref="TokenValidationParameters.CertificateValidator"/>.</remarks>
        protected virtual void ValidateIssuerSecurityKey(SecurityKey securityKey, SecurityToken securityToken, TokenValidationParameters validationParameters)
        {
            Validators.ValidateIssuerSecurityKey(securityKey, securityToken, validationParameters);
        }
    }
}