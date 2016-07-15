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
using System.Globalization;
using System.IdentityModel.Tokens.Saml;
using System.IO;
using System.Security.Claims;
using System.Text;
using System.Xml;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;

namespace System.IdentityModel.Tokens.Saml2
{
    /// <summary>
    /// A derived <see cref="System.IdentityModel.Tokens.Saml2.Saml2SecurityTokenHandler"/> that implements ISecurityTokenValidator,
    /// which supports validating tokens passed as strings using <see cref="TokenValidationParameters"/>.
    /// </summary>
    ///
    public class Saml2SecurityTokenHandler : SecurityTokenHandler, ISecurityTokenValidator
    {
        internal const string Saml2TokenProfile11 = "urn:oasis:names:tc:SAML:2.0:assertion";
        internal const string OasisWssSaml2TokenProfile11 = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0";

        private int _maximumTokenSizeInBytes = TokenValidationParameters.DefaultMaximumTokenSizeInBytes;
        private static string[] _tokenTypeIdentifiers = new string[] { Saml2TokenProfile11, OasisWssSaml2TokenProfile11 };

        /// <summary>
        /// Initializes a new instance of <see cref="Saml2SecurityTokenHandler"/>.
        /// </summary>
        public Saml2SecurityTokenHandler()
        {
        }

        /// <summary>
        /// Gets the token type supported by this handler.
        /// </summary>
        public override Type TokenType
        {
            get { return typeof(Saml2SecurityToken); }
        }

        /// <summary>
        /// Gets a value indicating whether this handler supports validation of tokens
        /// handled by this instance.
        /// </summary>v
        /// <returns>'True' if the instance is capable of SecurityToken
        /// validation.</returns>
        public override bool CanValidateToken
        {
            get { return true; }
        }

        /// <summary>
        /// Gets a value indicating whether the class provides serialization functionality to serialize the token handled
        /// by this instance.
        /// </summary>
        /// <returns>true if the WriteToken method can serialize this token.</returns>
        public override bool CanWriteToken
        {
            get { return true; }
        }

        /// <summary>
        /// Reads the string as XML and looks for the an element <see cref="SamlConstants.Assertion"/> or  <see cref="SamlConstants.EncryptedAssertion"/> with namespace <see cref="SamlConstants.Saml2Namespace"/>.
        /// </summary>
        /// <param name="securityToken">The securitytoken.</param>
        /// <returns><see cref="XmlDictionaryReader.IsStartElement"/> (<see cref="SamlConstants.Assertion"/>, <see cref="SamlConstants.Saml2Namespace"/>)
        /// OR <see cref="XmlDictionaryReader.IsStartElement"/> (<see cref="SamlConstants.EncryptedAssertion"/>, <see cref="SamlConstants.Saml2Namespace"/>).</returns>
        public override bool CanReadToken(string securityToken)
        {
            if (string.IsNullOrWhiteSpace(securityToken) || securityToken.Length > MaximumTokenSizeInBytes)
            {
                return false;
            }

            using (StringReader sr = new StringReader(securityToken))
            {
                using (XmlDictionaryReader reader = XmlDictionaryReader.CreateDictionaryReader(XmlReader.Create(sr)))
                {
                    try
                    {
                        reader.MoveToContent();
                    }
                    catch (XmlException)
                    {
                        return false;
                    }

                    return reader.IsStartElement(SamlConstants.Assertion, SamlConstants.Saml2Namespace)
                        || reader.IsStartElement(SamlConstants.EncryptedAssertion, SamlConstants.Saml2Namespace);
                }
            }
        }

        /// <summary>
        /// Creates the security token reference when the token is not attached to the message.
        /// </summary>
        /// <param name="token">The saml token.</param>
        /// <param name="attached">Boolean that indicates if a attached or unattached
        /// reference needs to be created.</param>
        /// <returns>A <see cref="SecurityKeyIdentifierClause"/>.</returns>
        public override SecurityKeyIdentifierClause CreateSecurityTokenReference(SecurityToken token, bool attached)
        {
            if (null == token)
            {
                throw new ArgumentNullException("token");
            }

            throw new NotSupportedException();
        }

        /// <summary>
        /// Creates a <see cref="ClaimsIdentity"/> from the Saml2 token.
        /// </summary>
        /// <param name="samlToken">The Saml2SecurityToken.</param>
        /// <param name="issuer">The issuer value for each <see cref="Claim"/> in the <see cref="ClaimsIdentity"/>.</param>
        /// <param name="validationParameters"> Contains parameters for validating the token.</param>
        /// <returns>An IClaimIdentity.</returns>
        protected virtual ClaimsIdentity CreateClaimsIdentity(Saml2SecurityToken samlToken, string issuer, TokenValidationParameters validationParameters)
        {
            if (samlToken == null)
            {
                throw new ArgumentNullException("samlToken");
            }

            if (validationParameters == null)
            {
                throw new ArgumentNullException("validationParameters");
            }

            if (string.IsNullOrWhiteSpace(issuer))
            {
                throw new ArgumentException(LogMessages.IDX10221);
            }

            throw new NotImplementedException();
        }

        /// <summary>
        /// Creates a <see cref="SecurityToken"/> based on a information contained in the <see cref="SecurityTokenDescriptor"/>.
        /// </summary>
        /// <param name="tokenDescriptor">The <see cref="SecurityTokenDescriptor"/> that has creation information.</param>
        /// <returns>A <see cref="SecurityToken"/> instance.</returns>
        /// <exception cref="ArgumentNullException">If 'tokenDescriptor' is null.</exception>
        public override SecurityToken CreateToken(SecurityTokenDescriptor tokenDescriptor)
        {
            if (null == tokenDescriptor)
            {
                throw new ArgumentNullException("tokenDescriptor");
            }

            throw new NotImplementedException();
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
                    throw LogHelper.LogExceptionMessage(new ArgumentOutOfRangeException("value", String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10101, value.ToString(CultureInfo.InvariantCulture))));
                }

                _maximumTokenSizeInBytes = value;
            }
        }

        /// <summary>
        /// Obsolete method, use <see cref="ReadToken(XmlReader, TokenValidationParameters)"/> to read a <see cref="Saml2SecurityToken"/>.
        /// </summary>
        /// <param name="tokenString">Not supported.</param>
        /// <exception cref="NotSupportedException">Use <see cref="ReadToken(XmlReader, TokenValidationParameters)"/> to read a <see cref="Saml2SecurityToken"/>.</exception>
        public override SecurityToken ReadToken(string tokenString)
        {
            throw new NotSupportedException(LogMessages.IDX11006);
        }

        /// <summary>
        /// Obsolete method, use <see cref="ReadToken(XmlReader, TokenValidationParameters)"/> to read a <see cref="Saml2SecurityToken"/>.
        /// </summary>
        /// <param name="reader"><see cref="XmlReader"/>.</param>
        /// <exception cref="NotSupportedException">Use <see cref="ReadToken(XmlReader, TokenValidationParameters)"/> to read a <see cref="Saml2SecurityToken"/>.</exception>
        public override SecurityToken ReadToken(XmlReader reader)
        {
            throw new NotSupportedException(LogMessages.IDX11002);
        }

        /// <summary>
        /// Reads a SAML 2.0 token from the XmlReader.
        /// </summary>
        /// <param name="reader">A <see cref="XmlReader"/> reader positioned at a <see cref="Saml2SecurityToken"/> element.</param>
        /// <param name="validationParameters">Contains data and information needed for reading the token.</param>
        /// <exception cref="ArgumentNullException">If 'reader' is null.</exception>
        /// <exception cref="ArgumentNullException">If 'validationParameters' is null.</exception>
        /// <returns>An instance of a <see cref="Saml2SecurityToken"/>.</returns>
        public override SecurityToken ReadToken(XmlReader reader, TokenValidationParameters validationParameters)
        {
            if (reader == null)
                throw LogHelper.LogExceptionMessage(new ArgumentNullException("reader", String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10000, "reader"))); 

            if (validationParameters == null)
                throw LogHelper.LogExceptionMessage(new ArgumentNullException("validationParameters", String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10000, "validationParameters"))); 

            throw new NotImplementedException();
        }

        /// <summary>
        /// Reads and validates a well fromed Saml2 token.
        /// </summary>
        /// <param name="securityToken">A Saml2 token.</param>
        /// <param name="validationParameters">Contains data and information needed for validation.</param>
        /// <param name="validatedToken">The <see cref="SamlSecurityToken"/> that was validated.</param>
        /// <exception cref="ArgumentNullException">'securityToken' is null or whitespace.</exception>
        /// <exception cref="ArgumentNullException">'validationParameters' is null.</exception>
        /// <exception cref="ArgumentException">'securityToken.Length' > <see cref="MaximumTokenSizeInBytes"/>.</exception>
        /// <returns>A <see cref="ClaimsPrincipal"/> generated from the claims in the Saml2 securityToken.</returns>
        public virtual ClaimsPrincipal ValidateToken(string securityToken, TokenValidationParameters validationParameters, out SecurityToken validatedToken)
        {
            validatedToken = null;
            if (string.IsNullOrWhiteSpace(securityToken))
                throw LogHelper.LogExceptionMessage(new ArgumentNullException("securityToken", String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10000, "securityToken"))); 

            if (validationParameters == null)
                throw LogHelper.LogExceptionMessage(new ArgumentNullException("validationParameters", String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10000, "validationParameters"))); 

            if (securityToken.Length > MaximumTokenSizeInBytes)
            {
                throw LogHelper.LogExceptionMessage(new ArgumentException(String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10209, securityToken.Length, MaximumTokenSizeInBytes)));
            }

            Saml2SecurityToken samlToken;
            using (StringReader sr = new StringReader(securityToken))
            {
                using (XmlDictionaryReader reader = XmlDictionaryReader.CreateDictionaryReader(XmlReader.Create(sr)))
                {
                        samlToken = ReadToken(reader) as Saml2SecurityToken;
                }
            }

            if (samlToken.SigningKey == null && validationParameters.RequireSignedTokens)
            {
                throw new SecurityTokenValidationException(LogMessages.IDX10213);
            }

            DateTime? notBefore = null;
            DateTime? expires = null;
            if (samlToken.Conditions != null)
            {
                notBefore = samlToken.Conditions.NotBefore;
                expires = samlToken.Conditions.Expires;
            }

            Validators.ValidateTokenReplay(securityToken, expires, validationParameters);

            if (validationParameters.ValidateLifetime)
            {
                if (validationParameters.LifetimeValidator != null)
                {
                    if (!validationParameters.LifetimeValidator(notBefore: notBefore, expires: expires, securityToken: samlToken, validationParameters: validationParameters))
                    {
                        throw LogHelper.LogExceptionMessage(new SecurityTokenInvalidLifetimeException(String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10230, securityToken))
                        { NotBefore = notBefore, Expires = expires });
                    }
                }
                else
                {
                    ValidateLifetime(notBefore: notBefore, expires: expires, securityToken: samlToken, validationParameters: validationParameters);
                }
            }

            if (validationParameters.ValidateAudience)
            {
                List<string> audiences = new List<string>();
                if (samlToken.Conditions != null && samlToken.Conditions.AudienceRestrictions != null)
                {
                    foreach (Saml2AudienceRestriction restriction in samlToken.Conditions.AudienceRestrictions)
                    {
                        if (restriction == null)
                        {
                            continue;
                        }

                        foreach (Uri uri in restriction.Audiences)
                        {
                            if (uri == null)
                            {
                                continue;
                            }

                            audiences.Add(uri.OriginalString);
                        }
                    }
                }


                if (validationParameters.AudienceValidator != null)
                {
                    if (!validationParameters.AudienceValidator(audiences, samlToken, validationParameters))
                    {
                        throw LogHelper.LogExceptionMessage(new SecurityTokenInvalidAudienceException(String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10231, securityToken))
                            { InvalidAudience = String.Join(", ", audiences) });
                    }
                }
                else
                {
                    ValidateAudience(audiences, samlToken, validationParameters);
                }
            }

            string issuer = samlToken.Issuer;
            if (validationParameters.ValidateIssuer)
            {
                if (validationParameters.IssuerValidator != null)
                {
                    issuer = validationParameters.IssuerValidator(issuer, samlToken, validationParameters);
                }
                else
                {
                    issuer = ValidateIssuer(issuer, samlToken, validationParameters);
                }
            }

            if (samlToken.SigningKey != null)
            {
                ValidateIssuerSecurityKey(samlToken.SigningKey, samlToken, validationParameters);
            }

            ClaimsIdentity identity = CreateClaimsIdentity(samlToken, issuer, validationParameters);
            if (validationParameters.SaveSigninToken)
            {
                identity.BootstrapContext = securityToken;
            }

            validatedToken = samlToken;
            return new ClaimsPrincipal(identity);
        }

        /// <summary>
        /// Determines if the audiences found in a <see cref="Saml2SecurityToken"/> are valid.
        /// </summary>
        /// <param name="audiences">The audiences found in the <see cref="Saml2SecurityToken"/>.</param>
        /// <param name="securityToken">The <see cref="Saml2SecurityToken"/> being validated.</param>
        /// <param name="validationParameters"><see cref="TokenValidationParameters"/> required for validation.</param>
        /// <remarks>See <see cref="Validators.ValidateAudience"/> for additional details.</remarks>
        protected virtual void ValidateAudience(IEnumerable<string> audiences, SecurityToken securityToken, TokenValidationParameters validationParameters)
        {
            Validators.ValidateAudience(audiences, securityToken, validationParameters);
        }

        /// <summary>
        /// Validates the lifetime of a <see cref="Saml2SecurityToken"/>.
        /// </summary>
        /// <param name="notBefore">The 'notBefore' time found in the <see cref="Saml2SecurityToken"/>.</param>
        /// <param name="expires">The 'expiration' time found in the <see cref="Saml2SecurityToken"/>.</param>
        /// <param name="securityToken">The <see cref="Saml2SecurityToken"/> being validated.</param>
        /// <param name="validationParameters"><see cref="TokenValidationParameters"/> required for validation.</param>
        /// <remarks><see cref="Validators.ValidateLifetime"/> for additional details.</remarks>
        protected virtual void ValidateLifetime(DateTime? notBefore, DateTime? expires, SecurityToken securityToken, TokenValidationParameters validationParameters)
        {
            Validators.ValidateLifetime(notBefore: notBefore, expires: expires, securityToken: securityToken, validationParameters: validationParameters);
        }

        /// <summary>
        /// Determines if an issuer found in a <see cref="Saml2SecurityToken"/> is valid.
        /// </summary>
        /// <param name="issuer">The issuer to validate</param>
        /// <param name="securityToken">The <see cref="Saml2SecurityToken"/> that is being validated.</param>
        /// <param name="validationParameters"><see cref="TokenValidationParameters"/> required for validation.</param>
        /// <returns>The issuer to use when creating the <see cref="Claim"/>(s) in the <see cref="ClaimsIdentity"/>.</returns>
        /// <remarks><see cref="Validators.ValidateIssuer"/> for additional details.</remarks>
        protected virtual string ValidateIssuer(string issuer, SecurityToken securityToken, TokenValidationParameters validationParameters)
        {
            return Validators.ValidateIssuer(issuer, securityToken, validationParameters);
        }

        /// <summary>
        /// Validates the <see cref="SecurityToken"/> was signed by a valid <see cref="SecurityKey"/>.
        /// </summary>
        /// <param name="securityKey">The <see cref="SecurityKey"/> that signed the <see cref="SecurityToken"/>.</param>
        /// <param name="securityToken">The <see cref="SecurityToken"/> to validate.</param>
        /// <param name="validationParameters">The current <see cref="TokenValidationParameters"/>.</param>
        protected virtual void ValidateIssuerSecurityKey(SecurityKey securityKey, SecurityToken securityToken, TokenValidationParameters validationParameters)
        {
            Validators.ValidateIssuerSecurityKey(securityKey, securityToken, validationParameters);
        }

        /// <summary>
        /// Serializes to <see cref="Saml2SecurityToken"/> to a string.
        /// </summary>
        /// <param name="token">A <see cref="Saml2SecurityToken"/>.</param>
        public override string WriteToken(SecurityToken token)
        {
            if (token == null)
                throw LogHelper.LogExceptionMessage(new ArgumentNullException("token", String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10000, "token"))); 

            Saml2SecurityToken samlSecurityToken = token as Saml2SecurityToken;
            if (samlSecurityToken == null)
                throw LogHelper.LogExceptionMessage(new ArgumentException(String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10400, this.GetType(), typeof(Saml2SecurityToken), token.GetType())));

            StringBuilder stringBuilder = new StringBuilder();
            using (XmlWriter xmlWriter = XmlWriter.Create(stringBuilder))
            {
                throw new NotSupportedException();
            }
        }

        /// <summary>
        /// Serializes to XML a token of the type handled by this instance.
        /// </summary>
        /// <param name="writer">The XML writer.</param>
        /// <param name="token">A token of type <see cref="TokenType"/>.</param>
        public override void WriteToken(XmlWriter writer, SecurityToken token)
        {
            if (writer == null)
                throw LogHelper.LogExceptionMessage(new ArgumentNullException("writer", String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10000, "writer"))); 

            if (token == null)
                throw LogHelper.LogExceptionMessage(new ArgumentNullException("token", String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10000, "token"))); 

            Saml2SecurityToken samlSecurityToken = token as Saml2SecurityToken;
            if (samlSecurityToken == null)
                throw LogHelper.LogExceptionMessage(new ArgumentException(String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10400, GetType(), typeof(SamlSecurityToken), token.GetType())));

            throw new NotSupportedException();
        }
    }
}
