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

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.IO;
using System.Security.Claims;
using System.Text;
using System.Xml;
using Saml2Handler = System.IdentityModel.Tokens.Saml2SecurityTokenHandler;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// A derived <see cref="System.IdentityModel.Tokens.Saml2SecurityTokenHandler"/> that implements ISecurityTokenValidator, 
    /// which supports validating tokens passed as strings using <see cref="TokenValidationParameters"/>.
    /// </summary>
    ///     
    public class Saml2SecurityTokenHandler : SecurityTokenHandler, ISecurityTokenValidator
    {        
        internal const string Saml2TokenProfile11 = "urn:oasis:names:tc:SAML:2.0:assertion";
        internal const string OasisWssSaml2TokenProfile11 = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0";

        private Int32 _maximumTokenSizeInBytes = TokenValidationParameters.DefaultMaximumTokenSizeInBytes;
        private static string[] _tokenTypeIdentifiers = new string[] { Saml2TokenProfile11, OasisWssSaml2TokenProfile11 };

        // TODO what is this used for?
        // private SecurityTokenSerializer keyInfoSerializer;

        // never set any properties on the handler.
        private static SMSaml2HandlerPrivate _smSaml2HandlerPrivateNeverSetAnyProperties = new SMSaml2HandlerPrivate();

        /// <summary>
        /// Saml2SecurityTokenHandler - TODO
        /// </summary>
        public Saml2SecurityTokenHandler()
        {
        }

        /// <summary>
        /// GetTokenTypeIdentifiers - TODO
        /// </summary>
        /// <returns>TODO</returns>
        public override string[] GetTokenTypeIdentifiers()
        {
            return _tokenTypeIdentifiers;
        }

        /// <summary>
        /// Gets the securityToken type supported by this handler.
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
        /// Gets a value indicating whether the class provides serialization functionality to serialize securityToken handled 
        /// by this instance.
        /// </summary>
        /// <returns>true if the WriteToken method can serialize this securityToken.</returns>
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
        /// Creates the security securityToken reference when the securityToken is not attached to the message.
        /// </summary>
        /// <param name="token">The saml securityToken.</param>
        /// <param name="attached">Boolean that indicates if a attached or unattached
        /// reference needs to be created.</param>
        /// <returns>A <see cref="Saml2AssertionKeyIdentifierClause"/>.</returns>
        public override SecurityKeyIdentifierClause CreateSecurityTokenReference(SecurityToken token, bool attached)
        {
            if (null == token)
            {
                throw new ArgumentNullException("token");
            }

            return token.CreateKeyIdentifierClause<Saml2AssertionKeyIdentifierClause>();
        }

        /// <summary>
        /// Creates a <see cref="ClaimsIdentity"/> from the Saml2 securityToken.
        /// </summary>
        /// <param name="samlToken">The Saml2SecurityToken.</param>
        /// <param name="issuer">the issuer value for each <see cref="Claim"/> in the <see cref="ClaimsIdentity"/>.</param>
        /// <param name="validationParameters"> contains parameters for validating the securityToken.</param>
        /// <returns>An IClaimIdentity.</returns>
        protected virtual ClaimsIdentity CreateClaimsIdentity(Saml2SecurityToken samlToken, string issuer, TokenValidationParameters validationParameters)
        {
            if (samlToken == null)
            {
                throw new ArgumentNullException("samlToken");
            }

            if (string.IsNullOrWhiteSpace(issuer))
            {
                throw new ArgumentException(ErrorMessages.IDX10221);
            }

            Saml2Assertion assertion = samlToken.Assertion;
            if (assertion == null)
            {
                throw new ArgumentException(ErrorMessages.IDX10202);
            }

            ClaimsIdentity identity = validationParameters.CreateClaimsIdentity(samlToken, issuer);
            _smSaml2HandlerPrivateNeverSetAnyProperties.ProcessSamlSubjectPublic(samlToken.Assertion.Subject, identity, issuer);
            _smSaml2HandlerPrivateNeverSetAnyProperties.ProcessStatmentPublic(samlToken.Assertion.Statements, identity, issuer);
            return identity;
        }

        /// <summary>
        /// Creates a <see cref="SecurityToken"/> based on a information contained in the <see cref="SecurityTokenDescriptor"/>.
        /// </summary>
        /// <param name="tokenDescriptor">The <see cref="SecurityTokenDescriptor"/> that has creation information.</param>
        /// <returns>A <see cref="SecurityToken"/> instance.</returns>
        /// <exception cref="ArgumentNullException">Thrown if 'tokenDescriptor' is null.</exception>
        public override SecurityToken CreateToken(SecurityTokenDescriptor tokenDescriptor)
        {
            if (null == tokenDescriptor)
            {
                throw new ArgumentNullException("tokenDescriptor");
            }

            return _smSaml2HandlerPrivateNeverSetAnyProperties.CreateToken(tokenDescriptor);
        }

        /// <summary>
        /// Not supported, use <see cref="TokenValidationParameters"/> when processing tokens.
        /// </summary>
        /// <exception cref="NotSupportedException"> use <see cref="TokenValidationParameters"/>. when processing tokens.</exception>
        public override void LoadCustomConfiguration(XmlNodeList nodelist)
        {
            throw new NotSupportedException(ErrorMessages.IDX11004);
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
                    throw new ArgumentOutOfRangeException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10101, value.ToString(CultureInfo.InvariantCulture)));
                }

                _maximumTokenSizeInBytes = value;
            }
        }

        /// <summary>
        /// Obsolete method, use <see cref="ReadToken(XmlReader, TokenValidationParameters)"/> to read a <see cref="Saml2SecurityToken"/>.
        /// </summary>
        /// <param name="token">not supported.</param>
        /// <exception cref="NotSupportedException"> use use <see cref="ReadToken(XmlReader, TokenValidationParameters)"/> to read a <see cref="Saml2SecurityToken"/>.</exception>
        public override SecurityToken ReadToken(string token)
        {
            throw new NotSupportedException(ErrorMessages.IDX11006);
        }

        /// <summary>
        /// Obsolete method, use <see cref="ReadToken(XmlReader, TokenValidationParameters)"/> to read a <see cref="Saml2SecurityToken"/>.
        /// </summary>
        /// <param name="reader">not supported.</param>
        /// <exception cref="NotSupportedException"> use use <see cref="ReadToken(XmlReader, TokenValidationParameters)"/> to read a <see cref="Saml2SecurityToken"/>.</exception>
        public override SecurityToken ReadToken(XmlReader reader)
        {
            throw new NotSupportedException(ErrorMessages.IDX11002);
        }

        /// <summary>
        /// Reads a SAML 2.0 securityToken from the XmlReader.
        /// </summary>
        /// <param name="reader">A <see cref="XmlReader"/> reader positioned at a <see cref="Saml2SecurityToken"/> element.</param>
        /// <param name="validationParameters">Contains data and information needed for reading the securityToken.</param>
        /// <returns>An instance of a <see cref="Saml2SecurityToken"/>.</returns>
        public virtual SecurityToken ReadToken(XmlReader reader, TokenValidationParameters validationParameters)
        {
            return (new Saml2Handler()
            {
                Configuration = new SecurityTokenHandlerConfiguration
                {
                    IssuerTokenResolver = new SecurityKeyResolver(string.Empty, validationParameters),
                    MaxClockSkew = validationParameters.ClockSkew,
                }
            }).ReadToken(reader);
        }

        /// <summary>
        /// Obsolete method, use <see cref="ValidateToken(String, TokenValidationParameters, out SecurityToken)"/>.
        /// </summary>
        /// <exception cref="NotSupportedException"> use <see cref="ValidateToken(String, TokenValidationParameters, out SecurityToken)"/>.</exception>
        public override ReadOnlyCollection<ClaimsIdentity> ValidateToken(SecurityToken token)
        {
            throw new NotSupportedException(ErrorMessages.IDX11000);
        }

        /// <summary>
        /// Reads and validates a well fromed Saml2 securityToken.
        /// </summary>
        /// <param name="securityToken">A Saml2 securityToken.</param>
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
            {
                throw new ArgumentNullException("securityToken");
            }

            if (validationParameters == null)
            {
                throw new ArgumentNullException("validationParameters");
            }

            if (securityToken.Length > MaximumTokenSizeInBytes)
            {
                throw new ArgumentException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10209, securityToken.Length, MaximumTokenSizeInBytes));
            }

            Saml2SecurityToken samlToken;
            using (StringReader sr = new StringReader(securityToken))
            {
                using (XmlDictionaryReader reader = XmlDictionaryReader.CreateDictionaryReader(XmlReader.Create(sr)))
                {
                    samlToken = (new Saml2Handler()
                    {
                        Configuration = new SecurityTokenHandlerConfiguration
                        {
                            IssuerTokenResolver = new SecurityKeyResolver(securityToken, validationParameters),
                            MaxClockSkew = validationParameters.ClockSkew,
                            ServiceTokenResolver = SecurityTokenResolver.CreateDefaultSecurityTokenResolver(validationParameters.ClientDecryptionTokens, true),
                        }
                    }).ReadToken(reader) as Saml2SecurityToken;
                }
            }

            if (samlToken.IssuerToken == null && validationParameters.RequireSignedTokens)
            {
                throw new SecurityTokenValidationException(ErrorMessages.IDX10213);
            }

            if (samlToken.Assertion == null)
            {
                throw new ArgumentException(ErrorMessages.IDX10202);
            }

            DateTime? notBefore = null;
            DateTime? expires = null;
            if (samlToken.Assertion.Conditions != null)
            {
                notBefore = samlToken.Assertion.Conditions.NotBefore;
                expires = samlToken.Assertion.Conditions.NotOnOrAfter;
            }

            if (validationParameters.LifetimeValidator != null)
            {
                validationParameters.LifetimeValidator(notBefore: notBefore, expires: expires, securityToken: samlToken, validationParameters: validationParameters);
            }
            else
            {
                ValidateLifetime(notBefore: notBefore, expires: expires, securityToken: samlToken, validationParameters: validationParameters);
            }

            // TODO
            // need to validate   ValidateConfirmationData(subjectConfirmation.SubjectConfirmationData);

            List<string> audiences = new List<string>();
            if (samlToken.Assertion.Conditions != null && samlToken.Assertion.Conditions.AudienceRestrictions != null)
            {
                foreach (Saml2AudienceRestriction restriction in samlToken.Assertion.Conditions.AudienceRestrictions)
                {
                    if (restriction==null)
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
                validationParameters.AudienceValidator(audiences, samlToken, validationParameters);
            }
            else
            {
                ValidateAudience(audiences, samlToken, validationParameters);
            }                            

            string issuer  = samlToken.Assertion.Issuer != null ? samlToken.Assertion.Issuer.Value : null;
            if (validationParameters.IssuerValidator != null)
            {
                issuer = validationParameters.IssuerValidator(issuer, samlToken, validationParameters);
            }
            else
            {
                issuer = ValidateIssuer( issuer, samlToken, validationParameters);
            }

            if (string.IsNullOrWhiteSpace(issuer))
            {
                throw new SecurityTokenInvalidIssuerException(ErrorMessages.IDX10203);
            }

            if (samlToken.IssuerToken != null)
            {
                ValidateIssuerSecurityKey(samlToken.IssuerToken.SecurityKeys[0], samlToken, validationParameters);
            }

            ClaimsIdentity claimsIdentity = CreateClaimsIdentity(samlToken, issuer, validationParameters);
            if (validationParameters.SaveSigninToken)
            {
                claimsIdentity.BootstrapContext = new BootstrapContext(securityToken);
            }

            validatedToken = samlToken;
            return new ClaimsPrincipal(claimsIdentity);
        }

        /// <summary>
        /// Determines if the audiences found in a <see cref="Saml2SecurityToken"/> are valid.
        /// </summary>
        /// <param name="audiences">The audiences found in the <see cref="Saml2SecurityToken"/>.</param>
        /// <param name="securityToken">The <see cref="Saml2SecurityToken"/> being validated.</param>
        /// <param name="validationParameters"><see cref="TokenValidationParameters"/> required for validation.</param>
        /// <remarks>see <see cref="Validators.ValidateAudience"/> for additional details.</remarks>
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
        /// <param name="validationParameters">the current <see cref="TokenValidationParameters"/>.</param>
        protected virtual void ValidateIssuerSecurityKey(SecurityKey securityKey, SecurityToken securityToken, TokenValidationParameters validationParameters)
        {
            Validators.ValidateIssuerSecurityKey(securityKey, securityToken, validationParameters);
        }

        /// <summary>
        /// Serializes to <see cref="Saml2SecurityToken"/> to a string.
        /// </summary>
        /// <param name="securityToken">A <see cref="Saml2SecurityToken"/>.</param>
        public override string WriteToken(SecurityToken securityToken)
        {
            if (securityToken == null)
            {
                throw new ArgumentNullException("securityToken");
            }

            Saml2SecurityToken samlSecurityToken = securityToken as Saml2SecurityToken;
            if (samlSecurityToken == null)
            {
                throw new ArgumentException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10400, this.GetType(), typeof(Saml2SecurityToken), securityToken.GetType()));
            }


            StringBuilder stringBuilder = new StringBuilder();
            using (XmlWriter xmlWriter = XmlWriter.Create(stringBuilder))
            {
                _smSaml2HandlerPrivateNeverSetAnyProperties.WriteToken(xmlWriter, securityToken);
                return stringBuilder.ToString();
            }
        }

        /// <summary>
        /// Serializes to XML a securityToken of the type handled by this instance.
        /// </summary>
        /// <param name="writer">The XML writer.</param>
        /// <param name="securityToken">A securityToken of type <see cref="TokenType"/>.</param>
        public override void WriteToken(XmlWriter writer, SecurityToken securityToken)
        {
            if (writer == null)
            {
                throw new ArgumentNullException("writer");
            }

            if (securityToken == null)
            {
                throw new ArgumentNullException("token");
            }

            Saml2SecurityToken samlSecurityToken = securityToken as Saml2SecurityToken;
            if (samlSecurityToken == null)
            {
                throw new ArgumentException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10400, this.GetType(), typeof(SamlSecurityToken), securityToken.GetType()));
            }

            _smSaml2HandlerPrivateNeverSetAnyProperties.WriteToken(writer, securityToken);
        }

        private class SMSaml2HandlerPrivate : Saml2Handler
        {
            public void ProcessStatmentPublic(Collection<Saml2Statement> statements, ClaimsIdentity subject, string issuer)
            {
                base.ProcessStatement(statements, subject, issuer);
            }

            public void ProcessSamlSubjectPublic(Saml2Subject assertionSubject, ClaimsIdentity subject, string issuer)
            {
                base.ProcessSamlSubject(assertionSubject, subject, issuer);
            }
        }
    }
}