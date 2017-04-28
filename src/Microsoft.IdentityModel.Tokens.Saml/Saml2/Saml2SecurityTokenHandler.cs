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
using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Xml;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Xml;

using TokenLogMessages = Microsoft.IdentityModel.Tokens.LogMessages;

namespace Microsoft.IdentityModel.Tokens.Saml2
{
    /// <summary>
    /// Creates SAML2 assertion-based security tokens
    /// </summary>
    public class Saml2SecurityTokenHandler : SecurityTokenHandler, ISecurityTokenValidator
    {
        private const string Actor = "Actor";
        private static string[] _tokenTypeIdentifiers = new string[] { Saml2Constants.Saml2TokenProfile11, Saml2Constants.OasisWssSaml2TokenProfile11 };
        private int _maximumTokenSizeInBytes = TokenValidationParameters.DefaultMaximumTokenSizeInBytes;

        /// <summary>
        /// Creates an instance of <see cref="Saml2SecurityTokenHandler"/>
        /// </summary>
        public Saml2SecurityTokenHandler()
        { }

        public Saml2Serializer Serializer { get; set; } = new Saml2Serializer();

        /// <summary>
        /// Returns a value that indicates if this handler can validate <see cref="SecurityToken"/>.
        /// </summary>
        /// <returns>'True', indicating this instance can validate <see cref="SecurityToken"/>.</returns>
        public override bool CanValidateToken
        {
            get { return true; }
        }

        /// <summary>
        /// Gets the token type supported by this handler.
        /// </summary>
        public override Type TokenType
        {
            get { return typeof(Saml2SecurityToken); }
        }

        /// <summary>
        /// Gets the value if this instance can write a token.
        /// </summary>
        public override bool CanWriteToken
        {
            get { return true; }
        }

        /// <summary>
        /// Gets and sets the maximum size in bytes, that a will be processed.
        /// </summary>
        /// <exception cref="ArgumentOutOfRangeException">'value' less than 1.</exception>
        public int MaximumTokenSizeInBytes
        {
            get { return _maximumTokenSizeInBytes; }
            set
            {
                if (value < 1)
                    throw LogHelper.LogExceptionMessage(new ArgumentOutOfRangeException(nameof(value), LogHelper.FormatInvariant(TokenLogMessages.IDX10101, value)));

                _maximumTokenSizeInBytes = value;
            }
        }

        public override bool CanReadToken(string token)
        {
            if (string.IsNullOrEmpty(token))
                throw LogHelper.LogArgumentNullException(nameof(token));

            if (token.Length * 2 > MaximumTokenSizeInBytes)
                return false;

            using (StringReader sr = new StringReader(token))
            {
                using (XmlDictionaryReader reader = XmlDictionaryReader.CreateDictionaryReader(XmlReader.Create(sr)))
                {
                    return CanReadToken(reader);
                }
            }
        }

        /// <summary>
        /// Indicates whether the current XML element can be read as a token of the type handled by this instance.
        /// </summary>
        /// <param name="reader">An <see cref="XmlReader"/> reader positioned at a start element. The reader should not be advanced.</param>
        /// <returns>'True' if the ReadToken method can read the element.</returns>
        public bool CanReadToken(XmlReader reader)
        {
            if (reader == null)
                return false;

            return reader.IsStartElement(Saml2Constants.Elements.Assertion, Saml2Constants.Namespace)
               || reader.IsStartElement(Saml2Constants.Elements.EncryptedAssertion, Saml2Constants.Namespace);
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
                throw LogHelper.LogArgumentNullException(nameof(tokenDescriptor));

            // Assertion/issuer
            Saml2Assertion assertion = new Saml2Assertion(CreateIssuerNameIdentifier(tokenDescriptor));

            // Subject
            assertion.Subject = CreateSamlSubject(tokenDescriptor);

            // Signature
            assertion.SigningCredentials = GetSigningCredentials(tokenDescriptor);

            // Conditions
            assertion.Conditions = CreateConditions(tokenDescriptor);

            // Advice
            assertion.Advice = CreateAdvice(tokenDescriptor);

            // Statements
            IEnumerable<Saml2Statement> statements = CreateStatements(tokenDescriptor);
            if (null != statements)
            {
                foreach (Saml2Statement statement in statements)
                {
                    assertion.Statements.Add(statement);
                }
            }

            // encrypting credentials
            assertion.EncryptingCredentials = GetEncryptingCredentials(tokenDescriptor);

            SecurityToken token = new Saml2SecurityToken(assertion);

            return token;
        }

        /// <summary>
        /// Validates a <see cref="Saml2SecurityToken"/>.
        /// </summary>
        /// <param name="token">The <see cref="Saml2SecurityToken"/> to validate.</param>
        /// <param name="validationParameters">Contains validation parameters for the <see cref="Saml2SecurityToken"/>.</param>
        /// <param name="validatedToken">The <see cref="Saml2SecurityToken"/> that was validated.</param>
        /// <exception cref="ArgumentNullException">'token' is null or whitespace.</exception>
        /// <exception cref="ArgumentNullException">'validationParameters' is null.</exception>
        /// <exception cref="ArgumentException">token.Length > MamimumTokenSizeInBytes.</exception>
        /// <returns>A <see cref="ClaimsPrincipal"/> representing the identity contained in the token.</returns>
        public ClaimsPrincipal ValidateToken(string token, TokenValidationParameters validationParameters, out SecurityToken validatedToken)
        {
            if (token == null)
                throw LogHelper.LogArgumentNullException(nameof(token));

            if (validationParameters == null)
                throw LogHelper.LogArgumentNullException(nameof(validationParameters));

            if (token.Length > MaximumTokenSizeInBytes)
                throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(TokenLogMessages.IDX10209, token.Length, MaximumTokenSizeInBytes)));

            var samlToken = ValidateSignature(token, validationParameters);
            ValidateConditions(samlToken, validationParameters);
            ValidateSubject(samlToken, validationParameters);
            ValidateIssuer(samlToken.Issuer, samlToken, validationParameters);
            validatedToken = samlToken;
            var identity = CreateClaims(samlToken, validationParameters);
            if (validationParameters.SaveSigninToken)
                identity.BootstrapContext = token;

            IdentityModelEventSource.Logger.WriteInformation(TokenLogMessages.IDX10241, token);

            return new ClaimsPrincipal(identity);
        }

        protected virtual void ValidateSubject(Saml2SecurityToken securityToken, TokenValidationParameters validationParameters)
        {
            if (securityToken == null)
                throw LogHelper.LogArgumentNullException(nameof(securityToken));

            if (securityToken.Assertion == null)
                throw LogHelper.LogArgumentNullException(nameof(securityToken.Assertion));

            if (securityToken.Assertion.Subject == null)
                throw LogHelper.LogExceptionMessage(new Saml2SecurityTokenException(LogMessages.IDX10509));

            var subjectConfirmation = securityToken.Assertion.Subject.SubjectConfirmations[0];
            if (subjectConfirmation != null && subjectConfirmation.SubjectConfirmationData != null)
                ValidateConfirmationData(subjectConfirmation.SubjectConfirmationData, securityToken, validationParameters);
        }

        /// <summary>
        /// Validates the Saml2SubjectConfirmation data.
        /// </summary>
        /// <param name="confirmationData">The Saml2 subject confirmation data.</param>
        protected virtual void ValidateConfirmationData(Saml2SubjectConfirmationData confirmationData, Saml2SecurityToken securityToken, TokenValidationParameters validationParameters)
        {
            if (null == confirmationData)
                throw LogHelper.LogArgumentNullException(nameof(confirmationData));

            if (validationParameters == null)
                throw LogHelper.LogArgumentNullException(nameof(validationParameters));

            Validators.ValidateLifetime(confirmationData.NotBefore, confirmationData.NotOnOrAfter, securityToken, validationParameters);
        }

        /// <summary>
        /// Reads the 'token' as a Saml2 SecurityToken and validates the signature is valid.
        /// </summary>
        /// <param name="token">A signed Saml2 token.</param>
        /// <param name="validationParameters"><see cref="TokenValidationParameters"/> that contains signing keys.</param>
        /// <exception cref="ArgumentNullException">If 'token' is null or whitespace.</exception>
        /// <exception cref="ArgumentNullException">If 'validationParameters' is null.</exception>
        /// <exception cref="SecurityTokenValidationException">If a signature is not found and <see cref="TokenValidationParameters.RequireSignedTokens"/> is true.</exception>
        /// <exception cref="SecurityTokenSignatureKeyNotFoundException">If the 'token' has a key identifier and none of the <see cref="SecurityKey"/>(s) provided result in a validated signature. 
        /// This can indicate that a key refresh is required.</exception>
        /// <exception cref="SecurityTokenInvalidSignatureException">If after trying all the <see cref="SecurityKey"/>(s), none result in a validated signture AND the 'token' does not have a key identifier.</exception>
        /// <returns><see cref="Saml2SecurityToken"/> that has the signature validated if token was signed and <see cref="TokenValidationParameters.RequireSignedTokens"/> is true.</returns>
        /// <remarks><para>If the 'token' is signed, the signature is validated even if <see cref="TokenValidationParameters.RequireSignedTokens"/> is false.</para>
        /// <para>If the 'token' signature is validated, then the <see cref="Saml2SecurityToken.SigningKey"/> will be set to the key that signed the 'token'.</para></remarks>
        protected virtual Saml2SecurityToken ValidateSignature(string token, TokenValidationParameters validationParameters)
        {
            if (string.IsNullOrEmpty(token))
                throw LogHelper.LogArgumentNullException(nameof(token));

            if (validationParameters == null)
                throw LogHelper.LogArgumentNullException(nameof(validationParameters));

            var samlToken = ReadSaml2Token(token);
            if (validationParameters.SignatureValidator != null)
            {
                var validatedSamlToken = validationParameters.SignatureValidator(token, validationParameters);
                if (validatedSamlToken == null)
                    throw LogHelper.LogExceptionMessage(new SecurityTokenInvalidSignatureException(LogHelper.FormatInvariant(TokenLogMessages.IDX10505, token)));

                var validatedSaml = validatedSamlToken as Saml2SecurityToken;
                if (validatedSaml == null)
                    throw LogHelper.LogExceptionMessage(new SecurityTokenInvalidSignatureException(LogHelper.FormatInvariant(TokenLogMessages.IDX10506, typeof(Saml2SecurityToken), validatedSamlToken.GetType(), token)));

                return validatedSaml;
            }

            if (samlToken.Assertion.Signature == null && validationParameters.RequireSignedTokens)
                throw LogHelper.LogExceptionMessage(new SecurityTokenValidationException(LogHelper.FormatInvariant(TokenLogMessages.IDX10504, token)));

            IEnumerable<SecurityKey> securityKeys = null;
            if (validationParameters.IssuerSigningKeyResolver != null)
            {
                securityKeys = validationParameters.IssuerSigningKeyResolver(token, samlToken, samlToken.SigningKey.KeyId, validationParameters);
            }
            else
            {
                var securityKey = ResolveIssuerSigningKey(token, samlToken, validationParameters);
                if (securityKey != null)
                {
                    try
                    {
                        samlToken.Assertion.Signature.Verify(securityKey);
                    }
                    catch (Exception ex)
                    {
                        throw new SecurityTokenInvalidSignatureException(TokenLogMessages.IDX10508, ex);
                    }
                }
            }

            if (securityKeys == null)
            {
                // control gets here if:
                // 1. User specified delegate: IssuerSigningKeyResolver returned null
                // 2. ResolveIssuerSigningKey returned null
                // Try all the keys. This is the degenerate case, not concerned about perf.
                securityKeys = GetAllSigningKeys(validationParameters);
            }

            // keep track of exceptions thrown, keys that were tried
            StringBuilder exceptionStrings = new StringBuilder();
            StringBuilder keysAttempted = new StringBuilder();
            bool canMatchKey = samlToken.Assertion.Signature.KeyInfo != null;
            foreach (SecurityKey securityKey in securityKeys)
            {
                try
                {
                    samlToken.Assertion.Signature.Verify(securityKey);
                    samlToken.SigningKey = securityKey;
                    return samlToken;
                }
                catch (Exception ex)
                {
                    exceptionStrings.AppendLine(ex.ToString());
                }

                if (securityKey != null)
                    keysAttempted.AppendLine(securityKey.ToString() + " , KeyId: " + securityKey.KeyId);
            }

            // if the kid != null and the signature fails, throw SecurityTokenSignatureKeyNotFoundException
            if (canMatchKey && keysAttempted.Length > 0)
                throw LogHelper.LogExceptionMessage(new SecurityTokenSignatureKeyNotFoundException(LogHelper.FormatInvariant(TokenLogMessages.IDX10501, samlToken.Assertion.Signature.KeyInfo, samlToken)));

            if (keysAttempted.Length > 0)
                throw LogHelper.LogExceptionMessage(new SecurityTokenInvalidSignatureException(LogHelper.FormatInvariant(TokenLogMessages.IDX10503, keysAttempted, exceptionStrings, samlToken)));

            throw LogHelper.LogExceptionMessage(new SecurityTokenInvalidSignatureException(TokenLogMessages.IDX10500));
        }

        private IEnumerable<SecurityKey> GetAllSigningKeys(TokenValidationParameters validationParameters)
        {
            IdentityModelEventSource.Logger.WriteInformation(TokenLogMessages.IDX10243);
            if (validationParameters.IssuerSigningKey != null)
                yield return validationParameters.IssuerSigningKey;

            if (validationParameters.IssuerSigningKeys != null)
                foreach (SecurityKey securityKey in validationParameters.IssuerSigningKeys)
                    yield return securityKey;
        }

        /// <summary>
        /// Returns a <see cref="SecurityKey"/> to use when validating the signature of a token.
        /// </summary>
        /// <param name="token">The <see cref="string"/> representation of the token that is being validated.</param>
        /// <param name="securityToken">The <see cref="JwtSecurityToken"/> that is being validated.</param>
        /// <param name="validationParameters">A <see cref="TokenValidationParameters"/>  required for validation.</param>
        /// <returns>Returns a <see cref="SecurityKey"/> to use for signature validation.</returns>
        /// <remarks>If key fails to resolve, then null is returned</remarks>
        protected virtual SecurityKey ResolveIssuerSigningKey(string token, Saml2SecurityToken securityToken, TokenValidationParameters validationParameters)
        {
            if (securityToken == null)
                throw LogHelper.LogArgumentNullException(nameof(securityToken));

            if (validationParameters == null)
                throw LogHelper.LogArgumentNullException(nameof(validationParameters));

            if (securityToken.Assertion == null)
                throw LogHelper.LogArgumentNullException(nameof(securityToken.Assertion));

            if (securityToken.Assertion.Signature.KeyInfo != null)
            {
                if (validationParameters.IssuerSigningKey != null && string.Equals(validationParameters.IssuerSigningKey.KeyId, securityToken.Assertion.Signature.KeyInfo.Kid, StringComparison.Ordinal))
                    return validationParameters.IssuerSigningKey;

                if (validationParameters.IssuerSigningKeys != null)
                {
                    foreach (var signingKey in validationParameters.IssuerSigningKeys)
                    {
                        if (signingKey != null && string.Equals(signingKey.KeyId, securityToken.Assertion.Signature.KeyInfo.Kid, StringComparison.Ordinal))
                            return signingKey;
                    }
                }
            }

            return null;
        }

        /// <summary>
        /// Writes a Saml2 Token using the XmlWriter.
        /// </summary>
        /// <param name="writer">A <see cref="XmlWriter"/> to serialize the <see cref="SecurityToken"/>.</param>
        /// <param name="token">The <see cref="SecurityToken"/> to serialize.</param>
        /// <exception cref="ArgumentNullException">The input argument 'writer' or 'token' is null.</exception>
        /// <exception cref="ArgumentException">The input argument 'token' is not a <see cref="Saml2SecurityToken"/>.</exception>
        public override void WriteToken(XmlWriter writer, SecurityToken token)
        {
            if (writer == null)
                throw LogHelper.LogArgumentNullException(nameof(writer));

            if (token == null)
                throw LogHelper.LogArgumentNullException(nameof(token));

            var samlToken = token as Saml2SecurityToken;
            if (null == samlToken)
                throw Saml2Serializer.LogWriteException(LogMessages.IDX11150, token.GetType());

            Serializer.WriteAssertion(writer, samlToken.Assertion);
        }

        public virtual Saml2SecurityToken ReadSaml2Token(string token)
        {
            if (string.IsNullOrEmpty(token))
                throw LogHelper.LogArgumentNullException(nameof(token));

            if (token.Length > MaximumTokenSizeInBytes)
                throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(TokenLogMessages.IDX10209, token.Length, MaximumTokenSizeInBytes)));

            using (StringReader sr = new StringReader(token))
            {
                using (XmlDictionaryReader reader = XmlDictionaryReader.CreateDictionaryReader(XmlReader.Create(sr)))
                {
                    var assertion = Serializer.ReadAssertion(reader);
                    return new Saml2SecurityToken(assertion);
                }
            }
        }

        public override SecurityToken ReadToken(string token)
        {
            return ReadSaml2Token(token);
        }

        /// <summary>
        /// Reads and validates a SAML 2.0 token using the XmlReader.
        /// </summary>
        /// <param name="reader">A <see cref="XmlReader"/> reader positioned at a <see cref="Saml2SecurityToken"/> element.</param>
        /// <param name="validationParameters"> validation parameters for the <see cref="Saml2SecurityToken"/>.</param>
        /// <returns>An instance of <see cref="Saml2SecurityToken"/>.</returns>
        public override SecurityToken ReadToken(XmlReader reader, TokenValidationParameters validationParameters)
        {
            throw new NotSupportedException("API is not supported");
        }

        internal static XmlDictionaryReader CreatePlaintextReaderFromEncryptedData(
                        XmlDictionaryReader reader,
                        Collection<SecurityKeyIdentifierClause> clauses,
                        out EncryptingCredentials encryptingCredentials)
        {
            if (reader == null)
                throw LogHelper.LogArgumentNullException(nameof(reader));

            reader.MoveToContent();
            if (reader.IsEmptyElement)
                throw LogHelper.LogExceptionMessage(new Saml2SecurityTokenException("ID3061"));

            encryptingCredentials = null;

            XmlUtil.ValidateXsiType(reader, Saml2Constants.Types.EncryptedElementType, Saml2Constants.Namespace);

            reader.ReadStartElement();
            EncryptedDataElement encryptedData = new EncryptedDataElement();

            // <xenc:EncryptedData> 1
            encryptedData.ReadXml(reader);

            // <xenc:EncryptedKey> 0-oo
            reader.MoveToContent();
            while (reader.IsStartElement(XmlEncryptionConstants.Elements.EncryptedKey, XmlEncryptionConstants.Namespace))
            {
                reader.Skip();
                // TODO - securityKey reader / writer
                //if (keyInfoSerializer.CanReadKeyIdentifierClause(reader))
                //{
                //    skic = keyInfoSerializer.ReadKeyIdentifierClause(reader);
                //}
                //else
                //{
                //    EncryptedKeyElement encryptedKey = new EncryptedKeyElement(keyInfoSerializer);
                //    encryptedKey.ReadXml(reader);
                //    skic = encryptedKey.GetClause();
                //}

                //EncryptedKeyIdentifierClause encryptedKeyClause = skic as EncryptedKeyIdentifierClause;
                //if (null == encryptedKeyClause)
                //{
                //    throw LogHelper.ThrowHelperXml(reader, SR.GetString(SR.ID4172));
                //}

                //clauses.Add(encryptedKeyClause);
            }

            reader.ReadEndElement();

            // Try to resolve the decryption key from both the embedded 
            // KeyInfo and any external clauses
            //SecurityKey decryptionKey = null;
            //SecurityKeyIdentifierClause matchingClause = null;

            //foreach (SecurityKeyIdentifierClause clause in encryptedData.KeyIdentifier)
            //{
            //    if (serviceTokenResolver.TryResolveSecurityKey(clause, out decryptionKey))
            //    {
            //        matchingClause = clause;
            //        break;
            //    }
            //}

            //if (null == decryptionKey)
            //{
            //    foreach (SecurityKeyIdentifierClause clause in clauses)
            //    {
            //        if (serviceTokenResolver.TryResolveSecurityKey(clause, out decryptionKey))
            //        {
            //            matchingClause = clause;
            //            break;
            //        }
            //    }
            //}

            //if (null == decryptionKey)
            //{
            //    throw LogHelper.LogExceptionMessage(
            //        new EncryptedTokenDecryptionFailedException());
            //}

            //// Need a symmetric key
            //SymmetricSecurityKey symmetricKey = decryptionKey as SymmetricSecurityKey;
            //if (null == symmetricKey)
            //{
            //    throw LogHelper.LogExceptionMessage(
            //        new SecurityTokenException(SR.GetString(SR.ID4023)));
            //}

            //// Do the actual decryption
            //SymmetricAlgorithm decryptor = symmetricKey.GetSymmetricAlgorithm(encryptedData.Algorithm);
            //byte[] plainText = encryptedData.Decrypt(decryptor);

            //// Save off the encrypting credentials for roundtrip
            //encryptingCredentials = new ReceivedEncryptingCredentials(decryptionKey, new SecurityKeyIdentifier(matchingClause), encryptedData.Algorithm);

            return XmlDictionaryReader.CreateTextReader(new byte[10], reader.Quotas);
        }

        /// <summary>
        /// Indicates if the current XML element is pointing to a Saml2Assertion.
        /// </summary>
        /// <param name="reader">A reader that may contain a <see cref="Saml2Assertion"/>.</param>
        /// <returns>'True' if reader contains a <see cref="Saml2Assertion"/>. 'False' otherwise.</returns>
        internal static bool IsSaml2Assertion(XmlReader reader)
        {
            return reader.IsStartElement(Saml2Constants.Elements.Assertion, Saml2Constants.Namespace)
               || reader.IsStartElement(Saml2Constants.Elements.EncryptedAssertion, Saml2Constants.Namespace);
        }

        /// <summary>
        /// Creates the conditions for the assertion.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Generally, conditions should be included in assertions to limit the 
        /// impact of misuse of the assertion. Specifying the NotBefore and 
        /// NotOnOrAfter conditions can limit the period of vulnerability in 
        /// the case of a compromised assertion. The AudienceRestrictionCondition
        /// can be used to explicitly state the intended relying party or parties
        /// of the assertion, which coupled with appropriate audience restriction
        /// enforcement at relying parties can help to mitigate spoofing attacks
        /// between relying parties.
        /// </para>
        /// <para>
        /// The default implementation creates NotBefore and NotOnOrAfter conditions
        /// based on the tokenDescriptor.Lifetime. It will also generate an 
        /// AudienceRestrictionCondition limiting consumption of the assertion to 
        /// tokenDescriptor.Scope.Address.
        /// </para>
        /// </remarks>
        /// <param name="tokenLifetime">Lifetime of the Token.</param>
        /// <param name="relyingPartyAddress">The endpoint address to who the token is created. The address
        /// is modeled as an AudienceRestriction condition.</param>
        /// <param name="tokenDescriptor">The token descriptor.</param>
        /// <returns>A Saml2Conditions object.</returns>
        protected virtual Saml2Conditions CreateConditions(SecurityTokenDescriptor tokenDescriptor)
        {
            if (null == tokenDescriptor)
                throw LogHelper.LogArgumentNullException(nameof(tokenDescriptor));

            // TODO - check for should set lifetime, url for audience
            var conditions = new Saml2Conditions();
            if (tokenDescriptor.NotBefore.HasValue)
                conditions.NotBefore = tokenDescriptor.NotBefore.Value;

            if (tokenDescriptor.Expires.HasValue)
                conditions.NotOnOrAfter = tokenDescriptor.Expires.Value;

            if (!string.IsNullOrEmpty(tokenDescriptor.Audience))
                conditions.AudienceRestrictions.Add(new Saml2AudienceRestriction(tokenDescriptor.Audience));

            return conditions;
        }

        /// <summary>
        /// Creates the advice for the assertion.
        /// </summary>
        /// <remarks>
        /// By default, this method returns null.
        /// </remarks>
        /// <param name="tokenDescriptor">The token descriptor.</param>
        /// <returns>A Saml2Advice object, default is null.</returns>
        protected virtual Saml2Advice CreateAdvice(SecurityTokenDescriptor tokenDescriptor)
        {
            return null;
        }

        /// <summary>
        /// Creates a name identifier that identifies the assertion issuer.
        /// </summary>
        /// <remarks>
        /// <para>
        /// SAML2 assertions must contain a name identifier for the issuer. 
        /// This method may not return null.
        /// </para>
        /// <para>
        /// The default implementation creates a simple name identifier 
        /// from the tokenDescriptor.Issuer. 
        /// </para>
        /// </remarks>
        /// <param name="tokenDescriptor">The token descriptor.</param>
        /// <returns>A <see cref="Saml2NameIdentifier"/> from the tokenDescriptor</returns>
        protected virtual Saml2NameIdentifier CreateIssuerNameIdentifier(SecurityTokenDescriptor tokenDescriptor)
        {
            if (null == tokenDescriptor)
                throw LogHelper.LogArgumentNullException(nameof(tokenDescriptor));

            // Must have an issuer
            if (string.IsNullOrEmpty(tokenDescriptor.Issuer))
                throw LogHelper.LogExceptionMessage(new Saml2SecurityTokenException("ID4138"));

            return new Saml2NameIdentifier(tokenDescriptor.Issuer);
        }

        /// <summary>
        /// Generates a Saml2Attribute from a claim.
        /// </summary>
        /// <param name="claim">The <see cref="Claim"/> from which to generate a <see cref="Saml2Attribute"/>.</param>
        /// <param name="tokenDescriptor">Contains all the information that is used in token issuance.</param>
        /// <returns>A <see cref="Saml2Attribute"/> based on the claim.</returns>
        /// <exception cref="ArgumentNullException">The parameter 'claim' is null.</exception>
        protected virtual Saml2Attribute CreateAttribute(Claim claim, SecurityTokenDescriptor tokenDescriptor)
        {
            if (claim == null)
                throw LogHelper.LogArgumentNullException(nameof(claim));

            Saml2Attribute attribute = new Saml2Attribute(claim.Type, claim.Value);
            if (!StringComparer.Ordinal.Equals(ClaimsIdentity.DefaultIssuer, claim.OriginalIssuer))
                attribute.OriginalIssuer = claim.OriginalIssuer;

            attribute.AttributeValueXsiType = claim.ValueType;

            if (claim.Properties.ContainsKey(ClaimProperties.SamlAttributeNameFormat))
            {
                string nameFormat = claim.Properties[ClaimProperties.SamlAttributeNameFormat];
                if (!XmlUtil.CanCreateValidUri(nameFormat, UriKind.Absolute))
                    throw LogHelper.LogArgumentNullException("nameof(nameFormat), ID0013");

                attribute.NameFormat = new Uri(nameFormat);
            }

            if (claim.Properties.ContainsKey(ClaimProperties.SamlAttributeDisplayName))
                attribute.FriendlyName = claim.Properties[ClaimProperties.SamlAttributeDisplayName];

            return attribute;
        }

        /// <summary>
        /// Creates <see cref="Saml2AttributeStatement"/> from a <see cref="SecurityTokenDescriptor"/> and a <see cref="ClaimsIdentity"/>
        /// </summary>
        /// <remarks>This method may return null if the token descriptor does not contain any subject or the subject does not have any claims.
        /// </remarks>
        /// <param name="subject">The <see cref="ClaimsIdentity"/> that contains claims which will be converted to SAML Attributes.</param>
        /// <param name="tokenDescriptor">The <see cref="SecurityTokenDescriptor"/> that contains information on building the <see cref="Saml2AttributeStatement"/>.</param>
        /// <returns>A Saml2AttributeStatement.</returns>
        protected virtual Saml2AttributeStatement CreateAttributeStatement(ClaimsIdentity subject, SecurityTokenDescriptor tokenDescriptor)
        {
            if (subject == null)
            {
                return null;
            }

            // We treat everything else as an Attribute except the nameId claim, which is already processed
            // for saml2subject
            // AuthenticationInstant and AuthenticationType are not converted to Claims
            if (subject.Claims != null)
            {
                List<Saml2Attribute> attributes = new List<Saml2Attribute>();
                foreach (Claim claim in subject.Claims)
                {
                    if (claim != null && claim.Type != ClaimTypes.NameIdentifier)
                    {
                        switch (claim.Type)
                        {
                            case ClaimTypes.AuthenticationInstant:
                            case ClaimTypes.AuthenticationMethod:
                                break;
                            default:
                                attributes.Add(CreateAttribute(claim, tokenDescriptor));
                                break;
                        }
                    }
                }

                AddDelegateToAttributes(subject, attributes, tokenDescriptor);
                return new Saml2AttributeStatement(CollectAttributeValues(attributes));
            }

            return null;
        }

        /// <summary>
        /// Collects attributes with a common claim type, claim value type, and original issuer into a
        /// single attribute with multiple values.
        /// </summary>
        /// <param name="attributes">List of attributes generated from claims.</param>
        /// <returns>A <see cref="ICollection{T}"/> of <see cref="Saml2Attribute"/> with common attributes collected into value lists.</returns>
        protected virtual ICollection<Saml2Attribute> CollectAttributeValues(ICollection<Saml2Attribute> attributes)
        {
            var distinctAttributes = new Dictionary<Saml2AttributeKeyComparer.AttributeKey, Saml2Attribute>(attributes.Count, new Saml2AttributeKeyComparer());

            // Use unique attribute if name, value type, or issuer differ
            foreach (Saml2Attribute saml2Attribute in attributes)
            {
                if (saml2Attribute != null)
                {
                    Saml2AttributeKeyComparer.AttributeKey attributeKey = new Saml2AttributeKeyComparer.AttributeKey(saml2Attribute);

                    if (distinctAttributes.ContainsKey(attributeKey))
                    {
                        foreach (string attributeValue in saml2Attribute.Values)
                            distinctAttributes[attributeKey].Values.Add(attributeValue);
                    }
                    else
                    {
                        distinctAttributes.Add(attributeKey, saml2Attribute);
                    }
                }
            }

            return distinctAttributes.Values;
        }

        /// <summary>
        /// Adds all the delegates associated with the subject into the attribute collection.
        /// </summary>
        /// <param name="subject">The delegate of this <see cref="ClaimsIdentity"/> will be serialized into a <see cref="Saml2Attribute"/>.</param>
        /// <param name="attributes">A <see cref="ICollection{T}"/> of <see cref="Saml2Attribute"/>.</param>
        /// <param name="tokenDescriptor">The <see cref="SecurityTokenDescriptor"/> that contains information on building the delegate.</param>
        protected virtual void AddDelegateToAttributes(ClaimsIdentity subject, ICollection<Saml2Attribute> attributes, SecurityTokenDescriptor tokenDescriptor)
        {
            if (subject == null)
                throw LogHelper.LogArgumentNullException(nameof(subject));

            if (tokenDescriptor == null)
                throw LogHelper.LogArgumentNullException(nameof(tokenDescriptor));

            if (subject.Actor == null)
                return;

            var actingAsAttributes = new List<Saml2Attribute>();
            foreach (Claim claim in subject.Actor.Claims)
            {
                if (claim != null)
                    actingAsAttributes.Add(CreateAttribute(claim, tokenDescriptor));
            }

            AddDelegateToAttributes(subject.Actor, actingAsAttributes, tokenDescriptor);

            ICollection<Saml2Attribute> collectedAttributes = CollectAttributeValues(actingAsAttributes);
            attributes.Add(CreateAttribute(new Claim(ClaimTypes.Actor, CreateXmlStringFromAttributes(collectedAttributes), ClaimValueTypes.String), tokenDescriptor));
        }

        /// <summary>
        /// Builds an XML formatted string from a collection of SAML attributes that represent the Actor. 
        /// </summary>
        /// <param name="attributes">An enumeration of Saml2Attributes.</param>
        /// <returns>A well-formed XML string.</returns>
        /// <remarks>The string is of the form "&lt;Actor&gt;&lt;Attribute name, ns&gt;&lt;AttributeValue&gt;...&lt;/AttributeValue&gt;, ...&lt;/Attribute&gt;...&lt;/Actor&gt;"</remarks>
        protected virtual string CreateXmlStringFromAttributes(IEnumerable<Saml2Attribute> attributes)
        {
            if (attributes == null)
                throw LogHelper.LogArgumentNullException(nameof(attributes));

            bool actorElementWritten = false;
            using (MemoryStream ms = new MemoryStream())
            {
                using (XmlDictionaryWriter dicWriter = XmlDictionaryWriter.CreateTextWriter(ms, Encoding.UTF8, false))
                {
                    foreach (Saml2Attribute samlAttribute in attributes)
                    {
                        if (samlAttribute != null)
                        {
                            if (!actorElementWritten)
                            {
                                dicWriter.WriteStartElement(Actor);
                                actorElementWritten = true;
                            }

                            Serializer.WriteAttribute(dicWriter, samlAttribute);
                        }
                    }

                    if (actorElementWritten)
                        dicWriter.WriteEndElement();

                    dicWriter.Flush();
                }

                return Encoding.UTF8.GetString(ms.ToArray());
            }
        }

        /// <summary>
        /// Creates an <see cref="IEnumerable{T}"/> of <see cref="Saml2Statement"/> to be included in the assertion.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Statements are not required in a SAML2 assertion. This method may
        /// return an empty collection.
        /// </para>
        /// </remarks>
        /// <param name="tokenDescriptor">The <see cref="SecurityTokenDescriptor"/> that contains information on creating the <see cref="Saml2Statement"/>.</param>
        /// <returns>An enumeration of Saml2Statements.</returns>
        protected virtual IEnumerable<Saml2Statement> CreateStatements(SecurityTokenDescriptor tokenDescriptor)
        {
            if (tokenDescriptor == null)
                throw LogHelper.LogArgumentNullException(nameof(tokenDescriptor));

            var statements = new Collection<Saml2Statement>();
            var attributeStatement = CreateAttributeStatement(tokenDescriptor.Subject, tokenDescriptor);
            if (attributeStatement != null)
                statements.Add(attributeStatement);

            // TODO - figure out how to set the AuthenticationInfo
            //var authenticationStatement = this.CreateAuthenticationStatement(tokenDescriptor.AuthenticationInfo, tokenDescriptor);
            //if (authenticationStatement != null)
            //    statements.Add(authenticationStatement);

            return statements;
        }

        /// <summary>
        /// Given an AuthenticationInformation object, this routine creates a Saml2AuthenticationStatement
        /// to be added to the Saml2Assertion that is produced by the factory.
        /// </summary>
        /// <param name="authInfo">
        /// An AuthenticationInformation object containing the state to be wrapped as a Saml2AuthenticationStatement
        /// object.
        /// </param>
        /// <param name="tokenDescriptor">The token descriptor.</param>
        /// <returns>
        /// The Saml2AuthenticationStatement to add to the assertion being created or null to ignore the AuthenticationInformation
        /// being wrapped as a statement.
        /// </returns>
        protected virtual Saml2AuthenticationStatement CreateAuthenticationStatement(AuthenticationInformation authInfo, SecurityTokenDescriptor tokenDescriptor)
        {
            if (tokenDescriptor == null)
                throw LogHelper.LogArgumentNullException(nameof(tokenDescriptor));

            if (tokenDescriptor.Subject == null)
                return null;

            Uri authenticationMethod = null;
            string authenticationInstant = null;

            // Search for an Authentication Claim.
            IEnumerable<Claim> claimCollection = from c in tokenDescriptor.Subject.Claims where c.Type == ClaimTypes.AuthenticationMethod select c;
            if (claimCollection.Count<Claim>() > 0)
            {
                // We support only one authentication statement and hence we just pick the first authentication type
                // claim found in the claim collection. Since the spec allows multiple Auth Statements, 
                // we do not throw an error.
                authenticationMethod = new Uri(claimCollection.First<Claim>().Value);
            }

            claimCollection = from c in tokenDescriptor.Subject.Claims where c.Type == ClaimTypes.AuthenticationInstant select c;

            if (claimCollection.Count<Claim>() > 0)
                authenticationInstant = claimCollection.First<Claim>().Value;

            if (authenticationMethod == null && authenticationInstant == null)
                return null;
            else if (authenticationMethod == null)
                throw LogHelper.LogExceptionMessage(new Saml2SecurityTokenException("ID4270, AuthenticationMethod, SAML2"));
            else if (authenticationInstant == null)
                throw LogHelper.LogExceptionMessage(new Saml2SecurityTokenException("ID4270, AuthenticationInstant, SAML2"));

            Saml2AuthenticationContext authCtx = new Saml2AuthenticationContext(authenticationMethod);
            DateTime authInstantTime = DateTime.ParseExact(authenticationInstant, Saml2Constants.AcceptedDateTimeFormats, DateTimeFormatInfo.InvariantInfo, DateTimeStyles.None).ToUniversalTime();
            Saml2AuthenticationStatement authnStatement = new Saml2AuthenticationStatement(authCtx, authInstantTime);

            if (authInfo != null)
            {
                if (!string.IsNullOrEmpty(authInfo.DnsName)
                    || !string.IsNullOrEmpty(authInfo.Address))
                    authnStatement.SubjectLocality
                        = new Saml2SubjectLocality(authInfo.Address, authInfo.DnsName);

                if (!string.IsNullOrEmpty(authInfo.Session))
                    authnStatement.SessionIndex = authInfo.Session;

                authnStatement.SessionNotOnOrAfter = authInfo.NotOnOrAfter;
            }

            return authnStatement;
        }

        /// <summary>
        /// Creates a SAML2 subject of the assertion.
        /// </summary>
        /// <param name="tokenDescriptor">The security token descriptor to create the subject.</param>
        /// <exception cref="ArgumentNullException">Thrown when 'tokenDescriptor' is null.</exception>
        /// <returns>A Saml2Subject.</returns>
        protected virtual Saml2Subject CreateSamlSubject(SecurityTokenDescriptor tokenDescriptor)
        {
            if (null == tokenDescriptor)
                throw LogHelper.LogArgumentNullException(nameof(tokenDescriptor));

            var saml2Subject = new Saml2Subject();

            // Look for name identifier claims
            string nameIdentifierClaim = null;
            string nameIdentifierFormat = null;
            string nameIdentifierNameQualifier = null;
            string nameIdentifierSpProviderId = null;
            string nameIdentifierSpNameQualifier = null;

            if (tokenDescriptor.Subject != null && tokenDescriptor.Subject.Claims != null)
            {
                foreach (Claim claim in tokenDescriptor.Subject.Claims)
                {
                    if (claim.Type == ClaimTypes.NameIdentifier)
                    {
                        // Do not allow multiple name identifier claim.
                        if (null != nameIdentifierClaim)
                            throw LogHelper.LogExceptionMessage(new Saml2SecurityTokenException("ID4139"));

                        nameIdentifierClaim = claim.Value;
                        if (claim.Properties.ContainsKey(ClaimProperties.SamlNameIdentifierFormat))
                            nameIdentifierFormat = claim.Properties[ClaimProperties.SamlNameIdentifierFormat];

                        if (claim.Properties.ContainsKey(ClaimProperties.SamlNameIdentifierNameQualifier))
                            nameIdentifierNameQualifier = claim.Properties[ClaimProperties.SamlNameIdentifierNameQualifier];

                        if (claim.Properties.ContainsKey(ClaimProperties.SamlNameIdentifierSPNameQualifier))
                            nameIdentifierSpNameQualifier = claim.Properties[ClaimProperties.SamlNameIdentifierSPNameQualifier];

                        if (claim.Properties.ContainsKey(ClaimProperties.SamlNameIdentifierSPProvidedId))
                            nameIdentifierSpProviderId = claim.Properties[ClaimProperties.SamlNameIdentifierSPProvidedId];
                    }
                }
            }

            if (nameIdentifierClaim != null)
            {
                Saml2NameIdentifier nameIdentifier = new Saml2NameIdentifier(nameIdentifierClaim);
                if (nameIdentifierFormat != null && XmlUtil.CanCreateValidUri(nameIdentifierFormat, UriKind.Absolute))
                    nameIdentifier.Format = new Uri(nameIdentifierFormat);

                nameIdentifier.NameQualifier = nameIdentifierNameQualifier;
                nameIdentifier.SPNameQualifier = nameIdentifierSpNameQualifier;
                nameIdentifier.SPProvidedId = nameIdentifierSpProviderId;
                saml2Subject.NameId = nameIdentifier;
            }

            // Add subject confirmation data
            Saml2SubjectConfirmation subjectConfirmation;
            //if (null == tokenDescriptor.Proof)
            {
                subjectConfirmation = new Saml2SubjectConfirmation(Saml2Constants.ConfirmationMethods.Bearer);
            }
            // TODO - proof of possesion
            //else
            //{
            //    subjectConfirmation = new Saml2SubjectConfirmation(Saml2Constants.ConfirmationMethods.HolderOfKey, new Saml2SubjectConfirmationData());
            //    subjectConfirmation.SubjectConfirmationData.KeyIdentifiers.Add(tokenDescriptor.Proof.KeyIdentifier);
            //}

            saml2Subject.SubjectConfirmations.Add(subjectConfirmation);
            return saml2Subject;
        }

        /// <summary>
        /// Override this method to change the token encrypting credentials. 
        /// </summary>
        /// <param name="tokenDescriptor">Retrieve some scope encrypting credentials from the Scope object</param>
        /// <returns>the token encrypting credentials</returns>
        /// <exception cref="ArgumentNullException">When the given tokenDescriptor is null</exception>
        protected virtual EncryptingCredentials GetEncryptingCredentials(SecurityTokenDescriptor tokenDescriptor)
        {
            if (null == tokenDescriptor)
                throw LogHelper.LogArgumentNullException(nameof(tokenDescriptor));

            EncryptingCredentials encryptingCredentials = null;
            if (null != tokenDescriptor.EncryptingCredentials)
            {
                encryptingCredentials = tokenDescriptor.EncryptingCredentials;
                if (encryptingCredentials.Key is AsymmetricSecurityKey)
                    throw LogHelper.LogExceptionMessage(new Saml2SecurityTokenException("ID4178"));
            }

            return encryptingCredentials;
        }

        /// <summary>
        /// Gets the credentials for the signing the assertion.
        /// </summary>
        /// <remarks>
        /// <para>
        /// SAML2 assertions used as security tokens should be signed.
        /// </para>
        /// <para>
        /// The default implementation uses the 
        /// tokenDescriptor.Scope.SigningCredentials.
        /// </para>
        /// </remarks>
        /// <param name="tokenDescriptor">The token descriptor.</param>
        /// <returns>The signing credential.</returns>
        protected virtual SigningCredentials GetSigningCredentials(SecurityTokenDescriptor tokenDescriptor)
        {
            if (null == tokenDescriptor)
                throw LogHelper.LogArgumentNullException(nameof(tokenDescriptor));

            return tokenDescriptor.SigningCredentials;
        }

        /// <summary>
        /// Rejects tokens that are not valid. 
        /// </summary>
        /// <remarks>
        /// The token may not be valid for a number of reasons. For example, the 
        /// current time may not be within the token's validity period, the 
        /// token may contain data that is contradictory or not valid, or the token 
        /// may contain unsupported SAML2 elements.
        /// </remarks>
        /// <param name="conditions">SAML 2.0 condition to be validated.</param>
        /// <param name="enforceAudienceRestriction">True to check for Audience Restriction condition.</param>
        protected virtual void ValidateConditions(Saml2SecurityToken securityToken, TokenValidationParameters validationParameters)
        {
            if (securityToken == null)
                throw LogHelper.LogArgumentNullException(nameof(securityToken));

            if (validationParameters == null)
                throw LogHelper.LogArgumentNullException(nameof(validationParameters));

            if (securityToken.Assertion == null)
                throw LogHelper.LogArgumentNullException(nameof(securityToken.Assertion));

            if (securityToken.Assertion.Conditions != null)
            {
                DateTime now = DateTime.UtcNow;

                Validators.ValidateLifetime(securityToken.Assertion.Conditions.NotBefore, securityToken.Assertion.Conditions.NotOnOrAfter, securityToken, validationParameters);

                if (securityToken.Assertion.Conditions.OneTimeUse)
                    throw LogHelper.LogExceptionMessage(new SecurityTokenValidationException(LogMessages.IDX10510));

                if (securityToken.Assertion.Conditions.ProxyRestriction != null)
                    throw LogHelper.LogExceptionMessage(new SecurityTokenValidationException(LogMessages.IDX10511));
            }

            // TODO - concat all the audiences together
            foreach (var audienceRestriction in securityToken.Assertion.Conditions.AudienceRestrictions)
            {
                if (validationParameters.AudienceValidator != null)
                    validationParameters.AudienceValidator(audienceRestriction.Audiences, securityToken, validationParameters);
                else
                    Validators.ValidateAudience(audienceRestriction.Audiences, securityToken, validationParameters);
            }
        }

        // TODO - not sure what this is about
        ///// <summary>
        ///// Returns the Saml2 AuthenticationContext matching a normalized value.
        ///// </summary>
        ///// <param name="normalizedAuthenticationType">Normalized value.</param>
        ///// <returns>A string that represents the denormalized authentication type used to obtain the token.</returns>
        //protected virtual string DenormalizeAuthenticationType(string normalizedAuthenticationType)
        //{
        //    return AuthenticationTypeMaps.Denormalize(normalizedAuthenticationType, AuthenticationTypeMaps.Saml2);
        //}

        /// <summary>
        /// Throws if a token is detected as being replayed. If the token is not found, it is added to the 
        /// <see cref="TokenReplayCache" />.
        /// </summary>
        /// <param name="token">The token to detect for replay.</param>
        /// <exception cref="ArgumentNullException">The input argument 'token' is null.</exception>
        /// <exception cref="InvalidOperationException">Configuration or Configuration.TokenReplayCache property is null.</exception>
        /// <exception cref="ArgumentException">The input argument 'token' can not be cast as a 'Saml2SecurityToken'.</exception>
        /// <exception cref="SecurityTokenValidationException">The Saml2SecurityToken.Assertion.Id.Value is null or empty.</exception>
        /// <exception cref="SecurityTokenReplayDetectedException">The token is found in the <see cref="TokenReplayCache" />.</exception>
        /// <remarks>The default behavior is to only check tokens bearer tokens (tokens that do not have keys).</remarks>
        protected void DetectReplayedToken(SecurityToken token, TokenValidationParameters validationParameters)
        {
            if (token == null)
                throw LogHelper.LogArgumentNullException(nameof(token));

            Saml2SecurityToken samlToken = token as Saml2SecurityToken;
            if (null == samlToken)
                throw LogHelper.LogArgumentNullException("nameof(token)");

            if (string.IsNullOrEmpty(samlToken.Assertion.Id.Value))
                throw LogHelper.LogExceptionMessage(new SecurityTokenValidationException("ID1065"));

            StringBuilder stringBuilder = new StringBuilder();
            string key;
            using (HashAlgorithm hashAlgorithm = SHA256.Create())
            {
                if (string.IsNullOrEmpty(samlToken.Assertion.Issuer.Value))
                {
                    stringBuilder.AppendFormat("{0}{1}", samlToken.Assertion.Id.Value, _tokenTypeIdentifiers[0]);
                }
                else
                {
                    stringBuilder.AppendFormat("{0}{1}{2}", samlToken.Assertion.Id.Value, samlToken.Assertion.Issuer.Value, _tokenTypeIdentifiers[0]);
                }

                key = Convert.ToBase64String(hashAlgorithm.ComputeHash(Encoding.UTF8.GetBytes(stringBuilder.ToString())));

                // TODO - check cache 
            }
        }

        // TODO - do we need to normalize ?
        ///// <summary>
        ///// Returns the normalized value matching a SAML2 AuthenticationContext class reference.
        ///// </summary>
        ///// <param name="saml2AuthenticationContextClassReference">A string representing the <see cref="Saml2Constants.AuthenticationContextClasses"/></param>
        ///// <returns>Normalized value.</returns>
        //protected virtual string NormalizeAuthenticationContextClassReference(string saml2AuthenticationContextClassReference)
        //{
        //    return AuthenticationTypeMaps.Normalize(saml2AuthenticationContextClassReference, AuthenticationTypeMaps.Saml2);
        //}


        /// <summary>
        /// This method gets called when a special type of Saml2Attribute is detected. The Saml2Attribute passed in 
        /// wraps a Saml2Attribute that contains a collection of AttributeValues, each of which will get mapped to a 
        /// claim.  All of the claims will be returned in an ClaimsIdentity with the specified issuer.
        /// </summary>
        /// <param name="attribute">The <see cref="Saml2Attribute"/> to use.</param>
        /// <param name="subject">The <see cref="ClaimsIdentity"/> that is the subject of this token.</param>
        /// <param name="issuer">The issuer of the claim.</param>
        /// <exception cref="InvalidOperationException">Will be thrown if the Saml2Attribute does not contain any 
        /// valid Saml2AttributeValues.
        /// </exception>
        protected virtual void SetDelegateFromAttribute(Saml2Attribute attribute, ClaimsIdentity subject, string issuer)
        {
            // bail here; nothing to add.
            if (subject == null || attribute == null || attribute.Values == null || attribute.Values.Count < 1)
            {
                return;
            }

            Saml2Attribute actingAsAttribute = null;
            Collection<Claim> claims = new Collection<Claim>();

            foreach (string attributeValue in attribute.Values)
            {
                if (attributeValue != null)
                {
                    using (XmlDictionaryReader dicReader = XmlDictionaryReader.CreateTextReader(Encoding.UTF8.GetBytes(attributeValue), XmlDictionaryReaderQuotas.Max))
                    {
                        dicReader.MoveToContent();
                        dicReader.ReadStartElement(Actor);

                        while (dicReader.IsStartElement(Saml2Constants.Elements.Attribute))
                        {
                            Saml2Attribute innerAttribute = Serializer.ReadAttribute(dicReader);
                            if (innerAttribute != null)
                            {
                                if (innerAttribute.Name == ClaimTypes.Actor)
                                {
                                    // In this case, we have two delegates acting as an identity: we do not allow this.
                                    if (actingAsAttribute != null)
                                        throw LogHelper.LogExceptionMessage(new Saml2SecurityTokenException(LogMessages.IDX11142));

                                    actingAsAttribute = innerAttribute;
                                }
                                else
                                {
                                    string originalIssuer = innerAttribute.OriginalIssuer;
                                    for (int k = 0; k < innerAttribute.Values.Count; ++k)
                                    {
                                        Claim claim = null;
                                        if (string.IsNullOrEmpty(originalIssuer))
                                        {
                                            claim = new Claim(innerAttribute.Name, innerAttribute.Values[k], innerAttribute.AttributeValueXsiType, issuer);
                                        }
                                        else
                                        {
                                            claim = new Claim(innerAttribute.Name, innerAttribute.Values[k], innerAttribute.AttributeValueXsiType, issuer, originalIssuer);
                                        }

                                        if (innerAttribute.NameFormat != null)
                                        {
                                            claim.Properties[ClaimProperties.SamlAttributeNameFormat] = innerAttribute.NameFormat.AbsoluteUri;
                                        }

                                        if (innerAttribute.FriendlyName != null)
                                        {
                                            claim.Properties[ClaimProperties.SamlAttributeDisplayName] = innerAttribute.FriendlyName;
                                        }

                                        claims.Add(claim);
                                    }
                                }
                            }
                        }

                        dicReader.ReadEndElement(); // Actor
                    }
                }
            }

            // TODO - what should the authenticationType be, call tokenvalidationParameters.CreateClaimsIdentity
            subject.Actor = new ClaimsIdentity(claims);
            SetDelegateFromAttribute(actingAsAttribute, subject.Actor, issuer);
        }

        /// <summary>
        /// Processes all statements to generate claims.
        /// </summary>
        /// <param name="statements">A collection of Saml2Statement.</param>
        /// <param name="subject">The subject.</param>
        /// <param name="issuer">The issuer.</param>
        protected virtual void ProcessStatements(Collection<Saml2Statement> statements, ClaimsIdentity subject, string issuer)
        {
            Collection<Saml2AuthenticationStatement> authnStatements = new Collection<Saml2AuthenticationStatement>();

            foreach (Saml2Statement statement in statements)
            {
	            if (statement is Saml2AttributeStatement attrStatement)
		            ProcessAttributeStatement(attrStatement, subject, issuer);
	            else if (statement is Saml2AuthenticationStatement authnStatement)
		            authnStatements.Add(authnStatement);
	            else if (statement is Saml2AuthorizationDecisionStatement authzStatement)
		            ProcessAuthorizationDecisionStatement(authzStatement, subject, issuer);

	            // We don't process custom statements. Just fall through.
            }

            foreach (Saml2AuthenticationStatement authStatement in authnStatements)
            {
                if (authStatement != null)
                    ProcessAuthenticationStatement(authStatement, subject, issuer);
            }
        }

        /// <summary>
        /// Creates claims from the Saml2Subject.
        /// </summary>
        /// <param name="assertionSubject">The Saml2Subject.</param>
        /// <param name="subject">The ClaimsIdentity subject.</param>
        /// <param name="issuer">The issuer.</param>
        protected virtual void ProcessSamlSubject(Saml2Subject assertionSubject, ClaimsIdentity subject, string issuer)
        {
            if (assertionSubject == null)
                throw LogHelper.LogArgumentNullException(nameof(assertionSubject));

            if (subject == null)
                throw LogHelper.LogArgumentNullException(nameof(subject));

            Saml2NameIdentifier nameId = assertionSubject.NameId;
            if (nameId != null)
            {
                var claim = new Claim(ClaimTypes.NameIdentifier, nameId.Value, ClaimValueTypes.String, issuer);
                if (nameId.Format != null)
                    claim.Properties[ClaimProperties.SamlNameIdentifierFormat] = nameId.Format.AbsoluteUri;

                if (nameId.NameQualifier != null)
                    claim.Properties[ClaimProperties.SamlNameIdentifierNameQualifier] = nameId.NameQualifier;

                if (nameId.SPNameQualifier != null)
                    claim.Properties[ClaimProperties.SamlNameIdentifierSPNameQualifier] = nameId.SPNameQualifier;

                if (nameId.SPProvidedId != null)
                    claim.Properties[ClaimProperties.SamlNameIdentifierSPProvidedId] = nameId.SPProvidedId;

                subject.AddClaim(claim);
            }
        }

        /// <summary>
        /// Creates claims from a Saml2AttributeStatement.
        /// </summary>
        /// <param name="statement">The Saml2AttributeStatement.</param>
        /// <param name="subject">The subject.</param>
        /// <param name="issuer">The issuer.</param>
        protected virtual void ProcessAttributeStatement(Saml2AttributeStatement statement, ClaimsIdentity subject, string issuer)
        {
            if (statement == null)
                throw LogHelper.LogArgumentNullException(nameof(statement));

            if (subject == null)
                throw LogHelper.LogArgumentNullException(nameof(subject));

            foreach (Saml2Attribute attribute in statement.Attributes)
            {
                if (StringComparer.Ordinal.Equals(attribute.Name, ClaimTypes.Actor))
                {
                    // TODO - should we support nested Actors?
                    if (subject.Actor != null)
                        throw LogHelper.LogExceptionMessage(new Saml2SecurityTokenException(LogMessages.IDX10512));

                    SetDelegateFromAttribute(attribute, subject, issuer);
                }
                else
                {
                    foreach (string value in attribute.Values)
                    {
                        if (value != null)
                        {
                            string originalIssuer = attribute.OriginalIssuer ?? issuer;
                            var claim = new Claim(attribute.Name, value, attribute.AttributeValueXsiType, issuer, originalIssuer);
                            if (attribute.NameFormat != null)
                                claim.Properties[ClaimProperties.SamlAttributeNameFormat] = attribute.NameFormat.AbsoluteUri;

                            if (attribute.FriendlyName != null)
                                claim.Properties[ClaimProperties.SamlAttributeDisplayName] = attribute.FriendlyName;

                            subject.AddClaim(claim);
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Creates claims from a Saml2AuthenticationStatement.
        /// </summary>
        /// <param name="statement">The Saml2AuthenticationStatement.</param>
        /// <param name="subject">The subject.</param>
        /// <param name="issuer">The issuer.</param>
        protected virtual void ProcessAuthenticationStatement(Saml2AuthenticationStatement statement, ClaimsIdentity subject, string issuer)
        {
            if (subject == null)
                throw LogHelper.LogArgumentNullException(nameof(subject));

            if (statement.AuthenticationContext.DeclarationReference != null)
                throw LogHelper.LogExceptionMessage(new Saml2SecurityTokenException(LogMessages.IDX14001));

            if (statement.AuthenticationContext.ClassReference != null)
            {
                subject.AddClaim(
                        new Claim(
                            ClaimTypes.AuthenticationMethod,
                            statement.AuthenticationContext.ClassReference.AbsoluteUri,
                            ClaimValueTypes.String,
                            issuer));
            }

            subject.AddClaim(new Claim(ClaimTypes.AuthenticationInstant, XmlConvert.ToString(statement.AuthenticationInstant.ToUniversalTime(), Saml2Constants.GeneratedDateTimeFormat), ClaimValueTypes.DateTime, issuer));
        }

        /// <summary>
        /// Creates claims from a Saml2AuthorizationDecisionStatement.
        /// </summary>
        /// <param name="statement">The Saml2AuthorizationDecisionStatement.</param>
        /// <param name="subject">The subject.</param>
        /// <param name="issuer">The issuer.</param>
        /// <remarks>Provided for extensibility. By default no claims are created.</remarks>
        protected virtual void ProcessAuthorizationDecisionStatement(Saml2AuthorizationDecisionStatement statement, ClaimsIdentity subject, string issuer)
        {
        }


        /// <summary>
        /// Creates claims from a Saml2 token.
        /// </summary>
        /// <param name="samlToken">The Saml2SecurityToken.</param>
        /// <param name="validationParameters">creates the <see cref="ClaimsIdentity"/> using <see cref="TokenValidationParameters.CreateClaimsIdentity(SecurityToken, string)"/>.</param>
        /// <returns>A <see cref="ClaimsIdentity"/> with claims from the saml statements.</returns>
        protected virtual ClaimsIdentity CreateClaims(Saml2SecurityToken samlToken, TokenValidationParameters validationParameters)
        {
            if (samlToken == null)
                throw LogHelper.LogArgumentNullException(nameof(samlToken));

            Saml2Assertion assertion = samlToken.Assertion;
            if (assertion == null)
                throw LogHelper.LogArgumentNullException(LogMessages.IDX11110);

            if (string.IsNullOrEmpty(assertion.Issuer.Value))
                throw LogHelper.LogExceptionMessage(new Saml2SecurityTokenException(LogMessages.IDX11111));

            var identity = validationParameters.CreateClaimsIdentity(samlToken, assertion.Issuer.Value);
            ProcessSamlSubject(assertion.Subject, identity, assertion.Issuer.Value);
            ProcessStatements(assertion.Statements, identity, assertion.Issuer.Value);

            return identity;
        }

        /// <summary>
        /// Resolves the collection of <see cref="SecurityKey"/> referenced in a <see cref="Saml2Assertion"/>.
        /// </summary>
        /// <param name="assertion"><see cref="Saml2Assertion"/> to process.</param>
        /// <param name="resolver"><see cref="SecurityTokenResolver"/> to use in resolving the <see cref="SecurityKey"/>.</param>
        /// <returns>A read only collection of <see cref="SecurityKey"/> contained in the assertion.</returns>
        protected virtual ICollection<SecurityKey> ResolveSecurityKeys(Saml2Assertion assertion, TokenValidationParameters validationParameters)
        {
            if (null == assertion)
                throw LogHelper.LogArgumentNullException(nameof(assertion));

            // Must have Subject
            Saml2Subject subject = assertion.Subject;
            if (null == subject)
                // No Subject
                throw LogHelper.LogExceptionMessage(new Saml2SecurityTokenException(LogMessages.IDX11143));

            // Must have one SubjectConfirmation
            if (0 == subject.SubjectConfirmations.Count)
                // No SubjectConfirmation
                throw LogHelper.LogExceptionMessage(new Saml2SecurityTokenException(LogMessages.IDX11144));

            if (subject.SubjectConfirmations.Count > 1)
                // More than one SubjectConfirmation
                throw LogHelper.LogExceptionMessage(new Saml2SecurityTokenException(LogMessages.IDX11145));

            // Extract the keys for the given method
            Collection<SecurityKey> securityKeys;
            var subjectConfirmation = subject.SubjectConfirmations[0];

            // For bearer, ensure there are no keys, set the collection to empty
            // For HolderOfKey, ensure there is at least one key, resolve and create collection
            if (Saml2Constants.ConfirmationMethods.Bearer == subjectConfirmation.Method)
            {
                if (null != subjectConfirmation.SubjectConfirmationData
                    && 0 != subjectConfirmation.SubjectConfirmationData.KeyIdentifiers.Count)
                {
                    // Bearer but has keys
                    throw LogHelper.LogExceptionMessage(new SecurityTokenException(LogMessages.IDX11146));
                }

                securityKeys = new Collection<SecurityKey>();
            }
            else if (Saml2Constants.ConfirmationMethods.HolderOfKey == subjectConfirmation.Method)
            {
                if (null == subjectConfirmation.SubjectConfirmationData
                    || 0 == subjectConfirmation.SubjectConfirmationData.KeyIdentifiers.Count)
                {
                    // Holder-of-key but no keys
                    throw LogHelper.LogExceptionMessage(new SecurityTokenException(LogMessages.IDX11147));
                }

                securityKeys = new Collection<SecurityKey>();
                //List<SecurityKey> holderKeys = new List<SecurityKey>();
                //SecurityKey key;

                // TODO - SecurityKey serialization / deserialization
                //foreach (SecurityKeyIdentifier keyIdentifier in subjectConfirmation.SubjectConfirmationData.KeyIdentifiers)
                //{
                //    key = null;

                //    // Try the resolver first
                //    foreach (SecurityKeyIdentifierClause clause in keyIdentifier)
                //    {
                //        if (null != resolver
                //            && resolver.TryResolveSecurityKey(clause, out key))
                //        {
                //            holderKeys.Add(key);
                //            break;
                //        }
                //    }

                //    // If that doesn't work, try to create the key (e.g. bare RSA or X509 raw)
                //    if (null == key)
                //    {
                //        if (keyIdentifier.CanCreateKey)
                //        {
                //            key = keyIdentifier.CreateKey();
                //            holderKeys.Add(key);
                //        }
                //        else
                //        {
                //            holderKeys.Add(new SecurityKeyElement(keyIdentifier, resolver));
                //        }
                //    }
                //}

                //securityKeys = holderKeys.AsReadOnly();
            }
            else
            {
                // SenderVouches, as well as other random things, aren't accepted
                throw LogHelper.LogExceptionMessage(new Saml2SecurityTokenException(LogHelper.FormatInvariant(LogMessages.IDX11148, subjectConfirmation.Method)));
            }

            return securityKeys;
        }

        /// <summary>
        /// Resolves the Signing Key Identifier to a SecurityToken.
        /// </summary>
        /// <param name="assertion">The Assertion for which the Issuer token is to be resolved.</param>
        /// <param name="issuerResolver">The current SecurityTokenResolver associated with this handler.</param>
        /// <returns>Instance of SecurityToken</returns>
        /// <exception cref="ArgumentNullException">Input parameter 'assertion' is null.</exception>
        /// <exception cref="SecurityTokenException">Unable to resolve token.</exception>
        protected virtual SecurityKey ResolveIssuerKey(Saml2Assertion assertion, TokenValidationParameters validationParameters)
        {
            if (null == assertion)
                throw LogHelper.LogArgumentNullException(nameof(assertion));

            if (TryResolveIssuerToken(assertion, validationParameters, out SecurityKey key))
	            return key;
            else
                throw LogHelper.LogExceptionMessage(new Saml2SecurityTokenException("cannot resolve key"));
        }

        /// <summary>
        /// Resolves the Signing Key Identifier to a SecurityToken.
        /// </summary>
        /// <param name="assertion">The Assertion for which the Issuer token is to be resolved.</param>
        /// <param name="issuerResolver">The current SecurityTokenResolver associated with this handler.</param>
        /// <param name="token">Resolved token.</param>
        /// <returns>True if token is resolved.</returns>
        protected virtual bool TryResolveIssuerToken(Saml2Assertion assertion, TokenValidationParameters validationParameters, out SecurityKey key)
        {
            // TODO - resolve the key;
            if (null == assertion)
                throw LogHelper.LogArgumentNullException(nameof(assertion));

            if (null == validationParameters)
                throw LogHelper.LogArgumentNullException(nameof(validationParameters));

            key = null;
            return false;
        }

        /// <summary>
        /// Determines if the audience found in a <see cref="Saml2SecurityToken"/> is valid.
        /// </summary>
        /// <param name="audiences">The audiences found in the <see cref="Saml2SecurityToken"/></param>
        /// <param name="securityToken">The <see cref="Saml2SecurityToken"/> that is being validated.</param>
        /// <param name="validationParameters"><see cref="TokenValidationParameters"/> required for validation.</param>
        /// <remarks><see cref="Validators.ValidateAudience(IEnumerable{string}, SecurityToken, TokenValidationParameters)"/> for additional details.</remarks>
        protected virtual void ValidateAudience(IEnumerable<string> audiences, SecurityToken securityToken, TokenValidationParameters validationParameters)
        {
            Validators.ValidateAudience(audiences, securityToken, validationParameters);
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
            if (validationParameters == null)
                throw LogHelper.LogArgumentNullException(nameof(validationParameters));

            return Validators.ValidateIssuer(issuer, securityToken, validationParameters);
        }

        /// <summary>
        /// When encrypted SAML 2.0 token is received, the credentials that are used
        /// to encrypt the token will be hydrated as a ReceivedEncryptingCredentials.
        /// This is to distinguish the case between a user explicitly setting an 
        /// encrypting credentials and a re-serialize case where a received token
        /// is re-serialized by a proxy to a backend service, in which case the token 
        /// should not be encrypted.
        /// </summary>
        internal class ReceivedEncryptingCredentials : EncryptingCredentials
        {
            /// <summary>
            /// Constructs an ReceivedEncryptingCredentials with a security key, a security key identifier and
            /// the encryption algorithm.
            /// </summary>
            /// <param name="key">A security key for encryption.</param>
            /// <param name="keyIdentifier">A security key identifier for the encryption key.</param>
            /// <param name="algorithm">The encryption algorithm.</param>
            public ReceivedEncryptingCredentials(SecurityKey key, string algorithm, string enc)
                : base(key, algorithm, enc)
            {
            }
        }
    }
}
