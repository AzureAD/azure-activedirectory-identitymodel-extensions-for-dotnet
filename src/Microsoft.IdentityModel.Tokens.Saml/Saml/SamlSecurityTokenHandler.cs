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
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Xml;
using Microsoft.IdentityModel.Logging;
using static Microsoft.IdentityModel.Logging.LogHelper;

using TokenLogMessages = Microsoft.IdentityModel.Tokens.LogMessages;

namespace Microsoft.IdentityModel.Tokens.Saml
{
    /// <summary>
    /// A <see cref="SecurityTokenHandler"/> designed for creating and validating Saml Tokens,
    /// which supports validating tokens passed as strings using <see cref="TokenValidationParameters"/>.
    /// </summary>
    ///
    public class SamlSecurityTokenHandler : SecurityTokenHandler, ISecurityTokenValidator
    {
        internal const string Actor = "Actor";

        private int _defaultTokenLifetimeInMinutes = DefaultTokenLifetimeInMinutes;
        private int _maximumTokenSizeInBytes = TokenValidationParameters.DefaultMaximumTokenSizeInBytes;
        private static string[] _tokenTypeIdentifiers = new string[] { SamlConstants.Namespace, SamlConstants.OasisWssSamlTokenProfile11 };

        /// <summary>
        /// Default lifetime of tokens created. When creating tokens, if 'expires' and 'notbefore' are both null, then a default will be set to: expires = DateTime.UtcNow, notbefore = DateTime.UtcNow + TimeSpan.FromMinutes(TokenLifetimeInMinutes).
        /// </summary>
        public static readonly int DefaultTokenLifetimeInMinutes = 60;

        /// <summary>
        /// Initializes an instance of <see cref="SamlSecurityTokenHandler"/>.
        /// </summary>
        public SamlSecurityTokenHandler()
        {
        }

#region fields
        /// <summary>
        /// Gets a value indicating whether this handler supports validation of tokens
        /// handled by this instance.
        /// </summary>v
        /// <returns>'true' if the instance is capable of SecurityToken
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
        /// Gets or sets the maximum size in bytes, that a will be processed.
        /// </summary>
        /// <exception cref="ArgumentOutOfRangeException">'value' less than 1.</exception>
        public int MaximumTokenSizeInBytes
        {
            get { return _maximumTokenSizeInBytes; }
            set
            {
                if (value < 1)
                    throw LogExceptionMessage(new ArgumentOutOfRangeException(nameof(value), FormatInvariant(TokenLogMessages.IDX10101, value)));

                _maximumTokenSizeInBytes = value;
            }
        }

        /// <summary>
        /// Gets or set the <see cref="SamlSerializer"/> that will be used to read and write a <see cref="SamlSecurityToken"/>.
        /// </summary>
        public SamlSerializer Serializer { get; set; } = new SamlSerializer();

        /// <summary>
        /// Gets or sets a bool that controls if token creation will set default 'NotBefore', 'NotOnOrAfter' and 'IssueInstant' if not specified.
        /// </summary>
        /// <remarks>See: <see cref="DefaultTokenLifetimeInMinutes"/>, <see cref="TokenLifetimeInMinutes"/> for defaults and configuration.</remarks>
        [DefaultValue(true)]
        public bool SetDefaultTimesOnTokenCreation { get; set; } = true;

        /// <summary>
        /// Gets or sets the token lifetime in minutes.
        /// </summary>
        /// <remarks>Used by <see cref="CreateToken(SecurityTokenDescriptor)"/> to set the default expiration ('exp'). <see cref="DefaultTokenLifetimeInMinutes"/> for the default.</remarks>
        /// <exception cref="ArgumentOutOfRangeException">'value' less than 1.</exception>
        public int TokenLifetimeInMinutes
        {
            get { return _defaultTokenLifetimeInMinutes; }
            set
            {
                if (value < 1)
                    throw LogExceptionMessage(new ArgumentOutOfRangeException(nameof(value), FormatInvariant(TokenLogMessages.IDX10104, value)));

                _defaultTokenLifetimeInMinutes = value;
            }
        }

        /// <summary>
        /// Gets the securityToken type supported by this handler.
        /// </summary>
        public override Type TokenType
        {
            get { return typeof(SamlSecurityToken); }
        }

        #endregion fields

#region methods
        /// <summary>
        /// Adds all Actors.
        /// </summary>
        /// <param name="subject"><see cref="ICollection{SamlAttribute}"/>.</param>
        /// <param name="attributes">Attribute collection to which the Actor added.</param>
        protected virtual void AddActorToAttributes(ICollection<SamlAttribute> attributes, ClaimsIdentity subject)
        {
            if (attributes == null)
                throw LogArgumentNullException(nameof(attributes));

            if (subject == null)
                return;

            var actorAttributes = new Collection<SamlAttribute>();
            foreach (var claim in subject.Claims)
            {
                if (claim != null)
                    actorAttributes.Add(CreateAttribute(claim));
            }

            // perform depth first recursion
            AddActorToAttributes(attributes, subject.Actor);

            var collectedAttributes = ConsolidateAttributes(actorAttributes);
            attributes.Add(CreateAttribute(new Claim(ClaimTypes.Actor, CreateXmlStringFromAttributes(collectedAttributes))));
        }

        /// <summary>
        /// Determines if the string is a valid Saml token by examining the xml for the correct start element.
        /// </summary>
        /// <param name="securityToken">A Saml token as a string.</param>
        /// <returns>'true' if the string has a start element equal <see cref="SamlConstants.Elements.Assertion"/>.</returns>
        public override bool CanReadToken(string securityToken)
        {
            if (string.IsNullOrWhiteSpace(securityToken) || securityToken.Length > MaximumTokenSizeInBytes)
                return false;

            try
            {
                using (var sr = new StringReader(securityToken))
                {
                    using (var reader = XmlDictionaryReader.CreateDictionaryReader(XmlReader.Create(sr)))
                    {
                        return CanReadToken(reader);
                    }
                }
            }
            catch (Exception)
            {
                return false;
            }
        }

        /// <summary>
        /// Indicates whether the current XML element can be read as a token of the type handled by this instance.
        /// </summary>
        /// <param name="reader">An <see cref="XmlReader"/> reader positioned at a start element. The reader should not be advanced.</param>
        /// <returns>'true' if <see cref="SamlSecurityTokenHandler.ReadToken(string)"/> can read the element.</returns>
        public bool CanReadToken(XmlReader reader)
        {
            if (reader == null)
                return false;

            return reader.IsStartElement(SamlConstants.Elements.Assertion, SamlConstants.Namespace);
        }

        /// <summary>
        /// Collects attributes with a common claim type, claim value type, and original issuer into a single attribute with multiple values.
        /// </summary>
        /// <param name="attributes"><see cref="ICollection{SamlAttribute}"/> to consolidate.</param>
        /// <returns><see cref="ICollection{SamlAttribute}"/>common attributes collected into value lists.</returns>
        protected virtual ICollection<SamlAttribute> ConsolidateAttributes(ICollection<SamlAttribute> attributes)
        {
            var distinctAttributes = new Dictionary<SamlAttributeKeyComparer.AttributeKey, SamlAttribute>(attributes.Count, new SamlAttributeKeyComparer());
            foreach (var attribute in attributes)
            {
                // Use unique attribute if name, value type, or issuer differ
                var attributeKey = new SamlAttributeKeyComparer.AttributeKey(attribute);
                if (distinctAttributes.ContainsKey(attributeKey))
                {
                    foreach (var attributeValue in attribute.Values)
                        distinctAttributes[attributeKey].Values.Add(attributeValue);
                }
                else
                {
                    distinctAttributes.Add(attributeKey, attribute);
                }
            }

            return distinctAttributes.Values;
        }

        /// <summary>
        /// Override this method to provide a SamlAdvice to place in the Samltoken. 
        /// </summary>
        /// <param name="tokenDescriptor">Contains information about the token.</param>
        /// <returns>SamlAdvice, default is null.</returns>
        protected virtual SamlAdvice CreateAdvice(SecurityTokenDescriptor tokenDescriptor)
        {
            return null;
        }

        // TODO - introduce a delegate to return the ns / name pair
        /// <summary>
        /// Generates a SamlAttribute from a claim.
        /// </summary>
        /// <param name="claim">Claim from which to generate a SamlAttribute.</param>
        /// <returns><see cref="SamlAttribute"/></returns>
        /// <exception cref="ArgumentNullException">The parameter 'claim' is null.</exception>
        protected virtual SamlAttribute CreateAttribute(Claim claim)
        {
            if (claim == null)
                LogArgumentNullException(nameof(claim));

            // A SamlAttribute 1.0 is required to have the attributeNamespace and attributeName be non-null and non-empty.
            string claimType = claim.Type;

            int lastSlashIndex = claimType.LastIndexOf('/');
            if ((lastSlashIndex == 0) || (lastSlashIndex == -1))
                throw LogExceptionMessage(new SamlSecurityTokenException($"claimType, ID4215, claim.Type: {claimType}"));

            // TODO - see if there is another slash before this one.
            if (lastSlashIndex == claim.Type.Length - 1)
                throw LogExceptionMessage(new SamlSecurityTokenException($"claimType, ID4216, claim.Type: {claimType}"));

            return new SamlAttribute(
                claimType.Substring(0, lastSlashIndex),
                claimType.Substring(lastSlashIndex + 1, claimType.Length - (lastSlashIndex + 1)),
                new string[] { claim.Value })
            {
                OriginalIssuer = claim.OriginalIssuer,
                AttributeValueXsiType = claim.ValueType
            };
        }

        /// <summary>
        /// Creates SamlAttributeStatements and adds them to a collection.
        /// Override this method to provide a custom implementation.
        /// <para>
        /// Default behavior is to create a new SamlAttributeStatement for each Subject in the tokenDescriptor.Subjects collection.
        /// </para>
        /// </summary>
        /// <param name="subject">The SamlSubject to use in the SamlAttributeStatement that are created.</param>
        /// <param name="tokenDescriptor">Contains all the other information that is used in token issuance.</param>
        /// <returns>SamlAttributeStatement</returns>
        /// <exception cref="ArgumentNullException">Thrown when 'samlSubject' is null.</exception>
        protected virtual SamlAttributeStatement CreateAttributeStatement(SamlSubject subject, SecurityTokenDescriptor tokenDescriptor)
        {

            if (subject == null)
                LogArgumentNullException(nameof(subject));

            if (tokenDescriptor == null)
                LogArgumentNullException(nameof(tokenDescriptor));

            if (tokenDescriptor.Subject != null)
            {
                var attributes = new List<SamlAttribute>();
                foreach (var claim in tokenDescriptor.Subject.Claims)
                {
                    if (claim != null && claim.Type != ClaimTypes.NameIdentifier)
                    {
                        //
                        // NameIdentifier claim is already processed while creating the samlsubject
                        // AuthenticationInstant and AuthenticationType are not converted to Claims
                        //
                        switch (claim.Type)
                        {
                            case ClaimTypes.AuthenticationInstant:
                            case ClaimTypes.AuthenticationMethod:
                                break;
                            default:
                                attributes.Add(CreateAttribute(claim));
                                break;
                        }
                    }
                }

                AddActorToAttributes(attributes, tokenDescriptor.Subject.Actor);

                var consolidatedAttributes = ConsolidateAttributes(attributes);
                if (consolidatedAttributes.Count > 0)
                {
                    return new SamlAttributeStatement(subject, consolidatedAttributes);
                }
            }

            return null;
        }

        /// <summary>
        /// Creates a SamlAuthenticationStatement for each AuthenticationInformation found in AuthenticationInformation. 
        /// Override this method to provide a custom implementation.
        /// </summary>
        /// <param name="subject">The SamlSubject of the Statement.</param>
        /// <param name="tokenDescriptor">Contains all the other information that is used in token issuance.</param>
        /// <returns>SamlAuthenticationStatement</returns>
        /// <exception cref="ArgumentNullException">Thrown when 'samlSubject' or 'authInfo' is null.</exception>
        protected virtual SamlAuthenticationStatement CreateAuthenticationStatement(SamlSubject subject, SecurityTokenDescriptor tokenDescriptor)
        {
            if (subject == null)
                throw LogArgumentNullException(nameof(subject));

            if (tokenDescriptor == null)
                throw LogArgumentNullException(nameof(tokenDescriptor));

            if (tokenDescriptor.Subject == null)
                return null;

            string authenticationMethod = null;
            string authenticationInstant = null;

            // Search for an Authentication Claim.
            var claimCollection = (from c in tokenDescriptor.Subject.Claims
                                   where c.Type == ClaimTypes.AuthenticationMethod
                                   select c);
            if (claimCollection.Count<Claim>() > 0)
            {
                // We support only one authentication statement and hence we just pick the first authentication type
                // claim found in the claim collection. Since the spec allows multiple Auth Statements 
                // we do not throw an error.
                authenticationMethod = claimCollection.First<Claim>().Value;
            }

            claimCollection = (from c in tokenDescriptor.Subject.Claims
                               where c.Type == ClaimTypes.AuthenticationInstant
                               select c);
            if (claimCollection.Count<Claim>() > 0)
                authenticationInstant = claimCollection.First<Claim>().Value;

            if (authenticationMethod == null && authenticationInstant == null)
                return null;
            else if (authenticationMethod == null)
                throw LogExceptionMessage(new SamlSecurityTokenException("ID4270, AuthenticationMethod, SAML11"));
            else if (authenticationInstant == null)
                throw LogExceptionMessage(new SamlSecurityTokenException("ID4270, AuthenticationMethod, SAML11"));

            var authInstantTime = DateTime.ParseExact(authenticationInstant,
                                                      SamlConstants.AcceptedDateTimeFormats,
                                                      DateTimeFormatInfo.InvariantInfo,
                                                      DateTimeStyles.None).ToUniversalTime();
            // we need to add authInfo
            //if (authInfo == null)
            //{
            return new SamlAuthenticationStatement(subject, authenticationMethod, authInstantTime, null, null, null);
            //}
            //else
            //{
            //    return new SamlAuthenticationStatement(subject, authenticationMethod, authInstantTime, authInfo.DnsName, authInfo.Address, null);
            //}
        }

        /// <summary>
        /// Creates claims from a Saml securityToken.
        /// </summary>
        /// <param name="samlToken">A <see cref="SamlSecurityToken"/> that will be used to create the claims.</param>
        /// <param name="issuer">The value to set <see cref="Claim.Issuer"/></param>
        /// <param name="validationParameters"> Contains parameters for validating the securityToken.</param>
        /// <returns>A <see cref="ClaimsIdentity"/> containing the claims from the <see cref="SamlSecurityToken"/>.</returns>
        protected virtual ClaimsIdentity CreateClaimsIdentity(SamlSecurityToken samlToken, string issuer, TokenValidationParameters validationParameters)
        {
            if (samlToken == null)
                throw LogArgumentNullException(nameof(samlToken));

            if (samlToken.Assertion == null)
                throw LogArgumentNullException(LogMessages.IDX11110);

            var actualIssuer = issuer;
            if (string.IsNullOrWhiteSpace(issuer))
            {
                IdentityModelEventSource.Logger.WriteVerbose(TokenLogMessages.IDX10244, ClaimsIdentity.DefaultIssuer);
                actualIssuer = ClaimsIdentity.DefaultIssuer;
            }

            return validationParameters.CreateClaimsIdentity(samlToken, actualIssuer);
        }

        /// <summary>
        /// Generates all the conditions for saml
        /// </summary>
        /// <param name="tokenDescriptor">information that is used in token issuance.</param>
        /// <returns>SamlConditions</returns>
        protected virtual SamlConditions CreateConditions(SecurityTokenDescriptor tokenDescriptor)
        {
            if (null == tokenDescriptor)
                throw LogArgumentNullException(nameof(tokenDescriptor));

            var conditions = new SamlConditions();
            if (tokenDescriptor.IssuedAt.HasValue)
                conditions.NotBefore = tokenDescriptor.IssuedAt.Value;

            if (tokenDescriptor.Expires.HasValue)
                conditions.NotOnOrAfter = tokenDescriptor.Expires.Value;

            if (!string.IsNullOrEmpty(tokenDescriptor.Audience))
                conditions.Conditions.Add(new SamlAudienceRestrictionCondition(new string[] { tokenDescriptor.Audience }));

            return conditions;
        }

        /// <summary>
        /// Generates an enumeration of SamlStatements from a SecurityTokenDescriptor.
        /// Only SamlAttributeStatements and SamlAuthenticationStatements are generated.
        /// Overwrite this method to customize the creation of statements.
        /// <para>
        /// Calls in order (all are virtual):
        /// 1. CreateSamlSubject
        /// 2. CreateAttributeStatements
        /// 3. CreateAuthenticationStatements
        /// </para>
        /// </summary>
        /// <param name="tokenDescriptor">The SecurityTokenDescriptor to use to build the statements.</param>
        /// <returns>An enumeration of SamlStatement.</returns>
        protected virtual ICollection<SamlStatement> CreateStatements(SecurityTokenDescriptor tokenDescriptor)
        {
            if (null == tokenDescriptor)
                throw LogArgumentNullException(nameof(tokenDescriptor));

            var statements = new Collection<SamlStatement>();
            var subject = CreateSubject(tokenDescriptor);
            var attributeStatement = CreateAttributeStatement(subject, tokenDescriptor);
            if (attributeStatement != null)
                statements.Add(attributeStatement);

            var authnStatement = CreateAuthenticationStatement(subject, tokenDescriptor);
            if (authnStatement != null)
                statements.Add(authnStatement);

            return statements;
        }

        /// <summary>
        /// Returns the SamlSubject to use for all the statements that will be created.
        /// Overwrite this method to customize the creation of the SamlSubject.
        /// </summary>
        /// <param name="tokenDescriptor">Contains all the information that is used in token issuance.</param>
        /// <returns>A SamlSubject created from the first subject found in the tokenDescriptor as follows:
        /// <para>
        /// 1. Claim of Type NameIdentifier is searched. If found, SamlSubject.Name is set to claim.Value.
        /// 2. If a non-null tokenDescriptor.proof is found then SamlSubject.KeyIdentifier = tokenDescriptor.Proof.KeyIdentifier AND SamlSubject.ConfirmationMethod is set to 'HolderOfKey'.
        /// 3. If a null tokenDescriptor.proof is found then SamlSubject.ConfirmationMethod is set to 'BearerKey'.
        /// </para>
        /// </returns>
        /// <exception cref="ArgumentNullException">Thrown when 'tokenDescriptor' is null.</exception>
        protected virtual SamlSubject CreateSubject(SecurityTokenDescriptor tokenDescriptor)
        {
            if (null == tokenDescriptor)
                throw LogArgumentNullException(nameof(tokenDescriptor));

            var samlSubject = new SamlSubject();
            Claim identityClaim = null;
            if (tokenDescriptor.Subject != null && tokenDescriptor.Subject.Claims != null)
            {
                foreach (var claim in tokenDescriptor.Subject.Claims)
                {
                    if (claim.Type == ClaimTypes.NameIdentifier)
                    {
                        // Do not allow multiple name identifier claim.
                        if (null != identityClaim)
                            throw LogExceptionMessage(new SamlSecurityTokenException("ID4139:"));

                        identityClaim = claim;
                    }
                }
            }

            // TODO - handle these special claims
            if (identityClaim != null)
            {
                samlSubject.Name = identityClaim.Value;
                //    if (identityClaim.Properties.ContainsKey(ClaimProperties.SamlNameIdentifierFormat))
                //    {
                //        samlSubject.NameFormat = identityClaim.Properties[ClaimProperties.SamlNameIdentifierFormat];
                //    }

                //    if (identityClaim.Properties.ContainsKey(ClaimProperties.SamlNameIdentifierNameQualifier))
                //    {
                //        samlSubject.NameQualifier = identityClaim.Properties[ClaimProperties.SamlNameIdentifierNameQualifier];
                //    }
            }

            //if (tokenDescriptor.Proof != null)
            //{
            //    //
            //    // Add the key and the Holder-Of-Key confirmation method
            //    // for both symmetric and asymmetric key case
            //    //
            //    samlSubject.KeyIdentifier = tokenDescriptor.Proof.KeyIdentifier;
            //    samlSubject.ConfirmationMethods.Add(SamlConstants.HolderOfKey);
            //}
            //else
            //{
            //    //
            //    // This is a bearer token
            //    //
            //    samlSubject.ConfirmationMethods.Add(BearerConfirmationMethod);
            //}

            return samlSubject;
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
                throw LogArgumentNullException(nameof(tokenDescriptor));

            var statements = CreateStatements(tokenDescriptor);

            // - NotBefore / NotAfter
            // - Audience Restriction
            var conditions = CreateConditions(tokenDescriptor);
            var advice = CreateAdvice(tokenDescriptor);
            // TODO - GUID is not correct form.
            var assertion = new SamlAssertion("_" + Guid.NewGuid().ToString(), tokenDescriptor.Issuer, DateTime.UtcNow, conditions, advice, statements);
            assertion.SigningCredentials = tokenDescriptor.SigningCredentials;
            return new SamlSecurityToken(assertion);

            //
            // TODO - handle encryption
            //
        }

        /// <summary>
        /// Builds an XML formated string from a collection of saml attributes that represent an Actor. 
        /// </summary>
        /// <param name="attributes"><see cref="ICollection{SamlAttribute}"/>.</param>
        /// <returns>A well formed XML string.</returns>
        /// <remarks>The string is of the form "&lt;Actor&gt;&lt;SamlAttribute name, ns&gt;&lt;SamlAttributeValue&gt;...&lt;/SamlAttributeValue&gt;, ...&lt;/SamlAttribute&gt;...&lt;/Actor&gt;"</remarks>        
        protected virtual string CreateXmlStringFromAttributes(ICollection<SamlAttribute> attributes)
        {
            bool actorElementWritten = false;

            using (var ms = new MemoryStream())
            {
                using (var writer = XmlDictionaryWriter.CreateTextWriter(ms, Encoding.UTF8, false))
                {
                    foreach (var samlAttribute in attributes)
                    {
                        if (samlAttribute != null)
                        {
                            if (!actorElementWritten)
                            {
                                writer.WriteStartElement(Actor);
                                actorElementWritten = true;
                            }
                       //     Serializer.WriteAttribute(writer, samlAttribute);
                        }
                    }

                    if (actorElementWritten)
                        writer.WriteEndElement();

                    writer.Flush();
                }

                return Encoding.UTF8.GetString(ms.ToArray());
            }
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
        /// Converts a string into an instance of <see cref="SamlSecurityToken"/>.
        /// </summary>
        /// <param name="token">a Saml token as a string.</param>
        /// <exception cref="ArgumentNullException"> If 'token' is null or empty.</exception>
        /// <exception cref="ArgumentException"> If 'token.Length' $gt; <see cref="MaximumTokenSizeInBytes"/>.</exception>
        /// <returns>A <see cref="SamlSecurityToken"/></returns>
        public virtual SamlSecurityToken ReadSamlToken(string token)
        {
            if (string.IsNullOrEmpty(token))
                throw LogArgumentNullException(nameof(token));

            if (token.Length > MaximumTokenSizeInBytes)
                throw LogExceptionMessage(new ArgumentException(FormatInvariant(TokenLogMessages.IDX10209, token.Length, MaximumTokenSizeInBytes)));

            using (var sr = new StringReader(token))
            {
                return new SamlSecurityToken(Serializer.ReadAssertion(XmlReader.Create(sr)));
            }
        }

        /// <summary>
        /// Converts a string into an instance of <see cref="SamlSecurityToken"/>.
        /// </summary>
        /// <param name="token">a Saml token as a string.</param>
        /// <exception cref="ArgumentNullException"> If 'token' is null or empty.</exception>
        /// <exception cref="ArgumentException"> If 'token.Length' $gt; <see cref="MaximumTokenSizeInBytes"/>.</exception>
        /// <returns>A <see cref="SamlSecurityToken"/></returns>
        public override SecurityToken ReadToken(string token)
        {
            return ReadSamlToken(token);
        }

        /// <summary>
        /// Deserializes from XML a token of the type handled by this instance.
        /// </summary>
        /// <param name="reader">An XML reader positioned at the token's start 
        /// element.</param>
        /// <param name="validationParameters"> validation parameters for the <see cref="SamlSecurityToken"/>.</param>
        /// <returns>An instance of <see cref="SamlSecurityToken"/>.</returns>
        public override SecurityToken ReadToken(XmlReader reader, TokenValidationParameters validationParameters)
        {
            throw new NotSupportedException("API is not supported");
        }

        /// <summary>
        /// Returns a <see cref="SecurityKey"/> to use for validating the signature of a token.
        /// </summary>
        /// <param name="token">The <see cref="string"/> representation of the token that is being validated.</param>
        /// <param name="securityToken">The <see cref="SamlSecurityToken"/> that is being validated.</param>
        /// <param name="validationParameters"><see cref="TokenValidationParameters"/> that will be used during validation.</param>
        /// <returns>Returns a <see cref="SecurityKey"/> to use for signature validation.</returns>
        /// <exception cref="ArgumentNullException">If 'securityToken' is null.</exception>
        /// <exception cref="ArgumentNullException">If 'validationParameters' is null.</exception>
        /// <exception cref="ArgumentNullException">If 'securityToken.Assertion' is null.</exception>
        /// <remarks>If key fails to resolve, then null is returned</remarks>
        protected virtual SecurityKey ResolveIssuerSigningKey(string token, SamlSecurityToken securityToken, TokenValidationParameters validationParameters)
        {
            if (securityToken == null)
                throw LogArgumentNullException(nameof(securityToken));

            if (validationParameters == null)
                throw LogArgumentNullException(nameof(validationParameters));

            if (securityToken.Assertion == null)
                throw LogArgumentNullException(nameof(securityToken.Assertion));

            if (securityToken.Assertion.Signature != null && securityToken.Assertion.Signature.KeyInfo != null && !string.IsNullOrEmpty(securityToken.Assertion.Signature.KeyInfo.Kid))
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
        /// This method gets called when a special type of SamlAttribute is detected. The SamlAttribute passed in wraps a SamlAttribute 
        /// that contains a collection of AttributeValues, each of which are mapped to a claim.  All of the claims will be returned
        /// in an ClaimsIdentity with the specified issuer.
        /// </summary>
        /// <param name="attribute">The SamlAttribute to be processed.</param>
        /// <param name="subject">The identity that should be modified to reflect the SamlAttribute.</param>
        /// <param name="issuer">Issuer Identity.</param>
        /// <exception cref="InvalidOperationException">Will be thrown if the SamlAttribute does not contain any valid SamlAttributeValues.</exception>
        protected virtual void SetDelegateFromAttribute(SamlAttribute attribute, ClaimsIdentity subject, string issuer)
        {
            // bail here nothing to add.
            if (subject == null || attribute == null || attribute.Values == null || attribute.Values.Count < 1)
                return;

            var claims = new Collection<Claim>();
            SamlAttribute actingAsAttribute = null;
            foreach (string attributeValue in attribute.Values)
            {
                if (attributeValue != null && attributeValue.Length > 0)
                {
                    using (var xmlReader = XmlDictionaryReader.CreateTextReader(Encoding.UTF8.GetBytes(attributeValue), XmlDictionaryReaderQuotas.Max))
                    {
                        xmlReader.MoveToContent();
                        xmlReader.ReadStartElement(Actor);
                        while (xmlReader.IsStartElement(SamlConstants.Elements.Attribute))
                        {
                            var innerAttribute = Serializer.ReadAttribute(xmlReader);
                            if (innerAttribute != null)
                            {
                                string claimType = string.IsNullOrEmpty(innerAttribute.Namespace) ? innerAttribute.Name : innerAttribute.Namespace + "/" + innerAttribute.Name;
                                if (claimType == ClaimTypes.Actor)
                                {
                                    // In this case we have two delegates acting as an identity, we do not allow this
                                    if (actingAsAttribute != null)
                                        throw LogExceptionMessage(new SamlSecurityTokenException("ID4034"));

                                    actingAsAttribute = innerAttribute;
                                }
                                else
                                {
                                    string claimValueType = ClaimValueTypes.String;
                                    string originalIssuer = null;

                                    if (innerAttribute is SamlAttribute SamlAttribute)
                                    {
                                        claimValueType = SamlAttribute.AttributeValueXsiType;
                                        originalIssuer = SamlAttribute.OriginalIssuer;
                                    }

                                    foreach (var value in innerAttribute.Values)
                                    {
                                        Claim claim = null;
                                        if (string.IsNullOrEmpty(originalIssuer))
                                            claim = new Claim(claimType, value, claimValueType, issuer);
                                        else
                                            claim = new Claim(claimType, value, claimValueType, issuer, originalIssuer);

                                        claims.Add(claim);
                                    }
                                }
                            }
                        }

                        xmlReader.ReadEndElement(); // Actor
                    }
                }
            }

            subject.Actor = new ClaimsIdentity(claims, "Federation");
            SetDelegateFromAttribute(actingAsAttribute, subject.Actor, issuer);
        }

        /// <summary>
        /// Determines if the audiences found in a <see cref="SamlSecurityToken"/> are valid.
        /// </summary>
        /// <param name="audiences"><see cref="IEnumerable{String}"/>.</param>
        /// <param name="securityToken">The <see cref="SamlSecurityToken"/> being validated.</param>
        /// <param name="validationParameters"><see cref="TokenValidationParameters"/> required for validation.</param>
        /// <remarks>see <see cref="Validators.ValidateAudience"/> for additional details.</remarks>
        protected virtual void ValidateAudience(IEnumerable<string> audiences, SecurityToken securityToken, TokenValidationParameters validationParameters)
        {
            Validators.ValidateAudience(audiences, securityToken, validationParameters);
        }


        /// <summary>
        /// Validates the Lifetime and Audience conditions.
        /// </summary>
        /// <param name="securityToken">a <see cref="SamlSecurityToken"/> that contains the <see cref="SamlConditions"/>.</param>
        /// <param name="validationParameters"><see cref="TokenValidationParameters"/> required for validation.</param>
        /// <exception cref="ArgumentNullException">If 'securityToken' is null or empty.</exception>
        /// <exception cref="ArgumentNullException">If 'validationParameters' is null.</exception>
        /// <exception cref="ArgumentNullException">If 'securityToken.Assertion' is null.</exception>
        /// <exception cref="SecurityTokenValidationException">if the Condition 'OneTimeUse' is specified. Requires overriding.</exception>
        /// <exception cref="SecurityTokenValidationException">if the Condition 'ProxyRestriction' is specified. Requires overriding.</exception>
        protected virtual void ValidateConditions(SamlSecurityToken securityToken, TokenValidationParameters validationParameters)
        {
            if (securityToken == null)
                throw LogArgumentNullException(nameof(securityToken));

            if (validationParameters == null)
                throw LogArgumentNullException(nameof(validationParameters));

            if (securityToken.Assertion == null)
                throw LogArgumentNullException(nameof(securityToken.Assertion));

            if (securityToken.Assertion.Conditions == null || securityToken.Assertion.Conditions.Conditions.Count() == 0)
                return;

            Validators.ValidateLifetime(securityToken.Assertion.Conditions.NotBefore, securityToken.Assertion.Conditions.NotOnOrAfter, securityToken, validationParameters);

            // TODO - concat all the audiences together
            if (securityToken.Assertion.Conditions.Conditions.ElementAt(0) is SamlAudienceRestrictionCondition)
            {
                foreach (var condition in securityToken.Assertion.Conditions.Conditions)
                {
                    SamlAudienceRestrictionCondition audienceRestriction = condition as SamlAudienceRestrictionCondition;
                    if (validationParameters.AudienceValidator != null)
                        validationParameters.AudienceValidator(audienceRestriction.Audiences, securityToken, validationParameters);
                    else
                        Validators.ValidateAudience(audienceRestriction.Audiences, securityToken, validationParameters);
                }
            }            
        }

        /// <summary>
        /// Determines if an issuer found in a <see cref="SamlSecurityToken"/> is valid.
        /// </summary>
        /// <param name="issuer">The issuer to validate</param>
        /// <param name="securityToken">The <see cref="SamlSecurityToken"/> that is being validated.</param>
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
        /// <param name="securityToken">The <see cref="SecurityToken"/> being validated.</param>
        /// <param name="validationParameters">The current <see cref="TokenValidationParameters"/>.</param>
        protected virtual void ValidateIssuerSecurityKey(SecurityKey securityKey, SecurityToken securityToken, TokenValidationParameters validationParameters)
        {
            if (validationParameters.ValidateIssuerSigningKey)
            {
                if (validationParameters.IssuerSigningKeyValidator != null)
                    validationParameters.IssuerSigningKeyValidator(securityKey, securityToken, validationParameters);
                else
                    Validators.ValidateIssuerSecurityKey(securityKey, securityToken, validationParameters);
            }
        }

        /// <summary>
        /// Validates the lifetime of a <see cref="SamlSecurityToken"/>.
        /// </summary>
        /// <param name="notBefore">The <see cref="DateTime"/> value found in the <see cref="SamlSecurityToken"/>.</param>
        /// <param name="expires">The <see cref="DateTime"/> value found in the <see cref="SamlSecurityToken"/>.</param>
        /// <param name="securityToken">The <see cref="SamlSecurityToken"/> being validated.</param>
        /// <param name="validationParameters"><see cref="TokenValidationParameters"/> required for validation.</param>
        /// <remarks><see cref="Validators.ValidateLifetime"/> for additional details.</remarks>
        protected virtual void ValidateLifetime(DateTime? notBefore, DateTime? expires, SecurityToken securityToken, TokenValidationParameters validationParameters)
        {
            Validators.ValidateLifetime(notBefore, expires, securityToken, validationParameters);
        }

        /// <summary>
        /// Validates that the signature, if found is valid.
        /// </summary>
        /// <param name="token">A Saml token.</param>
        /// <param name="validationParameters"><see cref="TokenValidationParameters"/> that will be used during validation.</param>
        /// <exception cref="ArgumentNullException">If 'token' is null or whitespace.</exception>
        /// <exception cref="ArgumentNullException">If 'validationParameters' is null.</exception>
        /// <exception cref="SecurityTokenValidationException">If <see cref="TokenValidationParameters.SignatureValidator"/> returns null OR an object other than a <see cref="SamlSecurityToken"/>.</exception>
        /// <exception cref="SecurityTokenValidationException">If a signature is not found and <see cref="TokenValidationParameters.RequireSignedTokens"/> is true.</exception>
        /// <exception cref="SecurityTokenSignatureKeyNotFoundException">If the 'token' has a key identifier and none of the <see cref="SecurityKey"/>(s) provided result in a validated signature. 
        /// This can indicate that a key refresh is required.</exception>
        /// <exception cref="SecurityTokenInvalidSignatureException">If after trying all the <see cref="SecurityKey"/>(s), none result in a validated signture AND the 'token' does not have a key identifier.</exception>
        /// <returns>A <see cref="SamlSecurityToken"/> that has had the signature validated if token was signed.</returns>
        /// <remarks><para>If the 'token' is signed, the signature is validated even if <see cref="TokenValidationParameters.RequireSignedTokens"/> is false.</para>
        /// <para>If the 'token' signature is validated, then the <see cref="SamlSecurityToken.SigningKey"/> will be set to the key that signed the 'token'. It is the responsibility of <see cref="TokenValidationParameters.SignatureValidator"/> to set the <see cref="SamlSecurityToken.SigningKey"/></para></remarks>
        protected virtual SamlSecurityToken ValidateSignature(string token, TokenValidationParameters validationParameters)
        {
            if (string.IsNullOrWhiteSpace(token))
                throw LogArgumentNullException(nameof(token));

            if (validationParameters == null)
                throw LogArgumentNullException(nameof(validationParameters));

            var samlToken = ReadSamlToken(token);
            if (validationParameters.SignatureValidator != null)
            {
                var validatedSamlToken = validationParameters.SignatureValidator(token, validationParameters);
                if (validatedSamlToken == null)
                    throw LogExceptionMessage(new SecurityTokenValidationException(FormatInvariant(TokenLogMessages.IDX10505, token)));

                var validatedSaml = validatedSamlToken as SamlSecurityToken;
                if (validatedSaml == null)
                    throw LogExceptionMessage(new SecurityTokenValidationException(FormatInvariant(TokenLogMessages.IDX10506, typeof(SamlSecurityToken), validatedSamlToken.GetType(), token)));

                return validatedSaml;
            }

            if (samlToken.Assertion.Signature == null && validationParameters.RequireSignedTokens)
                throw LogExceptionMessage(new SecurityTokenValidationException(FormatInvariant(TokenLogMessages.IDX10504, token)));

            bool keyMatched = false;
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
                    // remember that key was matched for throwing exception SecurityTokenSignatureKeyNotFoundException
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
                securityKeys = GetAllSigningKeys(validationParameters);
            }

            // keep track of exceptions thrown, keys that were tried
            var exceptionStrings = new StringBuilder();
            var keysAttempted = new StringBuilder();
            bool canMatchKey = samlToken.Assertion.Signature.KeyInfo != null;
            foreach (var securityKey in securityKeys)
            {
                try
                {
                    samlToken.Assertion.Signature.Verify(securityKey);
                    IdentityModelEventSource.Logger.WriteInformation(TokenLogMessages.IDX10242, token);
                    samlToken.SigningKey = securityKey;
                    return samlToken;
                }
                catch (Exception ex)
                {
                    exceptionStrings.AppendLine(ex.ToString());
                }

                if (securityKey != null)
                {
                    keysAttempted.AppendLine(securityKey.ToString() + " , KeyId: " + securityKey.KeyId);
                    if (canMatchKey && !keyMatched && securityKey.KeyId != null)
                        keyMatched = securityKey.KeyId.Equals(samlToken.Assertion.Signature.KeyInfo.Kid, StringComparison.Ordinal);
                }
            }

            // if there was a keymatch with what was found in tokenValidationParameters most likely metadata is stale. throw SecurityTokenSignatureKeyNotFoundException
            if (!keyMatched && canMatchKey && keysAttempted.Length > 0)
                throw LogExceptionMessage(new SecurityTokenSignatureKeyNotFoundException(FormatInvariant(TokenLogMessages.IDX10501, samlToken.Assertion.Signature.KeyInfo, samlToken)));

            if (keysAttempted.Length > 0)
                throw LogExceptionMessage(new SecurityTokenInvalidSignatureException(FormatInvariant(TokenLogMessages.IDX10503, keysAttempted, exceptionStrings, samlToken)));

            throw LogExceptionMessage(new SecurityTokenInvalidSignatureException(TokenLogMessages.IDX10500));
        }

        /// <summary>
        /// Validates the token replay.
        /// </summary>
        /// <param name="expiration">expiration time of the <see cref="SamlSecurityToken"/></param>
        /// <param name="token"><see cref="SamlSecurityToken"/> to validate</param>
        /// <param name="validationParameters"><see cref="TokenValidationParameters"/> that will be used during validation</param>
        protected virtual void ValidateTokenReplay(DateTime? expiration, string token, TokenValidationParameters validationParameters)
        {
            Validators.ValidateTokenReplay(expiration, token, validationParameters);
        }

        /// <summary>
        /// Reads and validates a well formed <see cref="SamlSecurityToken"/>.
        /// </summary>
        /// <param name="token">A string containing a well formed securityToken.</param>
        /// <param name="validationParameters">Contains data and information needed for validation.</param>
        /// <param name="validatedToken">The <see cref="SecurityToken"/> that was validated.</param>
        /// <exception cref="ArgumentNullException">'securityToken' is null or whitespace.</exception>
        /// <exception cref="ArgumentNullException">'validationParameters' is null.</exception>
        /// <exception cref="SecurityTokenException">'securityToken.Length' > <see cref="MaximumTokenSizeInBytes"/>.</exception>
        /// <returns>A <see cref="ClaimsPrincipal"/> generated from the claims in the Saml securityToken.</returns>
        public virtual ClaimsPrincipal ValidateToken(string token, TokenValidationParameters validationParameters, out SecurityToken validatedToken)
        {
            if (string.IsNullOrWhiteSpace(token))
                throw LogArgumentNullException(nameof(token));

            if (validationParameters == null)
                throw LogArgumentNullException(nameof(validationParameters));

            if (token.Length > MaximumTokenSizeInBytes)
                throw LogExceptionMessage(new ArgumentException(FormatInvariant(TokenLogMessages.IDX10209, token.Length, MaximumTokenSizeInBytes)));

            var samlToken = ValidateSignature(token, validationParameters);
            ValidateConditions(samlToken, validationParameters);
            var issuer = ValidateIssuer(samlToken.Issuer, samlToken, validationParameters);
            ValidateTokenReplay(samlToken.Assertion.Conditions.NotBefore, token, validationParameters);
            validatedToken = samlToken;
            var identity = CreateClaimsIdentity(samlToken, issuer, validationParameters);
            if (validationParameters.SaveSigninToken)
                identity.BootstrapContext = token;

            IdentityModelEventSource.Logger.WriteInformation(TokenLogMessages.IDX10241, token);

            return new ClaimsPrincipal(identity);
        }

        /// <summary>
        /// Serializes a <see cref="SamlSecurityToken"/> to a string.
        /// </summary>
        /// <param name="token">A <see cref="SamlSecurityToken"/>.</param>
        public override string WriteToken(SecurityToken token)
        {
            if (token == null)
                throw LogArgumentNullException(nameof(token));

            var samlToken = token as SamlSecurityToken;
            if (samlToken == null)
                throw LogExceptionMessage(new ArgumentException(FormatInvariant(LogMessages.IDX10400, GetType(), typeof(SamlSecurityToken), token)));

            var stringBuilder = new StringBuilder();
            using (var writer = XmlWriter.Create(stringBuilder))
            {
                WriteToken(writer, samlToken);
                writer.Flush();
                return stringBuilder.ToString();
            }
        }

        /// <summary>
        /// Serializes to XML a securityToken of the type handled by this instance.
        /// </summary>
        /// <param name="writer">The XML writer.</param>
        /// <param name="token">A securityToken of type <see cref="TokenType"/>.</param>
        public override void WriteToken(XmlWriter writer, SecurityToken token)
        {
            if (writer == null)
                throw LogArgumentNullException(nameof(writer));

            if (token == null)
                throw LogArgumentNullException(nameof(token));

            var samlSecurityToken = token as SamlSecurityToken;
            if (samlSecurityToken == null)
                throw LogExceptionMessage(new ArgumentException(FormatInvariant(LogMessages.IDX10400, GetType(), typeof(SamlSecurityToken), token.GetType())));

            if (samlSecurityToken.Assertion == null)
                throw LogArgumentNullException(nameof(samlSecurityToken.Assertion));

           // var envelopedWriter = new EnvelopedSignatureWriter(writer, samlSecurityToken.Assertion.SigningCredentials, Guid.NewGuid().ToString());
            // Serializer.WriteToken(envelopedWriter, samlSecurityToken);
        }

#endregion methods
    }
}
