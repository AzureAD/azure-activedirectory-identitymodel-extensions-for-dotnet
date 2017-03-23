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
using Microsoft.IdentityModel.Xml;

namespace Microsoft.IdentityModel.Tokens.Saml
{
    /// <summary>
    /// A derived <see cref="System.IdentityModel.Tokens.Saml.SamlSecurityTokenHandler"/> that implements ISecurityTokenValidator,
    /// which supports validating tokens passed as strings using <see cref="TokenValidationParameters"/>.
    /// </summary>
    ///
    public class SamlSecurityTokenHandler : SecurityTokenHandler, ISecurityTokenValidator
    {
        internal const string SamlTokenProfile11 = "urn:oasis:names:tc:SAML:1.0:assertion";
        internal const string OasisWssSamlTokenProfile11 = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1";
        internal const string Actor = "Actor";
        internal const string Attribute = "saml:Attribute";

        private int _defaultTokenLifetimeInMinutes = DefaultTokenLifetimeInMinutes;
        private int _maximumTokenSizeInBytes = TokenValidationParameters.DefaultMaximumTokenSizeInBytes;
        private static string[] _tokenTypeIdentifiers = new string[] { SamlTokenProfile11, OasisWssSamlTokenProfile11 };
        private SamlSerializer serializer = new SamlSerializer();
        private Dictionary<string, string> _shortToLongClaimTypeMapping;
        /// <summary>
        /// Default lifetime of tokens created. When creating tokens, if 'expires' and 'notbefore' are both null, then a default will be set to: expires = DateTime.UtcNow, notbefore = DateTime.UtcNow + TimeSpan.FromMinutes(TokenLifetimeInMinutes).
        /// </summary>
        public static readonly int DefaultTokenLifetimeInMinutes = 60;

        /// <summary>
        /// Initializes an instance of <see cref="SamlSecurityTokenHandler"/>
        /// </summary>
        public SamlSecurityTokenHandler()
        {
            _shortToLongClaimTypeMapping = new Dictionary<string, string>()
            {
                { "actort", ClaimTypes.Actor },
                { "birthdate", ClaimTypes.DateOfBirth },
                { "email", ClaimTypes.Email },
                { "family_name", ClaimTypes.Surname },
                { "gender", ClaimTypes.Gender },
                { "given_name", ClaimTypes.GivenName },
                { "nameid", ClaimTypes.NameIdentifier },
                { "sub", ClaimTypes.NameIdentifier },
                { "website", ClaimTypes.Webpage },
                { "unique_name", ClaimTypes.Name },
                { "oid", "http://schemas.microsoft.com/identity/claims/objectidentifier" },
                { "scp", "http://schemas.microsoft.com/identity/claims/scope" },
                { "tid", "http://schemas.microsoft.com/identity/claims/tenantid" },
                { "acr", "http://schemas.microsoft.com/claims/authnclassreference" },
                { "adfs1email", "http://schemas.xmlsoap.org/claims/EmailAddress" },
                { "adfs1upn", "http://schemas.xmlsoap.org/claims/UPN" },
                { "amr", "http://schemas.microsoft.com/claims/authnmethodsreferences" },
                { "authmethod", ClaimTypes.AuthenticationMethod },
                { "certapppolicy", "http://schemas.microsoft.com/2012/12/certificatecontext/extension/applicationpolicy" },
                { "certauthoritykeyidentifier", "http://schemas.microsoft.com/2012/12/certificatecontext/extension/authoritykeyidentifier" },
                { "certbasicconstraints", "http://schemas.microsoft.com/2012/12/certificatecontext/extension/basicconstraints" },
                { "certeku", "http://schemas.microsoft.com/2012/12/certificatecontext/extension/eku" },
                { "certissuer", "http://schemas.microsoft.com/2012/12/certificatecontext/field/issuer" },
                { "certissuername", "http://schemas.microsoft.com/2012/12/certificatecontext/field/issuername" },
                { "certkeyusage", "http://schemas.microsoft.com/2012/12/certificatecontext/extension/keyusage" },
                { "certnotafter", "http://schemas.microsoft.com/2012/12/certificatecontext/field/notafter" },
                { "certnotbefore", "http://schemas.microsoft.com/2012/12/certificatecontext/field/notbefore" },
                { "certpolicy", "http://schemas.microsoft.com/2012/12/certificatecontext/extension/certificatepolicy" },
                { "certpublickey", ClaimTypes.Rsa },
                { "certrawdata", "http://schemas.microsoft.com/2012/12/certificatecontext/field/rawdata" },
                { "certserialnumber", ClaimTypes.SerialNumber },
                { "certsignaturealgorithm", "http://schemas.microsoft.com/2012/12/certificatecontext/field/signaturealgorithm" },
                { "certsubject", "http://schemas.microsoft.com/2012/12/certificatecontext/field/subject" },
                { "certsubjectaltname", "http://schemas.microsoft.com/2012/12/certificatecontext/extension/san" },
                { "certsubjectkeyidentifier", "http://schemas.microsoft.com/2012/12/certificatecontext/extension/subjectkeyidentifier" },
                { "certsubjectname", "http://schemas.microsoft.com/2012/12/certificatecontext/field/subjectname" },
                { "certtemplateinformation", "http://schemas.microsoft.com/2012/12/certificatecontext/extension/certificatetemplateinformation" },
                { "certtemplatename", "http://schemas.microsoft.com/2012/12/certificatecontext/extension/certificatetemplatename" },
                { "certthumbprint", ClaimTypes.Thumbprint },
                { "certx509version", "http://schemas.microsoft.com/2012/12/certificatecontext/field/x509version" },
                { "clientapplication", "http://schemas.microsoft.com/2012/01/requestcontext/claims/x-ms-client-application" },
                { "clientip", "http://schemas.microsoft.com/2012/01/requestcontext/claims/x-ms-client-ip" },
                { "clientuseragent", "http://schemas.microsoft.com/2012/01/requestcontext/claims/x-ms-client-user-agent" },
                { "commonname", "http://schemas.xmlsoap.org/claims/CommonName" },
                { "denyonlyprimarygroupsid", ClaimTypes.DenyOnlyPrimaryGroupSid },
                { "denyonlyprimarysid", ClaimTypes.DenyOnlyPrimarySid },
                { "denyonlysid", ClaimTypes.DenyOnlySid },
                { "devicedispname", "http://schemas.microsoft.com/2012/01/devicecontext/claims/displayname" },
                { "deviceid", "http://schemas.microsoft.com/2012/01/devicecontext/claims/identifier" },
                { "deviceismanaged", "http://schemas.microsoft.com/2012/01/devicecontext/claims/ismanaged" },
                { "deviceostype", "http://schemas.microsoft.com/2012/01/devicecontext/claims/ostype" },
                { "deviceosver", "http://schemas.microsoft.com/2012/01/devicecontext/claims/osversion" },
                { "deviceowner", "http://schemas.microsoft.com/2012/01/devicecontext/claims/userowner" },
                { "deviceregid", "http://schemas.microsoft.com/2012/01/devicecontext/claims/registrationid" },
                { "endpointpath", "http://schemas.microsoft.com/2012/01/requestcontext/claims/x-ms-endpoint-absolute-path" },
                { "forwardedclientip", "http://schemas.microsoft.com/2012/01/requestcontext/claims/x-ms-forwarded-client-ip" },
                { "group", "http://schemas.xmlsoap.org/claims/Group" },
                { "groupsid", ClaimTypes.GroupSid },
                { "idp", "http://schemas.microsoft.com/identity/claims/identityprovider" },
                { "insidecorporatenetwork", "http://schemas.microsoft.com/ws/2012/01/insidecorporatenetwork" },
                { "isregistereduser", "http://schemas.microsoft.com/2012/01/devicecontext/claims/isregistereduser" },
                { "ppid", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/privatepersonalidentifier" },
                { "primarygroupsid", ClaimTypes.PrimaryGroupSid },
                { "primarysid", ClaimTypes.PrimarySid },
                { "proxy", "http://schemas.microsoft.com/2012/01/requestcontext/claims/x-ms-proxy" },
                { "pwdchgurl", "http://schemas.microsoft.com/ws/2012/01/passwordchangeurl" },
                { "pwdexpdays", "http://schemas.microsoft.com/ws/2012/01/passwordexpirationdays" },
                { "pwdexptime", "http://schemas.microsoft.com/ws/2012/01/passwordexpirationtime" },
                { "relyingpartytrustid", "http://schemas.microsoft.com/2012/01/requestcontext/claims/relyingpartytrustid" },
                { "role", ClaimTypes.Role },
                { "roles", ClaimTypes.Role },
                { "upn", ClaimTypes.Upn },
                { "winaccountname", ClaimTypes.WindowsAccountName },
            };
        }

        /// <summary>
        /// Gets the InboundClaimTypeMap used by JwtSecurityTokenHandler when producing claims from jwt. 
        /// </summary>
        public IDictionary<string, string> ShortToLongClaimTypeMap
        {
            get
            {
                return _shortToLongClaimTypeMapping;
            }
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
        /// Reads the string as XML and looks for the an element <see cref="SamlConstants.Assertion"/> with namespace <see cref="SamlConstants.Saml11Namespace"/>.
        /// </summary>
        /// <param name="securityToken">The securitytoken.</param>
        /// <returns><see cref="XmlDictionaryReader.IsStartElement"/> (<see cref="SamlConstants.Assertion"/>, <see cref="SamlConstants.Saml11Namespace"/>).</returns>
        public override bool CanReadToken(string securityToken)
        {
            if (string.IsNullOrWhiteSpace(securityToken) || securityToken.Length > MaximumTokenSizeInBytes)
                return false;

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
                    return reader.IsStartElement(SamlConstants.ElementNames.Assertion, SamlConstants.Saml11Namespace);
                }
            }
        }

        /// <summary>
        /// Creates claims from a Saml securityToken.
        /// </summary>
        /// <param name="samlToken">A <see cref="SamlSecurityToken"/> that will be used to create the claims.</param>
        /// <param name="issuer">The issuer value for each <see cref="Claim"/> in the <see cref="ClaimsIdentity"/>.</param>
        /// <param name="validationParameters"> Contains parameters for validating the securityToken.</param>
        /// <returns>A <see cref="ClaimsIdentity"/> containing the claims from the <see cref="SamlSecurityToken"/>.</returns>
        protected virtual ClaimsIdentity CreateClaimsIdentity(SamlSecurityToken samlToken, string issuer, TokenValidationParameters validationParameters)
        {
            if (samlToken == null)
                throw LogHelper.LogArgumentNullException("samlToken");

            if (string.IsNullOrWhiteSpace(issuer))
                throw LogHelper.LogExceptionMessage(new ArgumentException(LogMessages.IDX10221));

            return validationParameters.CreateClaimsIdentity(samlToken, issuer);
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
                throw LogHelper.LogArgumentNullException(nameof(tokenDescriptor));

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
        /// Generates all the conditions for saml
        /// </summary>
        /// <param name="tokenDescriptor">information that is used in token issuance.</param>
        /// <returns>SamlConditions</returns>
        protected virtual SamlConditions CreateConditions(SecurityTokenDescriptor tokenDescriptor)
        {
            if (null == tokenDescriptor)
                throw LogHelper.LogArgumentNullException(nameof(tokenDescriptor));

            var conditions = new SamlConditions();
            if (tokenDescriptor.IssuedAt.HasValue)
                conditions.NotBefore = tokenDescriptor.IssuedAt.Value;

            if (tokenDescriptor.Expires.HasValue)
                conditions.NotOnOrAfter = tokenDescriptor.Expires.Value;

            if (!string.IsNullOrEmpty(tokenDescriptor.Audience))
                conditions.Conditions.Add(new SamlAudienceRestrictionCondition(new Uri[] { new Uri(tokenDescriptor.Audience) }));

            return conditions;
        }

        /// <summary>
        /// Override this method to provide a SamlAdvice to place in the Samltoken. 
        /// </summary>
        /// <param name="tokenDescriptor">Contains informaiton about the token.</param>
        /// <returns>SamlAdvice, default is null.</returns>
        protected virtual SamlAdvice CreateAdvice(SecurityTokenDescriptor tokenDescriptor)
        {
            return null;
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
                throw LogHelper.LogArgumentNullException(nameof(tokenDescriptor));

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
        /// Creates SamlAttributeStatements and adds them to a collection.
        /// Override this method to provide a custom implementation.
        /// <para>
        /// Default behavior is to create a new SamlAttributeStatement for each Subject in the tokenDescriptor.Subjects collection.
        /// </para>
        /// </summary>
        /// <param name="samlSubject">The SamlSubject to use in the SamlAttributeStatement that are created.</param>
        /// <param name="subject">The ClaimsIdentity that contains claims which will be converted to SAML Attributes.</param>
        /// <param name="tokenDescriptor">Contains all the other information that is used in token issuance.</param>
        /// <returns>SamlAttributeStatement</returns>
        /// <exception cref="ArgumentNullException">Thrown when 'samlSubject' is null.</exception>
        protected virtual SamlAttributeStatement CreateAttributeStatement(
            SamlSubject subject,
            SecurityTokenDescriptor tokenDescriptor)
        {

            if (subject == null)
                LogHelper.LogArgumentNullException(nameof(subject));

            if (tokenDescriptor == null)
                LogHelper.LogArgumentNullException(nameof(tokenDescriptor));

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
        /// Adds all Actors.
        /// </summary>
        /// <param name="subject">The delegate of this ClaimsIdentity will be serialized into a SamlAttribute.</param>
        /// <param name="attributes">Attribute collection to which the Actor added.</param>
        protected virtual void AddActorToAttributes(ICollection<SamlAttribute> attributes, ClaimsIdentity subject)
        {
            if (attributes == null)
                throw LogHelper.LogArgumentNullException(nameof(attributes));

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
        /// Builds an XML formated string from a collection of saml attributes that represent an Actor. 
        /// </summary>
        /// <param name="attributes">An enumeration of Saml Attributes.</param>
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
                            serializer.WriteAttribute(writer, samlAttribute);
                        }
                    }

                    if (actorElementWritten)
                        writer.WriteEndElement();

                    writer.Flush();
                }

                return Encoding.UTF8.GetString(ms.ToArray());
            }
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
                    foreach (var attributeValue in attribute.AttributeValues)
                        distinctAttributes[attributeKey].AttributeValues.Add(attributeValue);
                }
                else
                {
                    distinctAttributes.Add(attributeKey, attribute);
                }
            }

            return distinctAttributes.Values;
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
            if (subject == null || attribute == null || attribute.AttributeValues == null || attribute.AttributeValues.Count < 1)
                return;

            var claims = new Collection<Claim>();
            SamlAttribute actingAsAttribute = null;
            foreach (string attributeValue in attribute.AttributeValues)
            {
                if (attributeValue != null && attributeValue.Length > 0)
                {
                    using (var xmlReader = XmlDictionaryReader.CreateTextReader(Encoding.UTF8.GetBytes(attributeValue), XmlDictionaryReaderQuotas.Max))
                    {
                        xmlReader.MoveToContent();
                        xmlReader.ReadStartElement(Actor);
                        while (xmlReader.IsStartElement(Attribute))
                        {
                            var innerAttribute = serializer.ReadAttribute(xmlReader);
                            if (innerAttribute != null)
                            {
                                string claimType = string.IsNullOrEmpty(innerAttribute.Namespace) ? innerAttribute.Name : innerAttribute.Namespace + "/" + innerAttribute.Name;
                                if (claimType == ClaimTypes.Actor)
                                {
                                    // In this case we have two delegates acting as an identity, we do not allow this
                                    if (actingAsAttribute != null)
                                        throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("ID4034"));

                                    actingAsAttribute = innerAttribute;
                                }
                                else
                                {
                                    string claimValueType = ClaimValueTypes.String;
                                    string originalIssuer = null;
                                    var SamlAttribute = innerAttribute as SamlAttribute;
                                    if (SamlAttribute != null)
                                    {
                                        claimValueType = SamlAttribute.AttributeValueXsiType;
                                        originalIssuer = SamlAttribute.OriginalIssuer;
                                    }

                                    foreach (var value in innerAttribute.AttributeValues)
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
                LogHelper.LogArgumentNullException(nameof(claim));

            // A SamlAttribute 1.0 is required to have the attributeNamespace and attributeName be non-null and non-empty.
            string claimType;
            if (!ShortToLongClaimTypeMap.TryGetValue(claim.Type, out claimType))
                claimType = claim.Type;

            int lastSlashIndex = claimType.LastIndexOf('/');
            if ((lastSlashIndex == 0) || (lastSlashIndex == -1))
                throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException($"claimType, ID4215, claim.Type: {claimType}"));

            // TODO - see if there is another slash before this one.
            if (lastSlashIndex == claim.Type.Length - 1)
                throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException($"claimType, ID4216, claim.Type: {claimType}"));

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
        /// Creates a SamlAuthenticationStatement for each AuthenticationInformation found in AuthenticationInformation. 
        /// Override this method to provide a custom implementation.
        /// </summary>
        /// <param name="subject">The SamlSubject of the Statement.</param>
        /// <param name="tokenDescriptor">Contains all the other information that is used in token issuance.</param>
        /// <returns>SamlAuthenticationStatement</returns>
        /// <exception cref="ArgumentNullException">Thrown when 'samlSubject' or 'authInfo' is null.</exception>
        protected virtual SamlAuthenticationStatement CreateAuthenticationStatement(
                                                                SamlSubject subject,
                                                                SecurityTokenDescriptor tokenDescriptor)
        {
            if (subject == null)
                throw LogHelper.LogArgumentNullException(nameof(subject));

            if (tokenDescriptor == null)
                throw LogHelper.LogArgumentNullException(nameof(tokenDescriptor));

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
                throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("ID4270, AuthenticationMethod, SAML11"));
            else if (authenticationInstant == null)
                throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("ID4270, AuthenticationMethod, SAML11"));

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
                throw LogHelper.LogArgumentNullException(nameof(tokenDescriptor));

            var samlSubject = new SamlSubject();
            Claim identityClaim = null;
            if (tokenDescriptor.Subject != null && tokenDescriptor.Subject.Claims != null)
            {
                foreach (var claim in tokenDescriptor.Subject.Claims)
                {
                    string claimType;
                    if (!ShortToLongClaimTypeMap.TryGetValue(claim.Type, out claimType))
                        claimType = claim.Type;

                    if (claimType == ClaimTypes.NameIdentifier)
                    {
                        // Do not allow multiple name identifier claim.
                        if (null != identityClaim)
                            throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("ID4139:"));

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

        ///// <summary>
        ///// Creates the security securityToken reference when the securityToken is not attached to the message.
        ///// </summary>
        ///// <param name="token">The saml securityToken.</param>
        ///// <param name="attached">Boolean that indicates if a attached or unattached
        ///// reference needs to be created.</param>
        ///// <returns>A <see cref="SamlAssertionKeyIdentifierClause"/>.</returns>
        //public override SecurityKeyIdentifierClause CreateSecurityTokenReference(SecurityToken token, bool attached)
        //{
        //    if (null == token)
        //    {
        //        throw new ArgumentNullException("token");
        //    }

        //    return token.CreateKeyIdentifierClause<SamlAssertionKeyIdentifierClause>();
        //}

        /// <summary>
        /// Gets or sets a bool that controls if token creation will set default 'exp', 'nbf' and 'iat' if not specified.
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
                    throw LogHelper.LogExceptionMessage(new ArgumentOutOfRangeException("value", string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10104, value)));

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
                    throw LogHelper.LogExceptionMessage(new ArgumentOutOfRangeException("value", String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10101, value)));

                _maximumTokenSizeInBytes = value;
            }
        }

        /// <summary>
        /// Deserializes from XML a token of the type handled by this instance.
        /// </summary>
        /// <param name="reader">An XML reader positioned at the token's start 
        /// element.</param>
        /// <returns>An instance of <see cref="SamlSecurityToken"/>.</returns>
        public override SecurityToken ReadToken(string token)
        {
            var sr = new StringReader(token);
            var envelopedDictionaryReader = new EnvelopedSignatureReader(XmlReader.Create(sr));
            return serializer.ReadToken(envelopedDictionaryReader);
        }

        /// <summary>
        /// Deserializes from XML a token of the type handled by this instance.
        /// </summary>
        /// <param name="reader">An XML reader positioned at the token's start 
        /// element.</param>
        /// <returns>An instance of <see cref="SamlSecurityToken"/>.</returns>
        public override SecurityToken ReadToken(XmlReader reader, TokenValidationParameters validationParameters)
        {
            // TODO - who sets reader to XmlDictionaryReader?
            return serializer.ReadToken(reader as XmlDictionaryReader);
        }

        /// <summary>
        /// Resolves the SecurityKeyIdentifier specified in a saml:Subject element. 
        /// </summary>
        /// <param name="subjectKeyIdentifier">SecurityKeyIdentifier to resolve into a key.</param>
        /// <returns>SecurityKey</returns>
        /// <exception cref="ArgumentNullException">The input parameter 'subjectKeyIdentifier' is null.</exception>

        protected virtual SecurityKey ResolveSubjectKeyIdentifier(SecurityKeyIdentifier subjectKeyIdentifier)
        {
            if (subjectKeyIdentifier == null)
                throw LogHelper.LogArgumentNullException(nameof(subjectKeyIdentifier));

            SecurityKey key = null;

            return key;
        }
        /// <summary>
        /// Reads and validates a well formed <see cref="SamlSecurityToken"/>.
        /// </summary>
        /// <param name="securityToken">A string containing a well formed securityToken.</param>
        /// <param name="validationParameters">Contains data and information needed for validation.</param>
        /// <param name="validatedToken">The <see cref="SecurityToken"/> that was validated.</param>
        /// <exception cref="ArgumentNullException">'securityToken' is null or whitespace.</exception>
        /// <exception cref="ArgumentNullException">'validationParameters' is null.</exception>
        /// <exception cref="SecurityTokenException">'securityToken.Length' > <see cref="MaximumTokenSizeInBytes"/>.</exception>
        /// <returns>A <see cref="ClaimsPrincipal"/> generated from the claims in the Saml securityToken.</returns>
        public virtual ClaimsPrincipal ValidateToken(string securityToken, TokenValidationParameters validationParameters, out SecurityToken validatedToken)
        {
            if (string.IsNullOrWhiteSpace(securityToken))
                throw LogHelper.LogArgumentNullException(nameof(securityToken));


            if (validationParameters == null)
                throw LogHelper.LogArgumentNullException(nameof(validationParameters));

            if (securityToken.Length > MaximumTokenSizeInBytes)
                throw LogHelper.LogExceptionMessage(new ArgumentException(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10209, securityToken.Length, MaximumTokenSizeInBytes)));

            SamlSecurityToken samlToken;
            using (var sr = new StringReader(securityToken))
            {
                using (var reader = XmlDictionaryReader.CreateDictionaryReader(XmlReader.Create(sr)))
                {
                    samlToken = ReadToken(reader, validationParameters) as SamlSecurityToken;
                }
            }

            if (samlToken.SigningKey == null && validationParameters.RequireSignedTokens)
            {
                throw new SecurityTokenValidationException(LogMessages.IDX10213);
            }

            DateTime? notBefore = null;
            DateTime? expires = null;

            // TODO - make the same a JWT
            //if (samlToken.Conditions != null)
            //{
            //    notBefore = samlToken.Conditions.NotBefore;
            //    expires = samlToken.Conditions.Expires;
            //}

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
                var audiences = new List<string>();
                //if (samlToken.Conditions != null && samlToken.Conditions.Conditions != null)
                //{
                //    foreach (SamlCondition condition in samlToken.Conditions.Conditions)
                //    {
                //        SamlAudienceRestrictionCondition audienceRestriction = condition as SamlAudienceRestrictionCondition;
                //        if (null == audienceRestriction)
                //        {
                //            continue;
                //        }

                //        foreach (Uri uri in audienceRestriction.Audiences)
                //        {
                //            audiences.Add(uri.OriginalString);
                //        }
                //    }
                //}

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

            string issuer = null;
            issuer = samlToken.Issuer == null ? null : samlToken.Issuer;

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

            var identity = CreateClaimsIdentity(samlToken, issuer, validationParameters);
            if (validationParameters.SaveSigninToken)
            {
                identity.BootstrapContext = securityToken;
            }

            validatedToken = samlToken;
            return new ClaimsPrincipal(identity);
        }

        /// <summary>
        /// Determines if the audiences found in a <see cref="SamlSecurityToken"/> are valid.
        /// </summary>
        /// <param name="audiences">The audiences found in the <see cref="SamlSecurityToken"/>.</param>
        /// <param name="securityToken">The <see cref="SamlSecurityToken"/> being validated.</param>
        /// <param name="validationParameters"><see cref="TokenValidationParameters"/> required for validation.</param>
        /// <remarks>see <see cref="Validators.ValidateAudience"/> for additional details.</remarks>
        protected virtual void ValidateAudience(IEnumerable<string> audiences, SecurityToken securityToken, TokenValidationParameters validationParameters)
        {
            if (validationParameters == null)
                throw LogHelper.LogArgumentNullException(nameof(validationParameters));

            if (validationParameters.ValidateAudience)
            {
                if (validationParameters.AudienceValidator != null)
                    validationParameters.AudienceValidator(audiences, securityToken, validationParameters);
                else
                    Validators.ValidateAudience(audiences, securityToken, validationParameters);
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
            if (validationParameters == null)
                throw LogHelper.LogArgumentNullException(nameof(validationParameters));

            if (validationParameters.ValidateIssuer)
            {
                if (validationParameters.IssuerValidator != null)
                    return validationParameters.IssuerValidator(issuer, securityToken, validationParameters);
                else
                    return Validators.ValidateIssuer(issuer, securityToken, validationParameters);
            }

            return issuer;
        }

        /// <summary>
        /// Validates the <see cref="SecurityToken"/> was signed by a valid <see cref="SecurityKey"/>.
        /// </summary>
        /// <param name="notBefore">The 'notBefore' time found in the <see cref="SamlSecurityToken"/>.</param>
        /// <param name="expires">The 'expiration' time found in the <see cref="SamlSecurityToken"/>.</param>
        /// <param name="securityToken">The <see cref="SamlSecurityToken"/> being validated.</param>
        /// <param name="validationParameters"><see cref="TokenValidationParameters"/> required for validation.</param>
        /// <remarks><see cref="Validators.ValidateLifetime"/> for additional details.</remarks>
        protected virtual void ValidateLifetime(DateTime? notBefore, DateTime? expires, SecurityToken securityToken, TokenValidationParameters validationParameters)
        {
            Validators.ValidateLifetime(notBefore: notBefore, expires: expires, securityToken: securityToken, validationParameters: validationParameters);
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
        /// Serializes to <see cref="SamlSecurityToken"/> to a string.
        /// </summary>
        /// <param name="token">A <see cref="SamlSecurityToken"/>.</param>
        public override string WriteToken(SecurityToken token)
        {
            if (token == null)
                throw LogHelper.LogArgumentNullException(nameof(token));

            var samlToken = token as SamlSecurityToken;
            if (samlToken == null)
                throw LogHelper.LogExceptionMessage(new ArgumentException(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10400, GetType(), typeof(SamlSecurityToken), token.GetType())));

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
                throw LogHelper.LogArgumentNullException(nameof(writer));

            if (token == null)
                throw LogHelper.LogArgumentNullException(nameof(token));

            var samlSecurityToken = token as SamlSecurityToken;
            if (samlSecurityToken == null)
                throw LogHelper.LogExceptionMessage(new ArgumentException(String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10400, GetType(), typeof(SamlSecurityToken), token.GetType())));

            var envelopedWriter = new EnvelopedSignatureWriter(writer, samlSecurityToken.Assertion.SigningCredentials, Guid.NewGuid().ToString());
            serializer.WriteToken(envelopedWriter, samlSecurityToken);
        }
    }
}
