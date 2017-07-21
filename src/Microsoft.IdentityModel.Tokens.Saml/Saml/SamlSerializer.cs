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
using System.Globalization;
using System.Xml;
using Microsoft.IdentityModel.Xml;
using static Microsoft.IdentityModel.Logging.LogHelper;

namespace Microsoft.IdentityModel.Tokens.Saml
{
    /// <summary>
    /// Reads and writes Saml Assertions and tokens
    /// </summary>
    public class SamlSerializer
    {
        private DSigSerializer _dsigSerializer = new DSigSerializer();

        /// <summary>
        /// Instantiates a new instance of <see cref="SamlSerializer"/>.
        /// </summary>
        public SamlSerializer()
        {
        }

        /// <summary>
        /// Determines whether a URI is valid and can be created using the specified UriKind.
        /// Uri.TryCreate is used here, which is more lax than Uri.IsWellFormedUriString.
        /// The reason we use this function is because IsWellFormedUriString will reject valid URIs if they are IPv6 or require escaping.
        /// </summary>
        /// <param name="uriString">The string to check.</param>
        /// <param name="uriKind">The type of URI (usually UriKind.Absolute)</param>
        /// <returns>True if the URI is valid, false otherwise.</returns>
        internal static bool CanCreateValidUri(string uriString, UriKind uriKind)
        {
            return Uri.TryCreate(uriString, uriKind, out Uri tempUri);
        }

        internal static bool IsAssertionIdValid(string assertionId)
        {
            if (string.IsNullOrEmpty(assertionId))
                return false;

            // The first character of the Assertion ID should be a letter or a '_'
            return (((assertionId[0] >= 'A') && (assertionId[0] <= 'Z')) ||
                ((assertionId[0] >= 'a') && (assertionId[0] <= 'z')) ||
                (assertionId[0] == '_'));
        }

        internal static Exception LogReadException(string format, params object[] args)
        {
            return LogExceptionMessage(new SamlSecurityTokenReadException(FormatInvariant(format, args)));
        }

        internal static Exception LogReadException(string format, Exception inner, params object[] args)
        {
            return LogExceptionMessage(new SamlSecurityTokenReadException(FormatInvariant(format, args), inner));
        }

        /// <summary>
        /// Read the &lt;saml:Action> element.
        /// </summary>
        /// <param name="reader">A <see cref="XmlDictionaryReader"/> positioned at a <see cref="SamlAction"/> element.</param>
        /// <returns>A <see cref="SamlAction"/> instance.</returns>
        protected virtual SamlAction ReadAction(XmlDictionaryReader reader)
        {
            XmlUtil.CheckReaderOnEntry(reader, SamlConstants.Elements.Action, SamlConstants.Namespace);

            try
            {
                // @xsi:type
                XmlUtil.ValidateXsiType(reader, SamlConstants.Types.ActionType, SamlConstants.Namespace);

                // @Namespace - optional. If this element is absent, the default namespace is in effect.
                // @attributes
                var namespaceValue = reader.GetAttribute(SamlConstants.Attributes.Namespace);
                if (!string.IsNullOrEmpty(namespaceValue))
                {
                    if (!CanCreateValidUri(namespaceValue, UriKind.Absolute))
                        throw LogReadException(LogMessages.IDX11111, SamlConstants.Elements.Action, SamlConstants.Attributes.Namespace, namespaceValue);
                }
                else
                    namespaceValue = SamlConstants.DefaultActionNamespace;

                return new SamlAction(reader.ReadElementContentAsString(), new Uri(namespaceValue));
            }
            catch (Exception ex)
            {
                if (ex is SamlSecurityTokenReadException)
                    throw;

                throw LogReadException(LogMessages.IDX11112, ex, SamlConstants.Elements.Action, ex);
            }
        }

        /// <summary>
        /// Reads the &lt;saml:Advice> element.
        /// </summary>
        /// <remarks>
        /// <para>
        /// The Advice element has an extensibility point to allow XML elements
        /// from non-SAML namespaces to be included. By default, because the 
        /// Advice may be ignored without affecting the semantics of the 
        /// assertion, any such elements are ignored. To handle the processing
        /// of those elements, override this method.
        /// </para>
        /// </remarks>
        /// <param name="reader">A <see cref="XmlReader"/> positioned at a <see cref="SamlAdvice"/> element.</param>
        /// <returns>A <see cref="SamlAdvice"/> instance.</returns>
        protected virtual SamlAdvice ReadAdvice(XmlDictionaryReader reader)
        {
            XmlUtil.CheckReaderOnEntry(reader, SamlConstants.Elements.Advice, SamlConstants.Namespace);

            try
            {
                var advice = new SamlAdvice();

                // @xsi:type
                XmlUtil.ValidateXsiType(reader, SamlConstants.Types.AdviceType, SamlConstants.Namespace);

                // SAML Advice is an optional element and all its child elements are optional
                // too. So we may have an empty saml:Advice element in the saml token.
                if (reader.IsEmptyElement)
                {
                    // Just issue a read for the empty element.
                    reader.Read();
                    return advice;
                }

                reader.MoveToContent();
                reader.Read();
                while (reader.IsStartElement())
                {
                    if (reader.IsStartElement(SamlConstants.Elements.AssertionIdReference, SamlConstants.Namespace))
                        advice.AssertionIdReferences.Add(reader.ReadElementContentAsString());
                    else if (reader.IsStartElement(SamlConstants.Elements.Assertion, SamlConstants.Namespace))
                        advice.Assertions.Add(ReadAssertion(reader));
                    else
                        throw LogReadException(LogMessages.IDX11126, SamlConstants.Elements.Advice, reader.Name);
                }

                reader.MoveToContent();
                reader.ReadEndElement();
                return advice;
            }
            catch (Exception ex)
            {
                if (ex is SamlSecurityTokenReadException)
                    throw;

                throw LogReadException(LogMessages.IDX11112, ex, SamlConstants.Elements.Advice, ex);
            }
        }

        /// <summary>
        /// Reads a &lt;saml:Assertion> element.
        /// </summary>
        /// <param name="reader">A <see cref="XmlReader"/> positioned at a <see cref="SamlAssertion"/> element.</param>
        /// <returns>A <see cref="SamlAssertion"/> instance.</returns>
        public virtual SamlAssertion ReadAssertion(XmlReader reader)
        {
            XmlUtil.CheckReaderOnEntry(reader, SamlConstants.Elements.Assertion, SamlConstants.Namespace);

            try
            {
                var envelopeReader = new EnvelopedSignatureReader(XmlDictionaryReader.CreateDictionaryReader(reader));
                var assertion = new SamlAssertion();

                // @xsi:type
                XmlUtil.ValidateXsiType(envelopeReader, SamlConstants.Types.AssertionType, SamlConstants.Namespace);

                // @MajorVersion - required - must be "1"
                var attributeValue = envelopeReader.GetAttribute(SamlConstants.Attributes.MajorVersion, null);
                if (string.IsNullOrEmpty(attributeValue))
                    throw LogReadException(LogMessages.IDX11115, SamlConstants.Elements.Assertion, SamlConstants.Attributes.MajorVersion);

                int majorVersion = int.Parse(attributeValue, CultureInfo.InvariantCulture);
                if (majorVersion != SamlConstants.MajorVersionValue)
                    throw LogReadException(LogMessages.IDX11116, majorVersion);

                // @MinorVersion - required - must be "1"
                attributeValue = envelopeReader.GetAttribute(SamlConstants.Attributes.MinorVersion, null);
                if (string.IsNullOrEmpty(attributeValue))
                    throw LogReadException(LogMessages.IDX11115, SamlConstants.Elements.Assertion, SamlConstants.Attributes.MinorVersion);

                int minorVersion = int.Parse(attributeValue, CultureInfo.InvariantCulture);
                if (minorVersion != SamlConstants.MinorVersionValue)
                    throw LogReadException(LogMessages.IDX11117, minorVersion);

                // @AssertionId - required
                attributeValue = envelopeReader.GetAttribute(SamlConstants.Attributes.AssertionId, null);
                if (string.IsNullOrEmpty(attributeValue))
                    throw LogReadException(LogMessages.IDX11115, SamlConstants.Elements.Assertion, SamlConstants.Attributes.AssertionId);

                if (!IsAssertionIdValid(attributeValue))
                    throw LogReadException(LogMessages.IDX11121, attributeValue);

                assertion.AssertionId = attributeValue;

                // @Issuer - required
                attributeValue = envelopeReader.GetAttribute(SamlConstants.Attributes.Issuer, null);
                if (string.IsNullOrEmpty(attributeValue))
                    throw LogReadException(LogMessages.IDX11115, SamlConstants.Elements.Assertion, SamlConstants.Attributes.Issuer);

                assertion.Issuer = attributeValue;

                // @IssueInstant - required
                attributeValue = envelopeReader.GetAttribute(SamlConstants.Attributes.IssueInstant, null);
                if (string.IsNullOrEmpty(attributeValue))
                    throw LogReadException(LogMessages.IDX11115, SamlConstants.Elements.Assertion, SamlConstants.Attributes.IssueInstant);

                assertion.IssueInstant = DateTime.ParseExact(
                        attributeValue, SamlConstants.AcceptedDateTimeFormats, DateTimeFormatInfo.InvariantInfo, DateTimeStyles.None).ToUniversalTime();

                envelopeReader.MoveToContent();
                envelopeReader.Read();

                // <Conditions> 0-1
                if (envelopeReader.IsStartElement(SamlConstants.Elements.Conditions, SamlConstants.Namespace))
                    assertion.Conditions = ReadConditions(envelopeReader) ?? throw LogReadException(LogMessages.IDX11127);

                // <Advice> 0-1
                if (envelopeReader.IsStartElement(SamlConstants.Elements.Advice, SamlConstants.Namespace))
                    assertion.Advice = ReadAdvice(envelopeReader) ?? throw LogReadException(LogMessages.IDX11128);

                while (envelopeReader.IsStartElement())
                {
                    // <ds:Signature> 0-1 read by EnvelopedSignatureReader
                    // will move to next element
                    if (envelopeReader.IsStartElement(XmlSignatureConstants.Elements.Signature, XmlSignatureConstants.Namespace))
                        envelopeReader.Read();
                    else
                    {
                        // <Statement|AuthnStatement|AuthzDecisionStatement|AttributeStatement>, 0-OO
                        var statement = ReadStatement(envelopeReader);
                        if (statement == null)
                            throw LogReadException(LogMessages.IDX11129);

                        assertion.Statements.Add(statement);
                    }
                }

                if (assertion.Statements.Count == 0)
                    throw LogReadException(LogMessages.IDX11130, SamlConstants.Elements.Assertion);

                envelopeReader.MoveToContent();
                envelopeReader.ReadEndElement();

                // attach signedXml for validation of signature
                assertion.Signature = envelopeReader.Signature;
                return assertion;
            }
            catch (Exception ex)
            {
                if (ex is SamlSecurityTokenException)
                    throw;

                throw LogReadException(LogMessages.IDX11122, ex, SamlConstants.Elements.Assertion, ex);
            }
        }

        /// <summary>
        /// Reads the &lt;saml:Attribute> element.
        /// </summary>
        /// <remarks>
        /// The default implementation requires that the content of the
        /// Attribute element be a simple string. To handle complex content
        /// or content of declared simple types other than xs:string, override
        /// this method.
        /// </remarks>
        /// <param name="reader">An <see cref="XmlReader"/> positioned at a <see cref="SamlAttribute"/> element.</param>
        /// <returns>A <see cref="SamlAttribute"/> instance.</returns>
        public virtual SamlAttribute ReadAttribute(XmlDictionaryReader reader)
        {
            XmlUtil.CheckReaderOnEntry(reader, SamlConstants.Elements.Attribute, SamlConstants.Namespace);

            try
            {
                var attribute = new SamlAttribute();

                // @xsi:type
                XmlUtil.ValidateXsiType(reader, SamlConstants.Types.AttributeType, SamlConstants.Namespace);

                var name = reader.GetAttribute(SamlConstants.Attributes.AttributeName, null);
                if (string.IsNullOrEmpty(name))
                    throw LogReadException(LogMessages.IDX11115, SamlConstants.Elements.Attribute, SamlConstants.Attributes.AttributeName);

                attribute.Name = name;

                var nameSpace = reader.GetAttribute(SamlConstants.Attributes.AttributeNamespace, null);
                if (string.IsNullOrEmpty(nameSpace))
                    throw LogReadException(LogMessages.IDX11115, SamlConstants.Elements.Attribute, SamlConstants.Attributes.AttributeNamespace);

                attribute.Namespace = nameSpace;

                // TODO is this the right thing?
                attribute.ClaimType = string.IsNullOrEmpty(nameSpace) ? name : nameSpace + "/" + name;

                reader.MoveToContent();
                reader.Read();
                // We will load all Attributes as a string value by default.
                while (reader.IsStartElement(SamlConstants.Elements.AttributeValue, SamlConstants.Namespace) && !reader.IsEmptyElement)
                    attribute.Values.Add(reader.ReadElementContentAsString());

                if (attribute.Values.Count == 0)
                    throw LogReadException(LogMessages.IDX11132);

                reader.MoveToContent();
                reader.ReadEndElement();

                return attribute;
            }
            catch (Exception ex)
            {
                if (ex is SamlSecurityTokenReadException)
                    throw;

                throw LogReadException(LogMessages.IDX11112, ex, SamlConstants.Elements.Attribute, ex);
            }
        }

        /// <summary>
        /// Reads the &lt;saml:AttributeStatement> element, or a
        /// &lt;saml:Statement element that specifies an xsi:type of
        /// saml:AttributeStatementType.
        /// </summary>
        /// <param name="reader">A <see cref="XmlReader"/> positioned at a <see cref="SamlAttributeStatement"/> element.</param>
        /// <returns>A <see cref="SamlAttributeStatement"/> instance.</returns>
        protected virtual SamlAttributeStatement ReadAttributeStatement(XmlDictionaryReader reader)
        {
            XmlUtil.CheckReaderOnEntry(reader, SamlConstants.Elements.AttributeStatement, SamlConstants.Namespace);

            try
            {
                // @xsi:type
                XmlUtil.ValidateXsiType(reader, SamlConstants.Types.AttributeStatementType, SamlConstants.Namespace);

                reader.ReadStartElement();
                var statement = new SamlAttributeStatement() { Subject = ReadSubject(reader) };
                while (reader.IsStartElement())
                {
                    if (reader.IsStartElement(SamlConstants.Elements.Attribute, SamlConstants.Namespace))
                    {
                        SamlAttribute attribute = ReadAttribute(reader);
                        if (attribute == null)
                            throw LogExceptionMessage(new SamlSecurityTokenException(LogMessages.IDX11511));

                        statement.Attributes.Add(attribute);
                    }
                    else
                        break;
                }

                // Each Attribute statement should have at least one attribute.
                if (statement.Attributes.Count == 0)
                    throw LogReadException(LogMessages.IDX11131);

                reader.MoveToContent();
                reader.ReadEndElement();

                return statement;
            }
            catch (Exception ex)
            {
                if (ex is SamlSecurityTokenReadException)
                    throw;

                throw LogReadException(LogMessages.IDX11112, ex, SamlConstants.Elements.AttributeStatement, ex);
            }
        }

        /// <summary>
        /// Reads the &lt;saml:AudienceRestriction> element or a 
        /// &lt;saml:Condition> element that specifies an xsi:type
        /// of saml:AudienceRestrictionType.
        /// </summary>
        /// <param name="reader">A <see cref="XmlReader"/> positioned at a <see cref="SamlAudienceRestrictionCondition"/> element.</param>
        /// <returns></returns>
        protected virtual SamlAudienceRestrictionCondition ReadAudienceRestrictionCondition(XmlDictionaryReader reader)
        {
            XmlUtil.CheckReaderOnEntry(reader, SamlConstants.Elements.AudienceRestrictionCondition, SamlConstants.Namespace);

            try
            {
                // disallow empty
                if (reader.IsEmptyElement)
                    throw LogReadException(LogMessages.IDX11123, SamlConstants.Elements.AudienceRestrictionCondition);

                // @xsi:type -- if we're a <Condition> element, this declaration must be present
                XmlUtil.ValidateXsiType(reader, SamlConstants.Types.AudienceRestrictionType, SamlConstants.Namespace);

                reader.ReadStartElement();
                var audienceRestrictionCondition = new SamlAudienceRestrictionCondition();

                while (reader.IsStartElement())
                {
                    if (reader.IsStartElement(SamlConstants.Elements.Audience, SamlConstants.Namespace))
                    {
                        string audience = reader.ReadElementContentAsString();
                        if (string.IsNullOrEmpty(audience))
                            throw LogReadException(LogMessages.IDX11125, SamlConstants.Elements.Audience);

                        audienceRestrictionCondition.Audiences.Add(audience);
                    }
                    else
                        throw LogReadException(LogMessages.IDX11134, SamlConstants.Elements.Audience, reader.Name);
                }

                if (audienceRestrictionCondition.Audiences.Count == 0)
                    throw LogReadException(LogMessages.IDX11120, SamlConstants.Elements.Audience, SamlConstants.Elements.AudienceRestrictionCondition);

                reader.MoveToContent();
                reader.ReadEndElement();

                return audienceRestrictionCondition;
            }
            catch (Exception ex)
            {
                if (ex is SamlSecurityTokenReadException)
                    throw;

                throw LogReadException(LogMessages.IDX11112, ex, SamlConstants.Elements.Audience, ex);
            }
        }

        /// <summary>
        /// Read the saml:AuthenticationStatement.
        /// </summary>
        /// <param name="reader">XmlReader positioned at a saml:AuthenticationStatement.</param>
        /// <returns>SamlAuthenticationStatement</returns>
        /// <exception cref="ArgumentNullException">The input parameter 'reader' is null.
        /// or the statement contains a unknown child element.</exception>
        protected virtual SamlAuthenticationStatement ReadAuthenticationStatement(XmlDictionaryReader reader)
        {
            XmlUtil.CheckReaderOnEntry(reader, SamlConstants.Elements.AuthenticationStatement, SamlConstants.Namespace);

            try
            {
                // @xsi:type
                XmlUtil.ValidateXsiType(reader, SamlConstants.Types.AuthnContextType, SamlConstants.Namespace);

                var authenticationStatement = new SamlAuthenticationStatement();

                var authInstance = reader.GetAttribute(SamlConstants.Attributes.AuthenticationInstant, null);
                if (string.IsNullOrEmpty(authInstance))
                    throw LogReadException(LogMessages.IDX11115, SamlConstants.Elements.AuthenticationStatement, SamlConstants.Attributes.AuthenticationInstant);

                authenticationStatement.AuthenticationInstant = DateTime.ParseExact(
                    authInstance, SamlConstants.AcceptedDateTimeFormats, DateTimeFormatInfo.InvariantInfo, DateTimeStyles.None).ToUniversalTime();

                var authenticationMethod = reader.GetAttribute(SamlConstants.Attributes.AuthenticationMethod, null);
                if (string.IsNullOrEmpty(authenticationMethod))
                    throw LogReadException(LogMessages.IDX11115, SamlConstants.Elements.AuthenticationStatement, SamlConstants.Attributes.AuthenticationMethod);

                authenticationStatement.AuthenticationMethod = authenticationMethod;

                reader.ReadStartElement();
                authenticationStatement.Subject = ReadSubject(reader);
                if (reader.IsStartElement(SamlConstants.Elements.SubjectLocality, SamlConstants.Namespace))
                {
                    authenticationStatement.DnsAddress = reader.GetAttribute(SamlConstants.Elements.SubjectLocalityDNSAddress, null);
                    authenticationStatement.IPAddress = reader.GetAttribute(SamlConstants.Elements.SubjectLocalityIPAddress, null);

                    bool isEmptyElement = reader.IsEmptyElement;
                    reader.MoveToContent();
                    reader.Read();

                    if (!isEmptyElement)
                        reader.ReadEndElement();
                }

                while (reader.IsStartElement())
                {
                    authenticationStatement.AuthorityBindings.Add(ReadAuthorityBinding(reader));
                }

                reader.MoveToContent();
                reader.ReadEndElement();

                return authenticationStatement;
            }
            catch (Exception ex)
            {
                if (ex is SamlSecurityTokenReadException)
                    throw;

                throw LogReadException(LogMessages.IDX11112, ex, SamlConstants.Elements.AuthenticationStatement, ex);
            }
        }

        /// <summary>
        /// Reads a &lt;saml:Binding> element.
        /// </summary>
        /// <param name="reader">A <see cref="XmlReader"/> positioned at a <see cref="SamlAssertion"/> element.</param>
        /// <returns>A <see cref="SamlAuthorityBinding"/> instance.</returns>
        protected virtual SamlAuthorityBinding ReadAuthorityBinding(XmlDictionaryReader reader)
        {
            XmlUtil.CheckReaderOnEntry(reader, SamlConstants.Elements.AuthorityBinding, SamlConstants.Namespace);

            try
            {
                // @xsi:type
                XmlUtil.ValidateXsiType(reader, SamlConstants.Types.AuthorityBindingType, SamlConstants.Namespace);

                var authKind = reader.GetAttribute(SamlConstants.Attributes.AuthorityKind, null);
                if (string.IsNullOrEmpty(authKind))
                    throw LogReadException(LogMessages.IDX11115, SamlConstants.Elements.AuthorityBinding, SamlConstants.Attributes.AuthorityKind);

                string[] authKindParts = authKind.Split(':');
                if (authKindParts.Length > 2)
                    throw LogReadException(LogMessages.IDX11108, authKind);

                string localName;
                string prefix;
                string nameSpace;
                if (authKindParts.Length == 2)
                {
                    prefix = authKindParts[0];
                    localName = authKindParts[1];
                }
                else
                {
                    prefix = string.Empty;
                    localName = authKindParts[0];
                }

                nameSpace = reader.LookupNamespace(prefix);
                var authorityKind = new XmlQualifiedName(localName, nameSpace);

                var binding = reader.GetAttribute(SamlConstants.Attributes.Binding, null);
                if (string.IsNullOrEmpty(binding))
                    throw LogExceptionMessage(new SamlSecurityTokenException(LogMessages.IDX11512));

                var location = reader.GetAttribute(SamlConstants.Attributes.Location, null);
                if (string.IsNullOrEmpty(location))
                    throw LogExceptionMessage(new SamlSecurityTokenException(LogMessages.IDX11513));

                bool isEmptyElement = reader.IsEmptyElement;
                reader.MoveToContent();
                reader.Read();

                if (!isEmptyElement)
                    reader.ReadEndElement();

                return new SamlAuthorityBinding(authorityKind, binding, location);
            }
            catch (Exception ex)
            {
                if (ex is SamlSecurityTokenReadException)
                    throw;

                throw LogReadException(LogMessages.IDX11112, ex, SamlConstants.Elements.AuthorityBinding, ex);
            }
        }

        /// <summary>
        /// Reads the &lt;saml:AuthzDecisionStatement> element or a
        /// &lt;saml:Statement element that specifies an xsi:type of
        /// saml:AuthzDecisionStatementType.
        /// </summary>
        /// <param name="reader">A <see cref="XmlReader"/> positioned at a <see cref="SamlAuthorizationDecisionStatement"/> element.</param>
        /// <returns>A <see cref="SamlAuthorizationDecisionStatement"/> instance.</returns>
        protected virtual SamlAuthorizationDecisionStatement ReadAuthorizationDecisionStatement(XmlDictionaryReader reader)
        {
            XmlUtil.CheckReaderOnEntry(reader, SamlConstants.Elements.AuthorizationDecisionStatement, SamlConstants.Namespace);

            try
            {
                // @xsi:type
                XmlUtil.ValidateXsiType(reader, SamlConstants.Types.AuthzDecisionStatementType, SamlConstants.Namespace, false);

                var statement = new SamlAuthorizationDecisionStatement();

                var resource = reader.GetAttribute(SamlConstants.Attributes.Resource, null);
                if (string.IsNullOrEmpty(resource))
                    throw LogReadException(LogMessages.IDX11115, SamlConstants.Elements.AuthorizationDecisionStatement, SamlConstants.Attributes.Resource);

                statement.Resource = resource;

                var decisionString = reader.GetAttribute(SamlConstants.Attributes.Decision, null);
                if (string.IsNullOrEmpty(decisionString))
                    throw LogReadException(LogMessages.IDX11115, SamlConstants.Elements.AuthorizationDecisionStatement, SamlConstants.Attributes.Decision);

                if (decisionString.Equals(SamlAccessDecision.Deny.ToString(), StringComparison.OrdinalIgnoreCase))
                    statement.AccessDecision = SamlAccessDecision.Deny;
                else if (decisionString.Equals(SamlAccessDecision.Permit.ToString(), StringComparison.OrdinalIgnoreCase))
                    statement.AccessDecision = SamlAccessDecision.Permit;
                else
                    statement.AccessDecision = SamlAccessDecision.Indeterminate;

                reader.ReadStartElement();
                statement.Subject = ReadSubject(reader);
                while (reader.IsStartElement())
                {
                    if (reader.IsStartElement(SamlConstants.Elements.Action, SamlConstants.Namespace))
                        statement.Actions.Add(ReadAction(reader));
                    else if (reader.IsStartElement(SamlConstants.Elements.Evidence, SamlConstants.Namespace))
                    {
                        if (statement.Evidence != null)
                            throw LogReadException(LogMessages.IDX11100, SamlConstants.Elements.Evidence);

                        statement.Evidence = ReadEvidence(reader);
                    }
                    else
                        throw LogReadException(LogMessages.IDX11124, reader.Name, SamlConstants.Elements.AuthorizationDecisionStatement);
                }

                if (statement.Actions.Count == 0)
                    throw LogReadException(LogMessages.IDX11102);

                reader.MoveToContent();
                reader.ReadEndElement();

                return statement;
            }
            catch (Exception ex)
            {
                if (ex is SamlSecurityTokenReadException)
                    throw;

                throw LogReadException(LogMessages.IDX11112, ex, SamlConstants.Elements.AuthorizationDecisionStatement, ex);
            }
        }

        /// <summary>
        /// Reads the &lt;saml:Condition> element.
        /// </summary>
        /// <param name="reader">A <see cref="XmlReader"/> positioned at a <see cref="SamlCondition"/> element.</param>
        /// <returns>A <see cref="SamlCondition"/> instance.</returns>
        protected virtual SamlCondition ReadCondition(XmlDictionaryReader reader)
        {
            if (reader == null)
                throw LogArgumentNullException(nameof(reader));

            if (reader.IsStartElement(SamlConstants.Elements.AudienceRestrictionCondition, SamlConstants.Namespace))
                return ReadAudienceRestrictionCondition(reader);
            else if (reader.IsStartElement(SamlConstants.Elements.DoNotCacheCondition, SamlConstants.Namespace))
                return ReadDoNotCacheCondition(reader);
            else
                throw LogReadException(LogMessages.IDX11118, reader.Name);
        }

        /// <summary>
        /// Reads the &lt;saml:Conditions> element.
        /// </summary>
        /// <remarks>
        /// To handle custom &lt;saml:Conditions> elements, override this
        /// method.
        /// </remarks>
        /// <param name="reader">A <see cref="XmlReader"/> positioned at a <see cref="SamlConditions"/> element.</param>
        /// <returns>A <see cref="SamlConditions"/> instance.</returns>
        protected virtual SamlConditions ReadConditions(XmlDictionaryReader reader)
        {
            XmlUtil.CheckReaderOnEntry(reader, SamlConstants.Elements.Conditions, SamlConstants.Namespace);

            try
            {
                // @xsi:type
                XmlUtil.ValidateXsiType(reader, SamlConstants.Types.ConditionsType, SamlConstants.Namespace);

                var nbf = DateTimeUtil.GetMinValue(DateTimeKind.Utc);
                var time = reader.GetAttribute(SamlConstants.Attributes.NotBefore, null);
                if (!string.IsNullOrEmpty(time))
                    nbf = DateTime.ParseExact(time, SamlConstants.AcceptedDateTimeFormats, DateTimeFormatInfo.InvariantInfo, DateTimeStyles.None).ToUniversalTime();

                var notOnOrAfter = DateTimeUtil.GetMaxValue(DateTimeKind.Utc);
                time = reader.GetAttribute(SamlConstants.Attributes.NotOnOrAfter, null);
                if (!string.IsNullOrEmpty(time))
                    notOnOrAfter = DateTime.ParseExact(time, SamlConstants.AcceptedDateTimeFormats, DateTimeFormatInfo.InvariantInfo, DateTimeStyles.None).ToUniversalTime();

                var conditions = new SamlConditions(nbf, notOnOrAfter);
                // Saml Conditions element is an optional element and all its child element
                // are optional as well. So we can have a empty <saml:Conditions /> element
                // in a valid Saml token.
                if (reader.IsEmptyElement)
                {
                    // Just issue a read to read the Empty element.
                    reader.MoveToContent();
                    reader.Read();
                    return conditions;
                }

                reader.ReadStartElement();
                while (reader.IsStartElement())
                {
                    conditions.Conditions.Add(ReadCondition(reader));
                }

                reader.ReadEndElement();

                return conditions;
            }
            catch (Exception ex)
            {
                if (ex is SamlSecurityTokenReadException)
                    throw;

                throw LogReadException(LogMessages.IDX11112, ex, SamlConstants.Elements.Conditions, ex);
            }
        }

        /// <summary>
        /// Reads the &lt;saml:DoNotCacheCondition> element.
        /// </summary>
        /// <param name="reader">A <see cref="XmlReader"/> positioned at a <see cref="SamlConditions"/> element.</param>
        /// <returns>A <see cref="SamlDoNotCacheCondition"/> instance.</returns>
        protected virtual SamlDoNotCacheCondition ReadDoNotCacheCondition(XmlDictionaryReader reader)
        {
            XmlUtil.CheckReaderOnEntry(reader, SamlConstants.Elements.DoNotCacheCondition, SamlConstants.Namespace);

            try
            {
                // @xsi:type
                XmlUtil.ValidateXsiType(reader, SamlConstants.Types.DoNotCacheConditionType, SamlConstants.Namespace);

                // TODO what is this about
                // saml:DoNotCacheCondition is a empty element. So just issue a read for
                // the empty element.
                if (reader.IsEmptyElement)
                {
                    reader.MoveToContent();
                    reader.Read();
                    return new SamlDoNotCacheCondition();
                }

                reader.MoveToContent();
                reader.Read();
                reader.ReadEndElement();

                return new SamlDoNotCacheCondition();
            }
            catch (Exception ex)
            {
                if (ex is SamlSecurityTokenReadException)
                    throw;

                throw LogReadException(LogMessages.IDX11112, ex, SamlConstants.Elements.DoNotCacheCondition, ex);
            }
        }

        /// <summary>
        /// Reads the &lt;saml:Evidence> element.
        /// </summary>
        /// <param name="reader">A <see cref="XmlReader"/> positioned at a <see cref="SamlEvidence"/> element.</param>
        /// <returns>A <see cref="SamlEvidence"/> instance.</returns>
        protected virtual SamlEvidence ReadEvidence(XmlDictionaryReader reader)
        {
            XmlUtil.CheckReaderOnEntry(reader, SamlConstants.Elements.Evidence, SamlConstants.Namespace);

            try
            {
                var evidence = new SamlEvidence();

                reader.Read();
                while (reader.IsStartElement())
                {
                    if (reader.IsStartElement(SamlConstants.Elements.AssertionIdReference, SamlConstants.Namespace))
                        evidence.AssertionIdReferences.Add(reader.ReadElementContentAsString());
                    else if (reader.IsStartElement(SamlConstants.Elements.Assertion, SamlConstants.Namespace))
                        evidence.Assertions.Add(ReadAssertion(reader));
                    else
                        throw LogReadException(LogMessages.IDX11120, SamlConstants.Elements.Evidence, reader.Name);
                }

                if ((evidence.AssertionIdReferences.Count == 0) && (evidence.Assertions.Count == 0))
                    throw LogReadException(LogMessages.IDX11133);

                reader.MoveToContent();
                reader.ReadEndElement();

                return evidence;
            }
            catch (Exception ex)
            {
                if (ex is SamlSecurityTokenReadException)
                    throw;

                throw LogReadException(LogMessages.IDX11112, ex, SamlConstants.Elements.Evidence, ex);
            }
        }

        /// <summary>
        /// Reads the &lt;saml:Statement> element.
        /// </summary>
        /// <param name="reader">A <see cref="XmlReader"/> positioned at a <see cref="SamlStatement"/> element.</param>
        /// <returns>An instance of <see cref="SamlStatement"/> derived type.</returns>
        /// <remarks>
        /// The default implementation only handles Statement elements which
        /// specify an xsi:type of saml:AttributeStatementType,
        /// saml:AuthnStatementType, and saml:AuthzDecisionStatementType. To
        /// handle custom statements, override this method.
        /// </remarks>
        protected virtual SamlStatement ReadStatement(XmlDictionaryReader reader)
        {
            if (reader == null)
                throw LogArgumentNullException(nameof(reader));

            if (reader.IsStartElement(SamlConstants.Elements.AuthenticationStatement, SamlConstants.Namespace))
                return ReadAuthenticationStatement(reader);
            else if (reader.IsStartElement(SamlConstants.Elements.AttributeStatement, SamlConstants.Namespace))
                return ReadAttributeStatement(reader);
            else if (reader.IsStartElement(SamlConstants.Elements.AuthorizationDecisionStatement, SamlConstants.Namespace))
                return ReadAuthorizationDecisionStatement(reader);
            else
                throw LogReadException(LogMessages.IDX11126, SamlConstants.Elements.Assertion, reader.Name);
        }

        /// <summary>
        /// Read the SamlSubject from the XmlReader.
        /// </summary>
        /// <param name="reader">A <see cref="XmlReader"/> positioned at a <see cref="SamlSubject"/> element.</param>
        /// <returns>An instance of <see cref="SamlSubject"/> .</returns>
        protected virtual SamlSubject ReadSubject(XmlDictionaryReader reader)
        {
            XmlUtil.CheckReaderOnEntry(reader, SamlConstants.Elements.Subject, SamlConstants.Namespace);

            try
            {
                var subject = new SamlSubject();

                reader.Read();

                if (reader.IsStartElement(SamlConstants.Elements.NameIdentifier, SamlConstants.Namespace))
                {
                    // @xsi:type
                    XmlUtil.ValidateXsiType(reader, SamlConstants.Types.NameIDType, SamlConstants.Namespace);

                    subject.NameFormat = reader.GetAttribute(SamlConstants.Attributes.NameIdentifierFormat, null);
                    subject.NameQualifier = reader.GetAttribute(SamlConstants.Attributes.NameIdentifierNameQualifier, null);

                    // TODO - check for empty element
                    reader.MoveToContent();
                    subject.Name = reader.ReadElementContentAsString();

                    if (string.IsNullOrEmpty(subject.Name))
                        throw LogReadException(LogMessages.IDX11104);
                }

                if (reader.IsStartElement(SamlConstants.Elements.SubjectConfirmation, SamlConstants.Namespace))
                {
                    // @xsi:type
                    XmlUtil.ValidateXsiType(reader, SamlConstants.Types.SubjectConfirmationDataType, SamlConstants.Namespace);

                    reader.MoveToContent();
                    reader.Read();

                    while (reader.IsStartElement(SamlConstants.Elements.SubjectConfirmationMethod, SamlConstants.Namespace))
                    {
                        string method = reader.ReadElementContentAsString();
                        if (string.IsNullOrEmpty(method))
                            throw LogReadException(LogMessages.IDX11135, SamlConstants.Elements.SubjectConfirmationMethod);

                        subject.ConfirmationMethods.Add(method);
                    }

                    // A SubjectConfirmaton clause should specify at least one ConfirmationMethod.
                    if (subject.ConfirmationMethods.Count == 0)
                        throw LogReadException(LogMessages.IDX11114, SamlConstants.Elements.SubjectConfirmationMethod);

                    // An Authentication protocol specified in the confirmation method might need this
                    // data. Just store this content value as string.
                    if (reader.IsStartElement(SamlConstants.Elements.SubjectConfirmationData, SamlConstants.Namespace))                        
                        subject.ConfirmationData = reader.ReadElementContentAsString();

                    if (reader.IsStartElement(XmlSignatureConstants.Elements.KeyInfo, XmlSignatureConstants.Namespace))
                    {
                        subject.KeyInfo = _dsigSerializer.ReadKeyInfo(reader);
                    }

                    if ((subject.ConfirmationMethods.Count == 0) && (string.IsNullOrEmpty(subject.Name)))
                        throw LogReadException(LogMessages.IDX11107);

                    reader.MoveToContent();
                    reader.ReadEndElement();
                }

                reader.MoveToContent();
                reader.ReadEndElement();

                return subject;
            }
            catch (Exception ex)
            {
                if (ex is SamlSecurityTokenReadException)
                    throw;

                throw LogReadException(LogMessages.IDX11112, ex, SamlConstants.Elements.Subject, ex);
            }
        }

        //protected virtual void WriteAction(XmlWriter writer, SamlAction action)
        //{
        //    if (writer == null)
        //        throw LogHelper.LogArgumentNullException(nameof(writer));

        //    if (action == null)
        //        throw LogHelper.LogArgumentNullException(nameof(action));

        //    writer.WriteStartElement(SamlConstants.PreferredPrefix, SamlConstants.Elements.Action, SamlConstants.Namespace);
        //    if (!string.IsNullOrEmpty(action.Namespace))
        //    {
        //        writer.WriteStartAttribute(SamlConstants.Attributes.ActionNamespaceAttribute, null);
        //        writer.WriteString(action.Namespace);
        //        writer.WriteEndAttribute();
        //    }

        //    writer.WriteString(action.Action);
        //    writer.WriteEndElement();
        //}

        //protected virtual void WriteAdvice(XmlWriter writer, SamlAdvice advice)
        //{
        //    if (writer == null)
        //        throw LogHelper.LogArgumentNullException(nameof(writer));

        //    if (advice == null)
        //        throw LogHelper.LogArgumentNullException(nameof(advice));

        //    writer.WriteStartElement(SamlConstants.PreferredPrefix, SamlConstants.Elements.Advice, SamlConstants.Namespace);

        //    foreach (var reference in advice.AssertionIdReferences)
        //    {
        //        writer.WriteStartElement(SamlConstants.PreferredPrefix, SamlConstants.Elements.AssertionIdReference, SamlConstants.Namespace);
        //        writer.WriteString(reference);
        //        writer.WriteEndElement();
        //    }

        //    foreach (var assertion in advice.Assertions)
        //        WriteAssertion(writer, assertion);

        //    writer.WriteEndElement();
        //}

        //public virtual void WriteAssertion(XmlWriter writer, SamlAssertion assertion)
        //{
        //    if (writer == null)
        //        throw LogHelper.LogArgumentNullException(nameof(writer));

        //    if (assertion == null)
        //        throw LogHelper.LogArgumentNullException(nameof(assertion));

        //    if (string.IsNullOrEmpty(assertion.AssertionId))
        //        throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLAssertionIdRequired"));

        //    if (!IsAssertionIdValid(assertion.AssertionId))
        //        throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLAssertionIDIsInvalid"));

        //    if (string.IsNullOrEmpty(assertion.Issuer))
        //        throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLAssertionIssuerRequired"));

        //    if (assertion.Statements.Count == 0)
        //        throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLAssertionRequireOneStatement"));

        //    try
        //    {
        //        writer.WriteStartElement(SamlConstants.PreferredPrefix, SamlConstants.Elements.Assertion, SamlConstants.Namespace);
        //        writer.WriteStartAttribute(SamlConstants.Attributes.MajorVersion, null);
        //        writer.WriteValue(SamlConstants.MajorVersionValue);
        //        writer.WriteEndAttribute();
        //        writer.WriteStartAttribute(SamlConstants.Attributes.MinorVersion, null);
        //        writer.WriteValue(SamlConstants.MinorVersionValue);
        //        writer.WriteEndAttribute();
        //        writer.WriteStartAttribute(SamlConstants.Attributes.AssertionId, null);
        //        writer.WriteString(assertion.AssertionId);
        //        writer.WriteEndAttribute();
        //        writer.WriteStartAttribute(SamlConstants.Attributes.Issuer, null);
        //        writer.WriteString(assertion.Issuer);
        //        writer.WriteEndAttribute();
        //        writer.WriteStartAttribute(SamlConstants.Attributes.IssueInstant, null);
        //        writer.WriteString(assertion.IssueInstant.ToString(SamlConstants.GeneratedDateTimeFormat, CultureInfo.InvariantCulture));
        //        writer.WriteEndAttribute();

        //        // Write out conditions
        //        if (assertion.Conditions != null)
        //            WriteConditions(writer, assertion.Conditions);

        //        // Write out advice if there is one
        //        if (assertion.Advice != null)
        //            WriteAdvice(writer, assertion.Advice);

        //        foreach (var statement in assertion.Statements)
        //            WriteStatement(writer, statement);

        //        writer.WriteEndElement();
        //    }
        //    catch (Exception ex)
        //    {
        //        throw LogHelper.LogExceptionMessage(new SecurityTokenException($"SAMLTokenNotSerialized, {ex}"));
        //    }
        //}

        //public virtual void WriteAttribute(XmlWriter writer, SamlAttribute attribute)

        //{
        //    if (writer == null)
        //        throw LogHelper.LogArgumentNullException(nameof(writer));

        //    if (attribute == null)
        //        throw LogHelper.LogArgumentNullException(nameof(attribute));

        //    writer.WriteStartElement(SamlConstants.PreferredPrefix, SamlConstants.Elements.Attribute, SamlConstants.Namespace);
        //    writer.WriteStartAttribute(SamlConstants.Attributes.AttributeName, null);
        //    writer.WriteString(attribute.Name);
        //    writer.WriteEndAttribute();
        //    writer.WriteStartAttribute(SamlConstants.Attributes.AttributeNamespace, null);
        //    writer.WriteString(attribute.Namespace);
        //    writer.WriteEndAttribute();

        //    foreach (var attributeValue in attribute.AttributeValues)
        //    {
        //        if (string.IsNullOrEmpty(attributeValue))
        //            throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SamlAttributeValueCannotBeNull"));

        //        writer.WriteElementString(SamlConstants.PreferredPrefix, SamlConstants.Elements.AttributeValue, SamlConstants.Namespace, attributeValue);
        //    }

        //    writer.WriteEndElement();
        //}

        //protected virtual void WriteAttributeStatement(XmlWriter writer, SamlAttributeStatement statement)
        //{
        //    if (writer == null)
        //        throw LogHelper.LogArgumentNullException(nameof(writer));

        //    if (statement == null)
        //        throw LogHelper.LogArgumentNullException(nameof(statement));

        //    writer.WriteStartElement(SamlConstants.PreferredPrefix, SamlConstants.Elements.AttributeStatement, SamlConstants.Namespace);

        //    WriteSubject(writer, statement.Subject);
        //    foreach (var attribute in statement.Attributes)
        //        WriteAttribute(writer, attribute);

        //    writer.WriteEndElement();
        //}

        //protected virtual void WriteAudienceRestrictionCondition(XmlWriter writer, SamlAudienceRestrictionCondition condition)
        //{
        //    if (condition == null)
        //        throw LogHelper.LogArgumentNullException(nameof(condition));

        //    if (writer == null)
        //        throw LogHelper.LogArgumentNullException(nameof(writer));

        //    writer.WriteStartElement(SamlConstants.PreferredPrefix, SamlConstants.Elements.AudienceRestrictionCondition, SamlConstants.Namespace);

        //    foreach (var audience in condition.Audiences)
        //    {
        //        // TODO - should we throw ?
        //        if (audience != null)
        //            writer.WriteElementString(SamlConstants.Elements.Audience, SamlConstants.Namespace, audience.AbsoluteUri);
        //    }

        //    writer.WriteEndElement();
        //}

        //protected virtual void WriteAuthenticationStatement(XmlWriter writer, SamlAuthenticationStatement statement)
        //{
        //    if (writer == null)
        //        throw LogHelper.LogArgumentNullException(nameof(writer));

        //    if (statement == null)
        //        throw LogHelper.LogArgumentNullException(nameof(statement));

        //    writer.WriteStartElement(SamlConstants.PreferredPrefix, SamlConstants.Elements.AuthenticationStatement, SamlConstants.Namespace);
        //    writer.WriteStartAttribute(SamlConstants.Attributes.AuthenticationMethod, null);
        //    writer.WriteString(statement.AuthenticationMethod);
        //    writer.WriteEndAttribute();
        //    writer.WriteStartAttribute(SamlConstants.Attributes.AuthenticationInstant, null);
        //    writer.WriteString(statement.AuthenticationInstant.ToString(SamlConstants.GeneratedDateTimeFormat, CultureInfo.InvariantCulture));
        //    writer.WriteEndAttribute();

        //    WriteSubject(writer, statement.Subject);

        //    if ((!string.IsNullOrEmpty(statement.IPAddress)) || (!string.IsNullOrEmpty(statement.DnsAddress)))
        //    {
        //        writer.WriteStartElement(SamlConstants.PreferredPrefix, SamlConstants.Elements.SubjectLocality, SamlConstants.Namespace);

        //        if (!string.IsNullOrEmpty(statement.IPAddress))
        //        {
        //            writer.WriteStartAttribute(SamlConstants.Attributes.SubjectLocalityIPAddress, null);
        //            writer.WriteString(statement.IPAddress);
        //            writer.WriteEndAttribute();
        //        }

        //        if (!string.IsNullOrEmpty(statement.DnsAddress))
        //        {
        //            writer.WriteStartAttribute(SamlConstants.Attributes.SubjectLocalityDNSAddress, null);
        //            writer.WriteString(statement.DnsAddress);
        //            writer.WriteEndAttribute();
        //        }

        //        writer.WriteEndElement();
        //    }

        //    foreach (var binding in statement.AuthorityBindings)
        //    {
        //        WriteAuthorityBinding(writer, binding);
        //    }

        //    writer.WriteEndElement();
        //}

        //protected virtual void WriteAuthorityBinding(XmlWriter writer, SamlAuthorityBinding authorityBinding)
        //{
        //    if (writer == null)
        //        throw LogHelper.LogArgumentNullException(nameof(writer));

        //    if (authorityBinding == null)
        //        throw LogHelper.LogArgumentNullException(nameof(authorityBinding));

        //    writer.WriteStartElement(SamlConstants.PreferredPrefix, SamlConstants.Elements.AuthorityBinding, SamlConstants.Namespace);

        //    string prefix = null;
        //    if (!string.IsNullOrEmpty(authorityBinding.AuthorityKind.Namespace))
        //    {
        //        writer.WriteAttributeString(string.Empty, SamlConstants.NamespaceAttributePrefix, null, authorityBinding.AuthorityKind.Namespace);
        //        prefix = writer.LookupPrefix(authorityBinding.AuthorityKind.Namespace);
        //    }

        //    writer.WriteStartAttribute(SamlConstants.Attributes.AuthorityKind, null);
        //    if (string.IsNullOrEmpty(prefix))
        //        writer.WriteString(authorityBinding.AuthorityKind.Name);
        //    else
        //        writer.WriteString(prefix + ":" + authorityBinding.AuthorityKind.Name);
        //    writer.WriteEndAttribute();

        //    writer.WriteStartAttribute(SamlConstants.Attributes.Location, null);
        //    writer.WriteString(authorityBinding.Location);
        //    writer.WriteEndAttribute();

        //    writer.WriteStartAttribute(SamlConstants.Attributes.Binding, null);
        //    writer.WriteString(authorityBinding.Binding);
        //    writer.WriteEndAttribute();

        //    writer.WriteEndElement();
        //}

        //protected virtual void WriteAuthorizationDecisionStatement(XmlWriter writer, SamlAuthorizationDecisionStatement statement)
        //{
        //    if (writer == null)
        //        throw LogHelper.LogArgumentNullException(nameof(writer));

        //    if (statement == null)
        //        throw LogHelper.LogArgumentNullException(nameof(statement));

        //    writer.WriteStartElement(SamlConstants.PreferredPrefix, SamlConstants.Elements.AuthorizationDecisionStatement, SamlConstants.Namespace);

        //    writer.WriteStartAttribute(SamlConstants.Attributes.Decision, null);
        //    writer.WriteString(statement.AccessDecision.ToString());
        //    writer.WriteEndAttribute();

        //    writer.WriteStartAttribute(SamlConstants.Attributes.Resource, null);
        //    writer.WriteString(statement.Resource);
        //    writer.WriteEndAttribute();

        //    WriteSubject(writer, statement.Subject);

        //    foreach (var action in statement.Actions)
        //        WriteAction(writer, action);

        //    if (statement.Evidence != null)
        //        WriteEvidence(writer, statement.Evidence);

        //    writer.WriteEndElement();
        //}

        //protected virtual void WriteCondition(XmlWriter writer, SamlCondition condition)
        //{
        //    var audienceRestrictionCondition = condition as SamlAudienceRestrictionCondition;
        //    if (audienceRestrictionCondition != null)
        //        WriteAudienceRestrictionCondition(writer, audienceRestrictionCondition);

        //    var donotCacheCondition = condition as SamlDoNotCacheCondition;
        //    if (donotCacheCondition != null)
        //        WriteDoNotCacheCondition(writer, donotCacheCondition);
        //}

        //protected virtual void WriteConditions(XmlWriter writer, SamlConditions conditions)
        //{
        //    if (writer == null)
        //        throw LogHelper.LogArgumentNullException(nameof(writer));

        //    if (conditions == null)
        //        throw LogHelper.LogArgumentNullException(nameof(conditions));

        //    writer.WriteStartElement(SamlConstants.PreferredPrefix, SamlConstants.Elements.Conditions, SamlConstants.Namespace);
        //    if (conditions.NotBefore != DateTimeUtil.GetMinValue(DateTimeKind.Utc))
        //    {
        //        writer.WriteStartAttribute(SamlConstants.Attributes.NotBefore, null);
        //        writer.WriteString(conditions.NotBefore.ToString(SamlConstants.GeneratedDateTimeFormat, DateTimeFormatInfo.InvariantInfo));
        //        writer.WriteEndAttribute();
        //    }

        //    if (conditions.NotOnOrAfter != DateTimeUtil.GetMaxValue(DateTimeKind.Utc))
        //    {
        //        writer.WriteStartAttribute(SamlConstants.Attributes.NotOnOrAfter, null);
        //        writer.WriteString(conditions.NotOnOrAfter.ToString(SamlConstants.GeneratedDateTimeFormat, DateTimeFormatInfo.InvariantInfo));
        //        writer.WriteEndAttribute();
        //    }

        //    foreach (var condition in conditions.Conditions)
        //        WriteCondition(writer, condition);

        //    writer.WriteEndElement();
        //}

        //internal void WriteTo(XmlWriter writer, SamlSerializer samlSerializer)
        //{
        //    if (writer == null)
        //        throw LogHelper.LogArgumentNullException(nameof(writer));

        //    XmlDictionaryWriter dictionaryWriter = XmlDictionaryWriter.CreateDictionaryWriter(writer);

        //    if (this.signingCredentials != null)
        //    {
        //        using (HashAlgorithm hash = CryptoProviderFactory.Default.CreateHashAlgorithm(this.signingCredentials.Algorithm))
        //        {
        //            this.hashStream = new HashStream(hash);
        //            this.dictionaryManager = samlSerializer.DictionaryManager;
        //            SamlDelegatingWriter delegatingWriter = new SamlDelegatingWriter(dictionaryWriter, this.hashStream, this, samlSerializer.DictionaryManager.ParentDictionary);
        //            this.WriteXml(delegatingWriter, samlSerializer);
        //        }
        //    }
        //    else
        //    {
        //        this.tokenStream.SetElementExclusion(null, null);
        //        this.tokenStream.WriteTo(dictionaryWriter, samlSerializer.DictionaryManager);
        //    }
        //}

        //protected virtual void WriteDoNotCacheCondition(XmlWriter writer, SamlDoNotCacheCondition condition)
        //{
        //    if (writer == null)
        //        throw LogHelper.LogArgumentNullException(nameof(writer));

        //    writer.WriteStartElement(SamlConstants.PreferredPrefix, SamlConstants.Elements.DoNotCacheCondition, SamlConstants.Namespace);
        //    writer.WriteEndElement();
        //}

        //protected virtual void WriteEvidence(XmlWriter writer, SamlEvidence evidence)
        //{
        //    if (writer == null)
        //        throw LogHelper.LogArgumentNullException(nameof(writer));

        //    if (evidence == null)
        //        throw LogHelper.LogArgumentNullException(nameof(evidence));

        //    writer.WriteStartElement(SamlConstants.PreferredPrefix, SamlConstants.Elements.Evidence, SamlConstants.Namespace);

        //    foreach (var assertionId in evidence.AssertionIdReferences)
        //    {
        //        writer.WriteStartElement(SamlConstants.PreferredPrefix, SamlConstants.Elements.AssertionIdReference, SamlConstants.Namespace);
        //        writer.WriteString(assertionId);
        //        writer.WriteEndElement();
        //    }

        //    foreach (var assertion in evidence.Assertions)
        //        WriteAssertion(writer, assertion);

        //    writer.WriteEndElement();
        //}

        //protected virtual void WriteStatement(XmlWriter writer, SamlStatement statement)
        //{
        //    if (writer == null)
        //        throw LogHelper.LogArgumentNullException(nameof(writer));

        //    if (statement == null)
        //        throw LogHelper.LogArgumentNullException(nameof(statement));

        //    var attributeStatement = statement as SamlAttributeStatement;
        //    if (attributeStatement != null)
        //    {
        //        WriteAttributeStatement(writer, attributeStatement);
        //        return;
        //    }

        //    var authenticationStatement = statement as SamlAuthenticationStatement;
        //    if (authenticationStatement != null)
        //    {
        //        WriteAuthenticationStatement(writer, authenticationStatement);
        //        return;
        //    }

        //    var authorizationStatement = statement as SamlAuthorizationDecisionStatement;
        //    if (authorizationStatement != null)
        //    {
        //        WriteAuthorizationDecisionStatement(writer, authorizationStatement);
        //        return;
        //    }

        //    throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException($"unknown statement type: {statement.GetType()}."));
        //}

        //protected virtual void WriteSubject(XmlWriter writer, SamlSubject subject)
        //{

        //    if (writer == null)
        //        throw LogHelper.LogArgumentNullException(nameof(writer));

        //    if (subject == null)
        //        throw LogHelper.LogArgumentNullException(nameof(subject));

        //    if (string.IsNullOrEmpty(subject.Name) && subject.ConfirmationMethods.Count == 0)
        //        throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("both name and confirmation methods can not be null"));

        //    writer.WriteStartElement(SamlConstants.PreferredPrefix, SamlConstants.Elements.Subject, SamlConstants.Namespace);

        //    if (!string.IsNullOrEmpty(subject.Name))
        //    {
        //        writer.WriteStartElement(SamlConstants.PreferredPrefix, SamlConstants.Elements.NameIdentifier, SamlConstants.Namespace);
        //        if (!string.IsNullOrEmpty(subject.NameFormat))
        //        {
        //            writer.WriteStartAttribute(SamlConstants.Attributes.NameIdentifierFormat, null);
        //            writer.WriteString(subject.NameFormat);
        //            writer.WriteEndAttribute();
        //        }

        //        if (!string.IsNullOrEmpty(subject.NameQualifier))
        //        {
        //            writer.WriteStartAttribute(SamlConstants.Attributes.NameIdentifierNameQualifier, null);
        //            writer.WriteString(subject.NameQualifier);
        //            writer.WriteEndAttribute();
        //        }

        //        writer.WriteString(subject.Name);
        //        writer.WriteEndElement();
        //    }

        //    if (subject.ConfirmationMethods.Count > 0)
        //    {
        //        writer.WriteStartElement(SamlConstants.PreferredPrefix, SamlConstants.Elements.SubjectConfirmation, SamlConstants.Namespace);
        //        foreach (string method in subject.ConfirmationMethods)
        //            writer.WriteElementString(SamlConstants.Elements.SubjectConfirmationMethod, SamlConstants.Namespace, method);

        //        if (!string.IsNullOrEmpty(subject.ConfirmationData))
        //            writer.WriteElementString(SamlConstants.Elements.SubjectConfirmationData, SamlConstants.Namespace, subject.ConfirmationData);

        //        if (subject.KeyIdentifier != null)
        //        {
        //            XmlDictionaryWriter dictionaryWriter = XmlDictionaryWriter.CreateDictionaryWriter(writer);
        //            // TODO - write keyinfo
        //            //SamlSerializer.WriteSecurityKeyIdentifier(dictionaryWriter, this.securityKeyIdentifier, keyInfoSerializer);
        //        }
        //        writer.WriteEndElement();
        //    }

        //    writer.WriteEndElement();
        //}

        //public virtual void WriteToken(XmlDictionaryWriter writer, SamlSecurityToken token)
        //{
        //    if (writer == null)
        //        throw LogHelper.LogArgumentNullException(nameof(writer));

        //    if (token == null)
        //        throw LogHelper.LogArgumentNullException(nameof(token));

        //    WriteAssertion(writer, token.Assertion);
        //}

        //// Helper metods to read and write SecurityKeyIdentifiers.
        //internal static SecurityKey ReadSecurityKey(XmlDictionaryReader reader)
        //{
        //    throw LogHelper.LogExceptionMessage(new InvalidOperationException("SamlSerializerUnableToReadSecurityKeyIdentifier"));
        //}

        //internal static void WriteStartElementWithPreferredcPrefix(XmlWriter writer, string name, string ns)
        //{
        //    writer.WriteStartElement(SamlConstants.PreferredPrefix, name, ns);            
        //}
    }
}
