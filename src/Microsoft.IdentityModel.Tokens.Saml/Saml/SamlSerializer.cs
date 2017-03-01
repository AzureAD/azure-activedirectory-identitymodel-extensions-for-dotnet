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
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Xml;

namespace Microsoft.IdentityModel.Tokens.Saml
{
    public class SamlSerializer
    {
        public SamlSerializer()
        {
        }

        /// <summary>
        /// Read saml:Action element.
        /// </summary>
        /// <param name="reader">XmlReader positioned at saml:Action element.</param>
        /// <returns>SamlAction</returns>
        /// <exception cref="ArgumentNullException">The parameter 'reader' is null.</exception>
        /// <exception cref="XmlException">The saml:Action element contains unknown elements.</exception>
        protected virtual SamlAction ReadAction(XmlReader reader)
        {
            if (reader == null)
                throw LogHelper.LogArgumentNullException(nameof(reader));

            if (!reader.IsStartElement(SamlStrings.Action, SamlStrings.Namespace))
                throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SamlConstants.ElementNames.Action, SamlConstants.Namespace, reader.LocalName, reader.NamespaceURI"));

            // The Namespace attribute is optional.
            string ns = reader.GetAttribute(SamlStrings.Namespace, null);

            reader.MoveToContent();
            string action = reader.ReadString();
            if (string.IsNullOrEmpty(action))
                throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("ID4073"));

            reader.MoveToContent();
            reader.ReadEndElement();

            return (string.IsNullOrEmpty(ns)) ? new SamlAction(action) : new SamlAction(action, ns);
        }

        protected virtual SamlAdvice ReadAdvice(XmlReader reader)
        {
            if (reader == null)
                throw LogHelper.LogArgumentNullException(nameof(reader));

            var advice = new SamlAdvice();

            // SAML Advice is an optional element and all its child elements are optional
            // too. So we may have an empty saml:Advice element in the saml token.
            if (reader.IsEmptyElement)
            {
                // Just issue a read for the empty element.
                reader.MoveToContent();
                reader.Read();
                return advice;
            }

            reader.MoveToContent();
            reader.Read();

            while (reader.IsStartElement())
            {
                if (reader.IsStartElement(SamlStrings.AssertionIdReference, SamlStrings.Namespace))
                {
                    reader.MoveToContent();
                    advice.AssertionIdReferences.Add(reader.ReadString());
                    reader.MoveToContent();
                    reader.ReadEndElement();
                }
                else if (reader.IsStartElement(SamlStrings.Assertion, SamlStrings.Namespace))
                {
                    advice.Assertions.Add(ReadAssertion(reader));
                }
                else
                {
                    throw LogHelper.LogExceptionMessage(new SecurityTokenException("SAMLBadSchema"));
                }
            }

            reader.MoveToContent();
            reader.ReadEndElement();

            return advice;
        }

        public virtual SamlAssertion ReadAssertion(XmlReader reader)
        {
            if (reader == null)
                throw LogHelper.LogArgumentNullException(nameof(reader));

            SamlAssertion assertion = new SamlAssertion();
            if (!reader.IsStartElement(SamlStrings.Assertion, SamlStrings.Namespace))
                throw LogHelper.LogExceptionMessage(new SecurityTokenException("SAMLElementNotRecognized"));

            string attributeValue = reader.GetAttribute(SamlStrings.MajorVersion, null);
            if (string.IsNullOrEmpty(attributeValue))
                throw LogHelper.LogExceptionMessage(new SecurityTokenException("SAMLAssertionMissingMajorVersionAttributeOnRead"));
            
            // TODO - use convert?
            int majorVersion = Int32.Parse(attributeValue, CultureInfo.InvariantCulture);
            attributeValue = reader.GetAttribute(SamlStrings.MinorVersion, null);
            if (string.IsNullOrEmpty(attributeValue))
                throw LogHelper.LogExceptionMessage(new SecurityTokenException("SAMLAssertionMissingMinorVersionAttributeOnRead"));

            // TODO - use convert?
            int minorVersion = Int32.Parse(attributeValue, CultureInfo.InvariantCulture);
            if ((majorVersion != SamlConstants.MajorVersionValue) || (minorVersion != SamlConstants.MinorVersionValue))
                throw LogHelper.LogExceptionMessage(new SecurityTokenException("SAMLTokenVersionNotSupported, majorVersion, minorVersion, SamlConstants.MajorVersionValue, SamlConstants.MinorVersionValue"));

            attributeValue = reader.GetAttribute(SamlStrings.AssertionId, null);
            if (string.IsNullOrEmpty(attributeValue))
                throw LogHelper.LogExceptionMessage(new SecurityTokenException("SAMLAssertionIdRequired"));

            if (!IsAssertionIdValid(attributeValue))
                throw LogHelper.LogExceptionMessage(new SecurityTokenException("SAMLAssertionIDIsInvalid, attributeValue"));

            assertion.AssertionId = attributeValue;

            attributeValue = reader.GetAttribute(SamlStrings.Issuer, null);
            if (string.IsNullOrEmpty(attributeValue))
                throw LogHelper.LogExceptionMessage(new SecurityTokenException("SAMLAssertionMissingIssuerAttributeOnRead"));

            assertion.Issuer = attributeValue;

            attributeValue = reader.GetAttribute(SamlStrings.IssueInstant, null);
            // TODO - try/catch throw SamlReadException
            if (!string.IsNullOrEmpty(attributeValue))
                assertion.IssueInstant = DateTime.ParseExact(
                    attributeValue, SamlConstants.AcceptedDateTimeFormats, DateTimeFormatInfo.InvariantInfo, DateTimeStyles.None).ToUniversalTime();

            reader.MoveToContent();
            reader.Read();

            if (reader.IsStartElement(SamlStrings.Conditions, SamlStrings.Namespace))
            {

                var conditions = ReadConditions(reader);
                if (conditions == null)
                    throw LogHelper.LogExceptionMessage(new SecurityTokenException("SAMLUnableToLoadCondtions"));

                assertion.Conditions = conditions;
            }

            if (reader.IsStartElement(SamlStrings.Advice, SamlStrings.Namespace))
            {
                var advice = ReadAdvice(reader);
                if (advice == null)
                    throw LogHelper.LogExceptionMessage(new SecurityTokenException("SAMLUnableToLoadAdvice"));

                assertion.Advice = advice;
            }

            while (reader.IsStartElement())
            {
                if (reader.IsStartElement(XmlSignatureStrings.Signature, XmlSignatureStrings.Namespace))
                {
                    reader.Skip();
                }
                else
                {
                    SamlStatement statement = ReadStatement(reader);
                    if (statement == null)
                        throw LogHelper.LogExceptionMessage(new SecurityTokenException("SAMLUnableToLoadStatement"));

                    assertion.Statements.Add(statement);
                }
            }

            if (assertion.Statements.Count == 0)
                throw LogHelper.LogExceptionMessage(new SecurityTokenException("SAMLAssertionRequireOneStatementOnRead"));

            //if (wrappedReader.IsStartElement(samlSerializer.DictionaryManager.XmlSignatureDictionary.Signature, samlSerializer.DictionaryManager.XmlSignatureDictionary.Namespace))
            //    this.ReadSignature(wrappedReader, samlSerializer);

            reader.MoveToContent();
            reader.ReadEndElement();

            // set as property on assertion
            //this.tokenStream = wrappedReader.XmlTokens;

            return assertion;
        }

        public virtual SamlAttribute ReadAttribute(XmlReader reader)
        {
            if (reader == null)
                throw LogHelper.LogArgumentNullException(nameof(reader));

            SamlAttribute attribute = new SamlAttribute();

            var name = reader.GetAttribute(SamlStrings.AttributeName, null);
            if (string.IsNullOrEmpty(name))
                throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLAttributeMissingNameAttributeOnRead"));

            var nameSpace = reader.GetAttribute(SamlStrings.AttributeNamespace, null);
            if (string.IsNullOrEmpty(nameSpace))
                throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLAttributeMissingNamespaceAttributeOnRead"));

            // TODO is this the right thing?
            var claimType = string.IsNullOrEmpty(nameSpace) ? name : nameSpace + "/" + name;

            reader.MoveToContent();
            reader.Read();
            while (reader.IsStartElement(SamlStrings.AttributeValue, SamlStrings.Namespace))
            {
                // We will load all Attributes as a string value by default.
                string attrValue = reader.ReadString();
                attribute.AttributeValues.Add(attrValue);

                reader.MoveToContent();
                reader.ReadEndElement();
            }

            if (attribute.AttributeValues.Count == 0)
                throw LogHelper.LogExceptionMessage(new SecurityTokenException("SAMLAttributeShouldHaveOneValue"));

            reader.MoveToContent();
            reader.ReadEndElement();

            return attribute;
        }

        protected virtual SamlAttributeStatement ReadAttributeStatement(XmlReader reader)
        {
            if (reader == null)
                throw LogHelper.LogArgumentNullException(nameof(reader));

            reader.MoveToContent();
            reader.Read();

            if (!reader.IsStartElement(SamlStrings.Subject, SamlStrings.Namespace))
                throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLAttributeStatementMissingSubjectOnRead"));

            var statement = new SamlAttributeStatement();
            statement.Subject = ReadSubject(reader);
            while (reader.IsStartElement())
            {
                if (reader.IsStartElement(SamlStrings.Attribute, SamlStrings.Namespace))
                {
                    SamlAttribute attribute = ReadAttribute(reader);
                    if (attribute == null)
                        throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLUnableToLoadAttribute"));

                    statement.Attributes.Add(attribute);
                }
                else
                {
                    break;
                }
            }

            if (statement.Attributes.Count == 0)
            {
                // Each Attribute statement should have at least one attribute.
                throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLAttributeStatementMissingAttributeOnRead"));
            }

            reader.MoveToContent();
            reader.ReadEndElement();

            return statement;
        }

        /// <summary>
        /// Read saml:AudienceRestrictionCondition from the given XmlReader.
        /// </summary>
        /// <param name="reader">XmlReader positioned at a saml:AudienceRestrictionCondition.</param>
        /// <returns>SamlAudienceRestrictionCondition</returns>
        /// <exception cref="ArgumentNullException">The inpur parameter 'reader' is null.</exception>
        /// <exception cref="XmlException">The XmlReader is not positioned at saml:AudienceRestrictionCondition.</exception>
        /// <summary>
        /// Reads an attribute value.
        /// </summary>
        /// <param name="reader">XmlReader to read from.</param>
        /// <param name="attribute">The current attribute that is being read.</param>
        /// <returns>The attribute value as a string.</returns>
        /// <exception cref="ArgumentNullException">The input parameter 'reader' is null.</exception>
        protected virtual string ReadAttributeValue(XmlReader reader, SamlAttribute attribute)
        {
            // This code was designed realizing that the writter of the xml controls how our
            // reader will report the NodeType. A completely differnet system could write the values.
            // Considering NodeType is important, because we need to read the entire value, end element and not loose anything significant.
            //
            // Couple of cases to help understand the design choices.
            //
            // 1.
            // "<MyElement xmlns=""urn:mynamespace""><another>complex</another></MyElement><sibling>value</sibling>"
            // Could result in the our reader reporting the NodeType as Text OR Element, depending if '<' was entitized to '&lt;'
            //
            // 2.
            // " <MyElement xmlns=""urn:mynamespace""><another>complex</another></MyElement><sibling>value</sibling>"
            // Could result in the our reader reporting the NodeType as Text OR Whitespace.  Post Whitespace processing, the NodeType could be
            // reported as Text or Element, depending if '<' was entitized to '&lt;'
            //
            // 3.
            // "/r/n/t   "
            // Could result in the our reader reporting the NodeType as whitespace.
            //
            // Since an AttributeValue with ONLY Whitespace and a complex Element proceeded by whitespace are reported as the same NodeType (2. and 3.)
            // the whitespace is remembered and discarded if an found is found, otherwise it becomes the value. This is to help users who accidently put a space when adding claims in ADFS
            // If we just skipped the Whitespace, then an AttributeValue that started with Whitespace would loose that part and claims generated from the AttributeValue
            // would be missing that part.
            //

            if (reader == null)
                throw LogHelper.LogArgumentNullException(nameof(reader));

            string result = string.Empty;
            string whiteSpace = string.Empty;

            reader.ReadStartElement(SamlStrings.AttributeValue, SamlStrings.Namespace);

            while (reader.NodeType == XmlNodeType.Whitespace)
            {
                whiteSpace += reader.Value;
                reader.Read();
            }

            reader.MoveToContent();
            if (reader.NodeType == XmlNodeType.Element)
            {
                while (reader.NodeType == XmlNodeType.Element)
                {
                    result += reader.ReadOuterXml();
                    reader.MoveToContent();
                }
            }
            else
            {
                result = whiteSpace;
                result += reader.ReadContentAsString();
            }

            reader.ReadEndElement();
            return result;
        }

        protected virtual SamlAudienceRestrictionCondition ReadAudienceRestrictionCondition(XmlReader reader)
        {
            if (reader == null)
                throw LogHelper.LogArgumentNullException(nameof(reader));

            if (!reader.IsStartElement(SamlStrings.AudienceRestrictionCondition, SamlStrings.Namespace))
                throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SamlConstants.ElementNames.AudienceRestrictionCondition, SamlConstants.Namespace, reader.LocalName, reader.NamespaceURI"));

            reader.ReadStartElement();

            var audienceRestrictionCondition = new SamlAudienceRestrictionCondition();
            while (reader.IsStartElement())
            {
                if (reader.IsStartElement(SamlStrings.Audience, SamlStrings.Namespace))
                {
                    string audience = reader.ReadString();
                    if (string.IsNullOrEmpty(audience))
                        throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("ID4083"));

                    audienceRestrictionCondition.Audiences.Add(new Uri(audience, UriKind.RelativeOrAbsolute));
                    reader.MoveToContent();
                    reader.ReadEndElement();
                }
                else
                {
                    throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SamlConstants.ElementNames.Audience, SamlConstants.Namespace, reader.LocalName, reader.NamespaceURI"));
                }
            }

            if (audienceRestrictionCondition.Audiences.Count == 0)
                throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("ID4084"));

            reader.MoveToContent();
            reader.ReadEndElement();

            return audienceRestrictionCondition;
        }

        /// <summary>
        /// Read the saml:AuthenticationStatement.
        /// </summary>
        /// <param name="reader">XmlReader positioned at a saml:AuthenticationStatement.</param>
        /// <returns>SamlAuthenticationStatement</returns>
        /// <exception cref="ArgumentNullException">The input parameter 'reader' is null.</exception>
        /// <exception cref="XmlException">The XmlReader is not positioned on a saml:AuthenticationStatement
        /// or the statement contains a unknown child element.</exception>
        protected virtual SamlAuthenticationStatement ReadAuthenticationStatement(XmlReader reader)
        {
            if (reader == null)
                throw LogHelper.LogArgumentNullException(nameof(reader));

            var authenticationStatement = new SamlAuthenticationStatement();

            string authInstance = reader.GetAttribute(SamlStrings.AuthenticationInstant, null);
            if (string.IsNullOrEmpty(authInstance))
                throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLAuthenticationStatementMissingAuthenticationInstanceOnRead"));

            var authenticationInstant = DateTime.ParseExact(
                authInstance, SamlConstants.AcceptedDateTimeFormats, DateTimeFormatInfo.InvariantInfo, DateTimeStyles.None).ToUniversalTime();

            var authenticationMethod = reader.GetAttribute(SamlStrings.AuthenticationMethod, null);
            if (string.IsNullOrEmpty(authenticationMethod))
                throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLAuthenticationStatementMissingAuthenticationMethodOnRead"));

            reader.MoveToContent();
            reader.Read();

            if (!reader.IsStartElement(SamlStrings.Subject, SamlStrings.Namespace))
                throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLAuthenticationStatementMissingSubject"));

            authenticationStatement.Subject = ReadSubject(reader);
            if (reader.IsStartElement(SamlStrings.SubjectLocality, SamlStrings.Namespace))
            {
                var dnsAddress = reader.GetAttribute(SamlStrings.SubjectLocalityDNSAddress, null);
                var ipAddress = reader.GetAttribute(SamlStrings.SubjectLocalityIPAddress, null);

                if (reader.IsEmptyElement)
                {
                    reader.MoveToContent();
                    reader.Read();
                }
                else
                {
                    reader.MoveToContent();
                    reader.Read();
                    reader.ReadEndElement();
                }
            }

            while (reader.IsStartElement())
            {
                if (!reader.IsStartElement(SamlStrings.AuthorityBinding, SamlStrings.Namespace))
                    throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLBadSchema, dictionary.AuthenticationStatement"));

                authenticationStatement.AuthorityBindings.Add(ReadAuthorityBinding(reader));
            }

            reader.MoveToContent();
            reader.ReadEndElement();

            return authenticationStatement;
        }

        protected virtual SamlAuthorityBinding ReadAuthorityBinding(XmlReader reader)
        {
            if (reader == null)
                throw LogHelper.LogArgumentNullException(nameof(reader));

            string authKind = reader.GetAttribute(SamlStrings.AuthorityKind, null);
            if (string.IsNullOrEmpty(authKind))
                throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLAuthorityBindingMissingAuthorityKindOnRead"));

            string[] authKindParts = authKind.Split(':');
            if (authKindParts.Length > 2)
                throw LogHelper.LogExceptionMessage(new SecurityTokenException("SAMLAuthorityBindingInvalidAuthorityKind"));

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
                prefix = String.Empty;
                localName = authKindParts[0];
            }

            nameSpace = reader.LookupNamespace(prefix);
            var authorityKind = new XmlQualifiedName(localName, nameSpace);

            var binding = reader.GetAttribute(SamlStrings.Binding, null);
            if (string.IsNullOrEmpty(binding))
                throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLAuthorityBindingMissingBindingOnRead"));

            var location = reader.GetAttribute(SamlStrings.Location, null);
            if (string.IsNullOrEmpty(location))
                throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLAuthorityBindingMissingLocationOnRead"));

            if (reader.IsEmptyElement)
            {
                reader.MoveToContent();
                reader.Read();
            }
            else
            {
                reader.MoveToContent();
                reader.Read();
                reader.ReadEndElement();
            }

            return new SamlAuthorityBinding(authorityKind, binding, location);
        }

        protected virtual SamlAuthorizationDecisionStatement ReadAuthorizationDecisionStatement(XmlReader reader)
        {
            if (reader == null)
                throw LogHelper.LogArgumentNullException(nameof(reader));

            var statement = new SamlAuthorizationDecisionStatement();

            var resource = reader.GetAttribute(SamlStrings.Resource, null);
            if (string.IsNullOrEmpty(resource))
                throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLAuthorizationDecisionStatementMissingResourceAttributeOnRead"));

            string decisionString = reader.GetAttribute(SamlStrings.Decision, null);
            if (string.IsNullOrEmpty(decisionString))
                throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLAuthorizationDecisionStatementMissingDecisionAttributeOnRead"));

            if (decisionString.Equals(SamlAccessDecision.Deny.ToString(), StringComparison.OrdinalIgnoreCase))
                statement.AccessDecision = SamlAccessDecision.Deny;
            else if (decisionString.Equals(SamlAccessDecision.Permit.ToString(), StringComparison.OrdinalIgnoreCase))
                statement.AccessDecision = SamlAccessDecision.Permit;
            else
                statement.AccessDecision = SamlAccessDecision.Indeterminate;

            reader.MoveToContent();
            reader.Read();

            if (!reader.IsStartElement(SamlStrings.Subject, SamlStrings.Namespace))
                throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLAuthorizationDecisionStatementMissingSubjectOnRead"));

            statement.Subject = ReadSubject(reader);
            while (reader.IsStartElement())
            {
                if (reader.IsStartElement(SamlStrings.Action, SamlStrings.Namespace))
                {
                    statement.Actions.Add(ReadAction(reader));
                }
                else if (reader.IsStartElement(SamlStrings.Evidence, SamlStrings.Namespace))
                {
                    if (statement.Evidence != null)
                        throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLAuthorizationDecisionHasMoreThanOneEvidence"));

                    statement.Evidence = ReadEvidence(reader);
                }
                else
                    throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLBadSchema, dictionary.AuthorizationDecisionStatement"));
            }

            if (statement.Actions.Count == 0)
                throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLAuthorizationDecisionShouldHaveOneActionOnRead"));

            reader.MoveToContent();
            reader.ReadEndElement();

            return statement;
        }

        protected virtual SamlCondition ReadCondition(XmlReader reader)
        {
            if (reader == null)
                throw LogHelper.LogArgumentNullException(nameof(reader));

            if (reader.IsStartElement(SamlStrings.AudienceRestrictionCondition, SamlStrings.Namespace))
            {
                return ReadAudienceRestrictionCondition(reader);
            }
            else if (reader.IsStartElement(SamlStrings.DoNotCacheCondition, SamlStrings.Namespace))
            {
                return ReadDoNotCacheCondition(reader);
            }
            else
                throw LogHelper.LogExceptionMessage(new SecurityTokenException("SAMLUnableToLoadUnknownElement, reader.LocalName"));
        }

        protected virtual SamlConditions ReadConditions(XmlReader reader)
        {
            if (reader == null)
                throw LogHelper.LogArgumentNullException(nameof(reader));

            //var conditions = new SamlConditions();
            var nbf = DateTimeUtil.GetMinValue(DateTimeKind.Utc);
            string time = reader.GetAttribute(SamlStrings.NotBefore, null);
            if (!string.IsNullOrEmpty(time))
                nbf = DateTime.ParseExact(time, SamlConstants.AcceptedDateTimeFormats, DateTimeFormatInfo.InvariantInfo, DateTimeStyles.None).ToUniversalTime();

            var notOnOrAfter = DateTimeUtil.GetMaxValue(DateTimeKind.Utc);
            time = reader.GetAttribute(SamlStrings.NotOnOrAfter, null);
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

        protected virtual SamlDoNotCacheCondition ReadDoNotCacheCondition(XmlReader reader)
        {
            if (reader == null)
                throw LogHelper.LogArgumentNullException(nameof(reader));

            if (!reader.IsStartElement(SamlStrings.DoNotCacheCondition, SamlStrings.Namespace))
                throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLBadSchema, dictionary.DoNotCacheCondition.Value"));

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

        protected virtual SamlEvidence ReadEvidence(XmlReader reader)
        {
            if (reader == null)
                throw LogHelper.LogArgumentNullException(nameof(reader));

            var evidence = new SamlEvidence();

            reader.MoveToContent();
            reader.Read();
            while (reader.IsStartElement())
            {
                if (reader.IsStartElement(SamlStrings.AssertionIdReference, SamlStrings.Namespace))
                {
                    reader.MoveToContent();
                    evidence.AssertionIdReferences.Add(reader.ReadString());
                    reader.ReadEndElement();
                }
                else if (reader.IsStartElement(SamlStrings.Assertion, SamlStrings.Namespace))
                {
                    evidence.Assertions.Add(ReadAssertion(reader));
                }
                else
                    throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLBadSchema, dictionary.Evidence.Value"));
            }

            if ((evidence.AssertionIdReferences.Count == 0) && (evidence.Assertions.Count == 0))
                throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLEvidenceShouldHaveOneAssertionOnRead"));

            reader.MoveToContent();
            reader.ReadEndElement();

            return evidence;
        }

        protected virtual SamlStatement ReadStatement(XmlReader reader)
        {
            if (reader == null)
                throw LogHelper.LogArgumentNullException(nameof(reader));

            if (reader.IsStartElement(SamlStrings.AuthenticationStatement, SamlStrings.Namespace))
                return ReadAuthenticationStatement(reader);
            else if (reader.IsStartElement(SamlStrings.AttributeStatement, SamlStrings.Namespace))
                return ReadAttributeStatement(reader);
            else if (reader.IsStartElement(SamlStrings.AuthorizationDecisionStatement, SamlStrings.Namespace))
                return ReadAuthorizationDecisionStatement(reader);
            else
                throw LogHelper.LogExceptionMessage(new SecurityTokenException("SAMLUnableToLoadUnknownElement, reader.LocalName"));
        }

        /// <summary>
        /// Read the SamlSubject from the XmlReader.
        /// </summary>
        /// <param name="reader">XmlReader to read the SamlSubject from.</param>
        /// <returns>SamlSubject</returns>
        /// <exception cref="ArgumentNullException">The input argument 'reader' is null.</exception>
        /// <exception cref="XmlException">The reader is not positioned at a SamlSubject.</exception>
        protected virtual SamlSubject ReadSubject(XmlReader reader)
        {
            if (reader == null)
                throw LogHelper.LogArgumentNullException(nameof(reader));

            if (!reader.IsStartElement(SamlStrings.Subject, SamlStrings.Namespace))
                throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLBadSchema, not on subject node"));

            var subject = new SamlSubject();

            reader.MoveToContent();
            if (reader.IsEmptyElement)
                throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLBadSchema, subject empty"));

            reader.Read();

            if (reader.IsStartElement(SamlStrings.NameIdentifier, SamlStrings.Namespace))
            {
                subject.NameFormat = reader.GetAttribute(SamlStrings.NameIdentifierFormat, null);
                subject.NameQualifier = reader.GetAttribute(SamlStrings.NameIdentifierNameQualifier, null);

                // TODO - check for string ??
                reader.MoveToContent();
                subject.Name = reader.ReadString();

                if (string.IsNullOrEmpty(subject.Name))
                    throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLNameIdentifierMissingIdentifierValueOnRead"));

                reader.MoveToContent();
                reader.ReadEndElement();
            }

            if (reader.IsStartElement(SamlStrings.SubjectConfirmation, SamlStrings.Namespace))
            {
                reader.MoveToContent();
                reader.Read();

                while (reader.IsStartElement(SamlStrings.SubjectConfirmationMethod, SamlStrings.Namespace))
                {
                    string method = reader.ReadString();
                    if (string.IsNullOrEmpty(method))
                        throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLBadSchema, dictionary.SubjectConfirmationMethod.Value"));

                    subject.ConfirmationMethods.Add(method);
                    reader.MoveToContent();
                    reader.ReadEndElement();
                }

                if (subject.ConfirmationMethods.Count == 0)
                {
                    // A SubjectConfirmaton clause should specify at least one 
                    // ConfirmationMethod.
                    throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLSubjectConfirmationClauseMissingConfirmationMethodOnRead"));
                }

                if (reader.IsStartElement(SamlStrings.SubjectConfirmationData, SamlStrings.Namespace))
                {
                    reader.MoveToContent();
                    // An Authentication protocol specified in the confirmation method might need this
                    // data. Just store this content value as string.
                    subject.ConfirmationData = reader.ReadString();
                    reader.MoveToContent();
                    reader.ReadEndElement();
                }

                if (reader.IsStartElement(XmlSignatureStrings.KeyInfo, XmlSignatureStrings.Namespace))
                {
                    XmlDictionaryReader dictionaryReader = XmlDictionaryReader.CreateDictionaryReader(reader);
                    // TODO - we need to get the key
                    /// subject.Key = ReadSecurityKey(dictionaryReader);
                    //this.crypto = SamlSerializer.ResolveSecurityKey(this.securityKeyIdentifier, outOfBandTokenResolver);
                    //if (this.crypto == null)
                    //{
                    //    throw LogHelper.LogExceptionMessage(new SecurityTokenException(SR.GetString(SR.SamlUnableToExtractSubjectKey)));
                    //}
                    //this.subjectToken = SamlSerializer.ResolveSecurityToken(this.securityKeyIdentifier, outOfBandTokenResolver);
                }


                if ((subject.ConfirmationMethods.Count == 0) && (string.IsNullOrEmpty(subject.Name)))
                    throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLSubjectRequiresNameIdentifierOrConfirmationMethodOnRead"));

                reader.MoveToContent();
                reader.ReadEndElement();
            }

            reader.MoveToContent();
            reader.ReadEndElement();

            return subject;
        }

        /// <summary>
        /// Read the SamlSubject KeyIdentifier from a XmlReader.
        /// </summary>
        /// <param name="reader">XmlReader positioned at the SamlSubject KeyIdentifier.</param>
        /// <returns>SamlSubject Key as a SecurityKeyIdentifier.</returns>
        /// <exception cref="ArgumentNullException">Input parameter 'reader' is null.</exception>
        /// <exception cref="XmlException">XmlReader is not positioned at a valid SecurityKeyIdentifier.</exception>
        protected virtual SecurityKeyIdentifier ReadSubjectKeyInfo(XmlReader reader)
        {
            if (reader == null)
                throw LogHelper.LogArgumentNullException(nameof(reader));

            // TODO - get the key
            //if (KeyInfoSerializer.CanReadKeyIdentifier(reader))
            //{
            //    return KeyInfoSerializer.ReadKeyIdentifier(reader);
            //}

            throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("ID4090"));
        }

        public virtual SamlSecurityToken ReadToken(XmlReader reader)
        {
            if (reader == null)
                throw LogHelper.LogArgumentNullException(nameof(reader));

            SamlAssertion assertion = ReadAssertion(reader);
            if (assertion == null)
                throw LogHelper.LogExceptionMessage(new SecurityTokenException("SAMLUnableToLoadAssertion"));

            //if (assertion.Signature == null)
            //    throw LogHelper.LogExceptionMessage(new SecurityTokenException(SR.GetString(SR.SamlTokenMissingSignature)));

            return new SamlSecurityToken(assertion);
        }

        protected virtual void WriteAction(XmlWriter writer, SamlAction action)
        {
            if (writer == null)
                throw LogHelper.LogArgumentNullException(nameof(writer));

            if (action == null)
                throw LogHelper.LogArgumentNullException(nameof(action));

            writer.WriteStartElement(SamlStrings.PreferredPrefix, SamlStrings.Action, SamlStrings.Namespace);
            if (!string.IsNullOrEmpty(action.Namespace))
            {
                writer.WriteStartAttribute(SamlStrings.ActionNamespaceAttribute, null);
                writer.WriteString(action.Namespace);
                writer.WriteEndAttribute();
            }

            writer.WriteString(action.Action);
            writer.WriteEndElement();
        }

        protected virtual void WriteAdvice(XmlWriter writer, SamlAdvice advice)
        {
            if (writer == null)
                throw LogHelper.LogArgumentNullException(nameof(writer));

            if (advice == null)
                throw LogHelper.LogArgumentNullException(nameof(advice));

            writer.WriteStartElement(SamlStrings.PreferredPrefix, SamlStrings.Advice, SamlStrings.Namespace);

            foreach (var reference in advice.AssertionIdReferences)
            {
                writer.WriteStartElement(SamlStrings.PreferredPrefix, SamlStrings.AssertionIdReference, SamlStrings.Namespace);
                writer.WriteString(reference);
                writer.WriteEndElement();
            }

            foreach (var assertion in advice.Assertions)
                WriteAssertion(writer, assertion);

            writer.WriteEndElement();
        }

        public virtual void WriteAssertion(XmlWriter writer, SamlAssertion assertion)
        {
            if (writer == null)
                throw LogHelper.LogArgumentNullException(nameof(writer));

            if (assertion == null)
                throw LogHelper.LogArgumentNullException(nameof(assertion));

            if (string.IsNullOrEmpty(assertion.AssertionId))
                throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLAssertionIdRequired"));

            if (!IsAssertionIdValid(assertion.AssertionId))
                throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLAssertionIDIsInvalid"));

            if (string.IsNullOrEmpty(assertion.Issuer))
                throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLAssertionIssuerRequired"));

            if (assertion.Statements.Count == 0)
                throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLAssertionRequireOneStatement"));

            try
            {
                writer.WriteStartElement(SamlStrings.PreferredPrefix, SamlStrings.Assertion, SamlStrings.Namespace);
                writer.WriteStartAttribute(SamlStrings.MajorVersion, null);
                writer.WriteValue(SamlConstants.MajorVersionValue);
                writer.WriteEndAttribute();
                writer.WriteStartAttribute(SamlStrings.MinorVersion, null);
                writer.WriteValue(SamlConstants.MinorVersionValue);
                writer.WriteEndAttribute();
                writer.WriteStartAttribute(SamlStrings.AssertionId, null);
                writer.WriteString(assertion.AssertionId);
                writer.WriteEndAttribute();
                writer.WriteStartAttribute(SamlStrings.Issuer, null);
                writer.WriteString(assertion.Issuer);
                writer.WriteEndAttribute();
                writer.WriteStartAttribute(SamlStrings.IssueInstant, null);
                writer.WriteString(assertion.IssueInstant.ToString(SamlConstants.GeneratedDateTimeFormat, CultureInfo.InvariantCulture));
                writer.WriteEndAttribute();

                // Write out conditions
                if (assertion.Conditions != null)
                    WriteConditions(writer, assertion.Conditions);

                // Write out advice if there is one
                if (assertion.Advice != null)
                    WriteAdvice(writer, assertion.Advice);

                foreach (var statement in assertion.Statements)
                    WriteStatement(writer, statement);

                writer.WriteEndElement();
            }
            catch (Exception ex)
            {
                throw LogHelper.LogExceptionMessage(new SecurityTokenException("SAMLTokenNotSerialized", ex));
            }
        }

        public virtual void WriteAttribute(XmlWriter writer, SamlAttribute attribute)

        {
            if (writer == null)
                throw LogHelper.LogArgumentNullException(nameof(writer));

            if (attribute == null)
                throw LogHelper.LogArgumentNullException(nameof(attribute));

            writer.WriteStartElement(SamlStrings.PreferredPrefix, SamlStrings.Attribute, SamlStrings.Namespace);
            writer.WriteStartAttribute(SamlStrings.AttributeName, null);
            writer.WriteString(attribute.Name);
            writer.WriteEndAttribute();
            writer.WriteStartAttribute(SamlStrings.AttributeNamespace, null);
            writer.WriteString(attribute.Namespace);
            writer.WriteEndAttribute();

            foreach (var attributeValue in attribute.AttributeValues)
            {
                if (string.IsNullOrEmpty(attributeValue))
                    throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SamlAttributeValueCannotBeNull"));

                writer.WriteElementString(SamlStrings.PreferredPrefix, SamlStrings.AttributeValue, SamlStrings.Namespace, attributeValue);
            }

            writer.WriteEndElement();
        }

        protected virtual void WriteAttributeStatement(XmlWriter writer, SamlAttributeStatement statement)
        {
            if (writer == null)
                throw LogHelper.LogArgumentNullException(nameof(writer));

            if (statement == null)
                throw LogHelper.LogArgumentNullException(nameof(statement));

            writer.WriteStartElement(SamlStrings.PreferredPrefix, SamlStrings.AttributeStatement, SamlStrings.Namespace);

            WriteSubject(writer, statement.Subject);
            foreach (var attribute in statement.Attributes)
                WriteAttribute(writer, attribute);

            writer.WriteEndElement();
        }

        protected virtual void WriteAudienceRestrictionCondition(XmlWriter writer, SamlAudienceRestrictionCondition condition)
        {
            if (condition == null)
                throw LogHelper.LogArgumentNullException(nameof(condition));

            if (writer == null)
                throw LogHelper.LogArgumentNullException(nameof(writer));

            writer.WriteStartElement(SamlStrings.PreferredPrefix, SamlStrings.AudienceRestrictionCondition, SamlStrings.Namespace);

            foreach (var audience in condition.Audiences)
            {
                // TODO - should we throw ?
                if (audience != null)
                    writer.WriteElementString(SamlStrings.Audience, SamlStrings.Namespace, audience.AbsoluteUri);
            }

            writer.WriteEndElement();
        }

        protected virtual void WriteAuthenticationStatement(XmlWriter writer, SamlAuthenticationStatement statement)
        {
            if (writer == null)
                throw LogHelper.LogArgumentNullException(nameof(writer));

            if (statement == null)
                throw LogHelper.LogArgumentNullException(nameof(statement));

            writer.WriteStartElement(SamlStrings.PreferredPrefix, SamlStrings.AuthenticationStatement, SamlStrings.Namespace);
            writer.WriteStartAttribute(SamlStrings.AuthenticationMethod, null);
            writer.WriteString(statement.AuthenticationMethod);
            writer.WriteEndAttribute();
            writer.WriteStartAttribute(SamlStrings.AuthenticationInstant, null);
            writer.WriteString(statement.AuthenticationInstant.ToString(SamlConstants.GeneratedDateTimeFormat, CultureInfo.InvariantCulture));
            writer.WriteEndAttribute();

            WriteSubject(writer, statement.Subject);

            if ((!string.IsNullOrEmpty(statement.IPAddress)) || (!string.IsNullOrEmpty(statement.DnsAddress)))
            {
                writer.WriteStartElement(SamlStrings.PreferredPrefix, SamlStrings.SubjectLocality, SamlStrings.Namespace);

                if (!string.IsNullOrEmpty(statement.IPAddress))
                {
                    writer.WriteStartAttribute(SamlStrings.SubjectLocalityIPAddress, null);
                    writer.WriteString(statement.IPAddress);
                    writer.WriteEndAttribute();
                }

                if (!string.IsNullOrEmpty(statement.DnsAddress))
                {
                    writer.WriteStartAttribute(SamlStrings.SubjectLocalityDNSAddress, null);
                    writer.WriteString(statement.DnsAddress);
                    writer.WriteEndAttribute();
                }

                writer.WriteEndElement();
            }

            foreach (var binding in statement.AuthorityBindings)
            {
                WriteAuthorityBinding(writer, binding);
            }

            writer.WriteEndElement();
        }

        protected virtual void WriteAuthorityBinding(XmlWriter writer, SamlAuthorityBinding authorityBinding)
        {
            if (writer == null)
                throw LogHelper.LogArgumentNullException(nameof(writer));

            if (authorityBinding == null)
                throw LogHelper.LogArgumentNullException(nameof(authorityBinding));

            writer.WriteStartElement(SamlStrings.PreferredPrefix, SamlStrings.AuthorityBinding, SamlStrings.Namespace);

            string prefix = null;
            if (!string.IsNullOrEmpty(authorityBinding.AuthorityKind.Namespace))
            {
                writer.WriteAttributeString(string.Empty, SamlStrings.NamespaceAttributePrefix, null, authorityBinding.AuthorityKind.Namespace);
                prefix = writer.LookupPrefix(authorityBinding.AuthorityKind.Namespace);
            }

            writer.WriteStartAttribute(SamlStrings.AuthorityKind, null);
            if (string.IsNullOrEmpty(prefix))
                writer.WriteString(authorityBinding.AuthorityKind.Name);
            else
                writer.WriteString(prefix + ":" + authorityBinding.AuthorityKind.Name);
            writer.WriteEndAttribute();

            writer.WriteStartAttribute(SamlStrings.Location, null);
            writer.WriteString(authorityBinding.Location);
            writer.WriteEndAttribute();

            writer.WriteStartAttribute(SamlStrings.Binding, null);
            writer.WriteString(authorityBinding.Binding);
            writer.WriteEndAttribute();

            writer.WriteEndElement();
        }

        protected virtual void WriteAuthorizationDecisionStatement(XmlWriter writer, SamlAuthorizationDecisionStatement statement)
        {
            if (writer == null)
                throw LogHelper.LogArgumentNullException(nameof(writer));

            if (statement == null)
                throw LogHelper.LogArgumentNullException(nameof(statement));

            writer.WriteStartElement(SamlStrings.PreferredPrefix, SamlStrings.AuthorizationDecisionStatement, SamlStrings.Namespace);

            writer.WriteStartAttribute(SamlStrings.Decision, null);
            writer.WriteString(statement.AccessDecision.ToString());
            writer.WriteEndAttribute();

            writer.WriteStartAttribute(SamlStrings.Resource, null);
            writer.WriteString(statement.Resource);
            writer.WriteEndAttribute();

            WriteSubject(writer, statement.Subject);

            foreach (var action in statement.Actions)
                WriteAction(writer, action);

            if (statement.Evidence != null)
                WriteEvidence(writer, statement.Evidence);

            writer.WriteEndElement();
        }

        protected virtual void WriteCondition(XmlWriter writer, SamlCondition condition)
        {
            var audienceRestrictionCondition = condition as SamlAudienceRestrictionCondition;
            if (audienceRestrictionCondition != null)
                WriteAudienceRestrictionCondition(writer, audienceRestrictionCondition);

            var donotCacheCondition = condition as SamlDoNotCacheCondition;
            if (donotCacheCondition != null)
                WriteDoNotCacheCondition(writer, donotCacheCondition);
        }

        protected virtual void WriteConditions(XmlWriter writer, SamlConditions conditions)
        {
            if (writer == null)
                throw LogHelper.LogArgumentNullException(nameof(writer));

            if (conditions == null)
                throw LogHelper.LogArgumentNullException(nameof(conditions));

            writer.WriteStartElement(SamlStrings.PreferredPrefix, SamlStrings.Conditions, SamlStrings.Namespace);
            if (conditions.NotBefore != SecurityUtils.MinUtcDateTime)
            {
                writer.WriteStartAttribute(SamlStrings.NotBefore, null);
                writer.WriteString(conditions.NotBefore.ToString(SamlConstants.GeneratedDateTimeFormat, DateTimeFormatInfo.InvariantInfo));
                writer.WriteEndAttribute();
            }

            if (conditions.NotOnOrAfter != SecurityUtils.MaxUtcDateTime)
            {
                writer.WriteStartAttribute(SamlStrings.NotOnOrAfter, null);
                writer.WriteString(conditions.NotOnOrAfter.ToString(SamlConstants.GeneratedDateTimeFormat, DateTimeFormatInfo.InvariantInfo));
                writer.WriteEndAttribute();
            }

            foreach (var condition in conditions.Conditions)
                WriteCondition(writer, condition);

            writer.WriteEndElement();
        }

        // TODO - figure this out when signing and maintaing node list

        ///// <summary>
        ///// Writes the source data, if available.
        ///// </summary>
        ///// <exception cref="InvalidOperationException">When no source data is available</exception>
        ///// <param name="writer"></param>
        //public virtual void WriteSourceData(XmlWriter writer)
        //{
        //    if (!this.CanWriteSourceData)
        //    {
        //        throw LogHelper.LogExceptionMessage(new InvalidOperationException("SR.ID4140"));
        //    }

        //    // This call will properly just reuse the existing writer if it already qualifies
        //    XmlDictionaryWriter dictionaryWriter = XmlDictionaryWriter.CreateDictionaryWriter(writer);
        //    this.sourceData.SetElementExclusion(null, null);
        //    this.sourceData.GetWriter().WriteTo(dictionaryWriter, null);
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

        protected virtual void WriteDoNotCacheCondition(XmlWriter writer, SamlDoNotCacheCondition condition)
        {
            if (writer == null)
                throw LogHelper.LogArgumentNullException(nameof(writer));

            writer.WriteStartElement(SamlStrings.PreferredPrefix, SamlStrings.DoNotCacheCondition, SamlStrings.Namespace);
            writer.WriteEndElement();
        }

        protected virtual void WriteEvidence(XmlWriter writer, SamlEvidence evidence)
        {
            if (writer == null)
                throw LogHelper.LogArgumentNullException(nameof(writer));

            if (evidence == null)
                throw LogHelper.LogArgumentNullException(nameof(evidence));

            writer.WriteStartElement(SamlStrings.PreferredPrefix, SamlStrings.Evidence, SamlStrings.Namespace);

            foreach (var assertionId in evidence.AssertionIdReferences)
            {
                writer.WriteStartElement(SamlStrings.PreferredPrefix, SamlStrings.AssertionIdReference, SamlStrings.Namespace);
                writer.WriteString(assertionId);
                writer.WriteEndElement();
            }

            foreach (var assertion in evidence.Assertions)
                WriteAssertion(writer, assertion);

            writer.WriteEndElement();
        }

        protected virtual void WriteStatement(XmlWriter writer, SamlStatement statement)
        {
            if (writer == null)
                throw LogHelper.LogArgumentNullException(nameof(writer));

            if (statement == null)
                throw LogHelper.LogArgumentNullException(nameof(statement));

            var attributeStatement = statement as SamlAttributeStatement;
            if (attributeStatement != null)
            {
                WriteAttributeStatement(writer, attributeStatement);
                return;
            }

            var authenticationStatement = statement as SamlAuthenticationStatement;
            if (authenticationStatement != null)
            {
                WriteAuthenticationStatement(writer, authenticationStatement);
                return;
            }

            var authorizationStatement = statement as SamlAuthorizationDecisionStatement;
            if (authorizationStatement != null)
            {
                WriteAuthorizationDecisionStatement(writer, authorizationStatement);
                return;
            }

            throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException($"unknown statement type: {statement.GetType()}."));
        }

        protected virtual void WriteSubject(XmlWriter writer, SamlSubject subject)
        {

            if (writer == null)
                throw LogHelper.LogArgumentNullException(nameof(writer));

            if (subject == null)
                throw LogHelper.LogArgumentNullException(nameof(subject));

            if (string.IsNullOrEmpty(subject.Name) && subject.ConfirmationMethods.Count == 0)
                throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("both name and confirmation methods can not be null"));

            writer.WriteStartElement(SamlStrings.PreferredPrefix, SamlStrings.Subject, SamlStrings.Namespace);

            if (!string.IsNullOrEmpty(subject.Name))
            {
                writer.WriteStartElement(SamlStrings.PreferredPrefix, SamlStrings.NameIdentifier, SamlStrings.Namespace);
                if (!string.IsNullOrEmpty(subject.NameFormat))
                {
                    writer.WriteStartAttribute(SamlStrings.NameIdentifierFormat, null);
                    writer.WriteString(subject.NameFormat);
                    writer.WriteEndAttribute();
                }

                if (!string.IsNullOrEmpty(subject.NameQualifier))
                {
                    writer.WriteStartAttribute(SamlStrings.NameIdentifierNameQualifier, null);
                    writer.WriteString(subject.NameQualifier);
                    writer.WriteEndAttribute();
                }

                writer.WriteString(subject.Name);
                writer.WriteEndElement();
            }

            if (subject.ConfirmationMethods.Count > 0)
            {
                writer.WriteStartElement(SamlStrings.PreferredPrefix, SamlStrings.SubjectConfirmation, SamlStrings.Namespace);
                foreach (string method in subject.ConfirmationMethods)
                    writer.WriteElementString(SamlStrings.SubjectConfirmationMethod, SamlStrings.Namespace, method);

                if (!string.IsNullOrEmpty(subject.ConfirmationData))
                    writer.WriteElementString(SamlStrings.SubjectConfirmationData, SamlStrings.Namespace, subject.ConfirmationData);

                if (subject.KeyIdentifier != null)
                {
                    XmlDictionaryWriter dictionaryWriter = XmlDictionaryWriter.CreateDictionaryWriter(writer);
                    // TODO - write keyinfo
                    //SamlSerializer.WriteSecurityKeyIdentifier(dictionaryWriter, this.securityKeyIdentifier, keyInfoSerializer);
                }
                writer.WriteEndElement();
            }

            writer.WriteEndElement();
        }

        public virtual void WriteToken(XmlDictionaryWriter writer, SamlSecurityToken token)
        {
            if (writer == null)
                throw LogHelper.LogArgumentNullException(nameof(writer));

            if (token == null)
                throw LogHelper.LogArgumentNullException(nameof(token));

            WriteAssertion(writer, token.Assertion);
        }

        // Helper metods to read and write SecurityKeyIdentifiers.
        internal static SecurityKey ReadSecurityKey(XmlReader reader)
        {
            throw LogHelper.LogExceptionMessage(new InvalidOperationException("SamlSerializerUnableToReadSecurityKeyIdentifier"));
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
    }
}
