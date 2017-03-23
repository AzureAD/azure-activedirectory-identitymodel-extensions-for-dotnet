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
using System.IO;
using System.Security.Claims;
using System.Text;
using System.Xml;
using System.Xml.Schema;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Xml;

namespace Microsoft.IdentityModel.Tokens.Saml2
{
    /// <summary>
    /// Reads and writes Saml2 Assertions and tokens
    /// </summary>
    public class Saml2Serializer
    {
        public Saml2Serializer() { }

        /// <summary>
        /// Reads the &lt;saml:Action> element.
        /// </summary>
        /// <param name="reader">A <see cref="XmlReader"/> positioned at a <see cref="Saml2Action"/> element.</param>
        /// <returns>A <see cref="Saml2Action"/> instance.</returns>
        public virtual Saml2Action ReadAction(XmlReader reader)
        {
            CheckReaderOnEntry(reader, Saml2Constants.Elements.Action, Saml2Constants.Namespace);
            try
            {
                // @xsi:type
                XmlUtil.ValidateXsiType(reader, Saml2Constants.Types.ActionType, Saml2Constants.Namespace);

                // @Namespace - required
                // @attributes
                string namespaceValue = reader.GetAttribute(Saml2Constants.Attributes.Namespace);
                if (string.IsNullOrEmpty(namespaceValue))
                    throw LogReadException(LogMessages.IDX11106, Saml2Constants.Elements.Action, Saml2Constants.Attributes.Namespace);

                // TODO - relax URI.Absolute?
                if (!UriUtil.CanCreateValidUri(namespaceValue, UriKind.Absolute))
                    throw LogReadException(LogMessages.IDX11107, Saml2Constants.Elements.Action, Saml2Constants.Attributes.Namespace, namespaceValue);

                return new Saml2Action(reader.ReadElementString(), new Uri(namespaceValue));
            }
            catch (Exception ex)
            {
                throw LogReadException(LogMessages.IDX11102, ex, Saml2Constants.Elements.Action);
            }
        }

        /// <summary>
        /// Reads the &lt;saml:Advice> element.
        /// </summary>
        /// <remarks>
        /// <para>
        /// The Advice element has an extensibility point to allow XML elements
        /// from non-SAML2 namespaces to be included. By default, because the 
        /// Advice may be ignored without affecting the semantics of the 
        /// assertion, any such elements are ignored. To handle the processing
        /// of those elements, override this method.
        /// </para>
        /// </remarks>
        /// <param name="reader">A <see cref="XmlReader"/> positioned at a <see cref="Saml2Advice"/> element.</param>
        /// <returns>A <see cref="Saml2Advice"/> instance.</returns>
        public virtual Saml2Advice ReadAdvice(XmlReader reader)
        {
            CheckReaderOnEntry(reader, Saml2Constants.Elements.Advice, Saml2Constants.Namespace);
            try
            {
                Saml2Advice advice = new Saml2Advice();
                bool isEmpty = reader.IsEmptyElement;

                // @attributes

                // @xsi:type
                XmlUtil.ValidateXsiType(reader, Saml2Constants.Types.AdviceType, Saml2Constants.Namespace);

                reader.Read();
                if (!isEmpty)
                {
                    // <AssertionIDRef|AssertionURIRef|Assertion|EncryptedAssertion|other:any> 0-OO
                    while (reader.IsStartElement())
                    {
                        // <AssertionIDRef>, <AssertionURIRef>, <Assertion>, <EncryptedAssertion>
                        if (reader.IsStartElement(Saml2Constants.Elements.AssertionIDRef, Saml2Constants.Namespace))
                            advice.AssertionIdReferences.Add(ReadSimpleNCNameElement(reader, Saml2Constants.Elements.AssertionIDRef));
                        else if (reader.IsStartElement(Saml2Constants.Elements.AssertionURIRef, Saml2Constants.Namespace))
                            advice.AssertionUriReferences.Add(ReadSimpleUriElement(reader, Saml2Strings.Advice, UriKind.RelativeOrAbsolute, false));
                        else if (reader.IsStartElement(Saml2Constants.Elements.Assertion, Saml2Constants.Namespace))
                            advice.Assertions.Add(ReadAssertion(reader));
                        else if (reader.IsStartElement(Saml2Constants.Elements.EncryptedAssertion, Saml2Constants.Namespace))
                            advice.Assertions.Add(ReadAssertion(reader));
                        else
                            reader.Skip();
                    }

                    reader.ReadEndElement();
                }

                return advice;
            }
            catch (Exception ex)
            {
                throw LogReadException(LogMessages.IDX11102, ex, Saml2Strings.Advice);
            }
        }

        /// <summary>
        /// Reads the &lt;saml:Assertion> element.
        /// </summary>
        /// <param name="reader">A <see cref="XmlReader"/> positioned at a <see cref="Saml2Assertion"/> element.</param>
        /// <returns>A <see cref="Saml2Assertion"/> instance.</returns>
        public virtual Saml2Assertion ReadAssertion(XmlReader reader)
        {
            if (null == reader)
                throw LogHelper.LogArgumentNullException(nameof(reader));

            XmlDictionaryReader plaintextReader = XmlDictionaryReader.CreateDictionaryReader(reader);

            Saml2Assertion assertion = new Saml2Assertion(new Saml2NameIdentifier("__TemporaryIssuer__"));

            // If it's an EncryptedAssertion, we need to retrieve the plaintext
            // and repoint our reader
            if (reader.IsStartElement(Saml2Constants.Elements.EncryptedAssertion, Saml2Constants.Namespace))
            {
                EncryptingCredentials encryptingCredentials = null;
                //plaintextReader = CreatePlaintextReaderFromEncryptedData(
                //                    plaintextReader,
                //                    out encryptingCredentials);

                assertion.EncryptingCredentials = encryptingCredentials;
            }

            // Throw if wrong element
            if (!plaintextReader.IsStartElement(Saml2Constants.Elements.Assertion, Saml2Constants.Namespace))
            {
                plaintextReader.ReadStartElement(Saml2Constants.Elements.Assertion, Saml2Constants.Namespace);
            }

            // disallow empty
            if (plaintextReader.IsEmptyElement)
                throw LogReadException(LogMessages.IDX11104, Saml2Constants.Elements.Assertion);

            // SAML supports enveloped signature, so we need to wrap our reader.
            // We do not dispose this reader, since as a delegating reader it would
            // dispose the inner reader, which we don't properly own.
            EnvelopedSignatureReader realReader = new EnvelopedSignatureReader(plaintextReader);
            try
            {
                // Process @attributes
                string value;

                // @xsi:type
                XmlUtil.ValidateXsiType(realReader, Saml2Constants.Types.AssertionType, Saml2Constants.Namespace);

                // @Version - required - must be "2.0"
                string version = realReader.GetAttribute(Saml2Constants.Attributes.Version);
                if (string.IsNullOrEmpty(version))
                {
                    throw LogHelper.LogExceptionMessage(new Saml2SecurityTokenException("version empty"));
                }

                if (!StringComparer.Ordinal.Equals(assertion.Version, version))
                {
                    throw LogHelper.LogExceptionMessage(new Saml2SecurityTokenException("version is not right"));
                }

                // @ID - required
                value = realReader.GetAttribute(Saml2Constants.Attributes.ID);
                if (string.IsNullOrEmpty(value))
                {
                    throw LogHelper.LogExceptionMessage(new Saml2SecurityTokenException("id missing"));
                }

                assertion.Id = new Saml2Id(value);

                // @IssueInstant - required
                value = realReader.GetAttribute(Saml2Constants.Attributes.IssueInstant);
                if (string.IsNullOrEmpty(value))
                {
                    throw LogHelper.LogExceptionMessage(new Saml2SecurityTokenException("IssueInstant missing"));
                }

                assertion.IssueInstant = XmlConvert.ToDateTime(value, Saml2Constants.AcceptedDateTimeFormats);

                // Process <elements>
                realReader.Read();

                // <Issuer> 1
                assertion.Issuer = ReadIssuer(realReader);

                // <ds:Signature> 0-1
                realReader.TryReadSignature();

                // <Subject> 0-1
                if (realReader.IsStartElement(Saml2Constants.Elements.Subject, Saml2Constants.Namespace))
                {
                    assertion.Subject = ReadSubject(realReader);
                }

                // <Conditions> 0-1
                if (realReader.IsStartElement(Saml2Constants.Elements.Conditions, Saml2Constants.Namespace))
                {
                    assertion.Conditions = ReadConditions(realReader);
                }

                // <Advice> 0-1
                if (realReader.IsStartElement(Saml2Constants.Elements.Advice, Saml2Constants.Namespace))
                    assertion.Advice = ReadAdvice(realReader);

                // <Statement|AuthnStatement|AuthzDecisionStatement|AttributeStatement>, 0-OO
                while (realReader.IsStartElement())
                {
                    Saml2Statement statement;

                    if (realReader.IsStartElement(Saml2Constants.Elements.Statement, Saml2Constants.Namespace))
                        statement = ReadStatement(realReader);
                    else if (realReader.IsStartElement(Saml2Constants.Elements.AttributeStatement, Saml2Constants.Namespace))
                        statement = ReadAttributeStatement(realReader);
                    else if (realReader.IsStartElement(Saml2Constants.Elements.AuthnStatement, Saml2Constants.Namespace))
                        statement = ReadAuthenticationStatement(realReader);
                    else if (realReader.IsStartElement(Saml2Constants.Elements.AuthzDecisionStatement, Saml2Constants.Namespace))
                        statement = ReadAuthorizationDecisionStatement(realReader);
                    else
                        break;

                    assertion.Statements.Add(statement);
                }

                realReader.ReadEndElement();

                if (null == assertion.Subject)
                {
                    // An assertion with no statements MUST contain a <Subject> element. [Saml2Core, line 585]
                    if (0 == assertion.Statements.Count)
                        throw LogReadException(LogMessages.IDX11108, Saml2Strings.Assertion);

                    // Furthermore, the built-in statement types all require the presence of a subject.
                    // [Saml2Core, lines 1050, 1168, 1280]
                    foreach (Saml2Statement statement in assertion.Statements)
                    {
                        if (statement is Saml2AuthenticationStatement
                            || statement is Saml2AttributeStatement
                            || statement is Saml2AuthorizationDecisionStatement)
                        {
                            throw LogReadException(LogMessages.IDX11109, Saml2Strings.Assertion);
                        }
                    }
                }

                // Reading the end element will complete the signature;
                // capture the signing creds
                assertion.SigningCredentials = realReader.SigningCredentials;

                // Save the captured on-the-wire data, which can then be used
                // to re-emit this assertion, preserving the same signature.
                assertion.CaptureSourceData(realReader);

                return assertion;
            }
            catch (Exception ex)
            {
                throw LogReadException(LogMessages.IDX11102, ex, Saml2Strings.Assertion);
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
        /// <param name="reader">An <see cref="XmlReader"/> positioned at a <see cref="Saml2Attribute"/> element.</param>
        /// <returns>A <see cref="Saml2Attribute"/> instance.</returns>
        public virtual Saml2Attribute ReadAttribute(XmlReader reader)
        {
            CheckReaderOnEntry(reader, Saml2Constants.Elements.Attribute, Saml2Constants.Namespace);
            try
            {
                Saml2Attribute attribute;
                bool isEmpty = reader.IsEmptyElement;

                // @attributes
                string value;

                // @xsi:type
                XmlUtil.ValidateXsiType(reader, Saml2Constants.Types.AttributeType, Saml2Constants.Namespace);

                // @Name - required
                value = reader.GetAttribute(Saml2Constants.Attributes.Name);
                if (string.IsNullOrEmpty(value))
                    throw LogReadException(LogMessages.IDX11106, Saml2Constants.Elements.Attribute, Saml2Constants.Attributes.Name);

                attribute = new Saml2Attribute(value);

                // @NameFormat - optional
                value = reader.GetAttribute(Saml2Constants.Attributes.NameFormat);
                if (!string.IsNullOrEmpty(value))
                {
                    if (!UriUtil.CanCreateValidUri(value, UriKind.Absolute))
                        LogReadException(LogMessages.IDX11107, Saml2Constants.Elements.Attribute, Saml2Constants.Attributes.NameFormat, value);

                    attribute.NameFormat = new Uri(value);
                }

                // @FriendlyName - optional
                attribute.FriendlyName = reader.GetAttribute(Saml2Constants.Attributes.FriendlyName);

                // @OriginalIssuer - optional.
                attribute.OriginalIssuer = reader.GetAttribute(Saml2Constants.Attributes.OriginalIssuer);

                // content
                reader.Read();
                if (!isEmpty)
                {
                    while (reader.IsStartElement(Saml2Constants.Elements.AttributeValue, Saml2Constants.Namespace))
                    {
                        bool isEmptyValue = reader.IsEmptyElement;
                        bool isNil = XmlUtil.IsNil(reader);

                        // FIP 9570 - ENTERPRISE SCENARIO: Saml11SecurityTokenHandler.ReadAttribute is not checking the AttributeValue XSI type correctly.
                        // Lax on receive. If we dont find the AttributeValueXsiType in the format we are looking for in the xml, we default to string.
                        // Read the xsi:type. We are expecting a value of the form "some-non-empty-string" or "some-non-empty-local-prefix:some-non-empty-string".
                        // ":some-non-empty-string" and "some-non-empty-string:" are edge-cases where defaulting to string is reasonable.
                        // For attributeValueXsiTypeSuffix, we want the portion after the local prefix in "some-non-empty-local-prefix:some-non-empty-string"
                        // "some-non-empty-local-prefix:some-non-empty-string" case
                        string attributeValueXsiTypePrefix = null;
                        string attributeValueXsiTypeSuffix = null;
                        string attributeValueXsiTypeSuffixWithLocalPrefix = reader.GetAttribute("type", XmlSchema.InstanceNamespace);
                        if (!string.IsNullOrEmpty(attributeValueXsiTypeSuffixWithLocalPrefix))
                        {
                            // "some-non-empty-string" case
                            if (attributeValueXsiTypeSuffixWithLocalPrefix.IndexOf(":", StringComparison.Ordinal) == -1)
                            {
                                attributeValueXsiTypePrefix = reader.LookupNamespace(String.Empty);
                                attributeValueXsiTypeSuffix = attributeValueXsiTypeSuffixWithLocalPrefix;
                            }
                            else if (attributeValueXsiTypeSuffixWithLocalPrefix.IndexOf(":", StringComparison.Ordinal) > 0 &&
                                      attributeValueXsiTypeSuffixWithLocalPrefix.IndexOf(":", StringComparison.Ordinal) < attributeValueXsiTypeSuffixWithLocalPrefix.Length - 1)
                            {
                                string localPrefix = attributeValueXsiTypeSuffixWithLocalPrefix.Substring(0, attributeValueXsiTypeSuffixWithLocalPrefix.IndexOf(":", StringComparison.Ordinal));
                                attributeValueXsiTypePrefix = reader.LookupNamespace(localPrefix);
                                attributeValueXsiTypeSuffix = attributeValueXsiTypeSuffixWithLocalPrefix.Substring(attributeValueXsiTypeSuffixWithLocalPrefix.IndexOf(":", StringComparison.Ordinal) + 1);
                            }
                        }

                        if (attributeValueXsiTypePrefix != null && attributeValueXsiTypeSuffix != null)
                        {
                            attribute.AttributeValueXsiType = String.Concat(attributeValueXsiTypePrefix, "#", attributeValueXsiTypeSuffix);
                        }

                        if (isNil)
                        {
                            reader.Read();
                            if (!isEmptyValue)
                            {
                                reader.ReadEndElement();
                            }

                            attribute.Values.Add(null);
                        }
                        else if (isEmptyValue)
                        {
                            reader.Read();
                            attribute.Values.Add(string.Empty);
                        }
                        else
                        {
                            attribute.Values.Add(ReadAttributeValue(reader, attribute));
                        }
                    }

                    reader.ReadEndElement();
                }

                return attribute;
            }
            catch (Exception ex)
            {
                throw LogReadException(LogMessages.IDX11102, Saml2Constants.Elements.Attribute, ex);
            }
        }

        /// <summary>
        /// Reads the &lt;saml:AttributeStatement> element, or a
        /// &lt;saml:Statement element that specifies an xsi:type of
        /// saml:AttributeStatementType.
        /// </summary>
        /// <param name="reader">A <see cref="XmlReader"/> positioned at a <see cref="Saml2AttributeStatement"/> element.</param>
        /// <returns>A <see cref="Saml2AttributeStatement"/> instance.</returns>
        public virtual Saml2AttributeStatement ReadAttributeStatement(XmlReader reader)
        {
            CheckReaderOnEntry(reader, Saml2Constants.Elements.AttributeStatement, Saml2Constants.Namespace);
            try
            {
                // @xsi:type
                XmlUtil.ValidateXsiType(reader, Saml2Constants.Types.AttributeStatementType, Saml2Constants.Namespace, false);

                // Content
                Saml2AttributeStatement statement = new Saml2AttributeStatement();
                reader.Read();

                // <Attribute|EncryptedAttribute> 1-OO
                while (reader.IsStartElement())
                {
                    if (reader.IsStartElement(Saml2Constants.Elements.EncryptedAttribute, Saml2Constants.Namespace))
                    {
                        throw LogReadException(LogMessages.IDX11117);
                    }
                    else if (reader.IsStartElement(Saml2Constants.Elements.Attribute, Saml2Constants.Namespace))
                    {
                        statement.Attributes.Add(ReadAttribute(reader));
                    }
                    else
                    {
                        break;
                    }
                }

                // At least one attribute expected
                if (0 == statement.Attributes.Count)
                {
                    reader.ReadStartElement(Saml2Constants.Elements.Attribute, Saml2Constants.Namespace);
                }

                reader.ReadEndElement();
                return statement;
            }
            catch (Exception ex)
            {
                throw LogReadException(LogMessages.IDX11102, ex, Saml2Constants.Elements.AttributeStatement);
            }
        }

        /// <summary>
        /// Reads an attribute value.
        /// </summary>
        /// <param name="reader">A <see cref="XmlReader"/> positioned at a <see cref="Saml2Attribute"/>.</param>
        /// <param name="attribute">The <see cref="Saml2Attribute"/>.</param>
        /// <returns>The attribute value as a string.</returns>
        /// <exception cref="ArgumentNullException">The input parameter 'reader' is null.</exception>
        public virtual string ReadAttributeValue(XmlReader reader, Saml2Attribute attribute)
        {
            // This code was designed realizing that the writter of the xml controls how our
            // reader will report the NodeType. A completely differnet system (IBM, etc) could write the values.
            // Considering NodeType is important, because we need to read the entire value, end element and not loose anything significant.
            //
            // Couple of cases to help understand the design choices.
            //
            // 1.
            // "<MyElement xmlns="urn:mynamespace"><another>complex</another></MyElement><sibling>value</sibling>"
            // Could result in the our reader reporting the NodeType as Text OR Element, depending if '<' was entitized to '&lt;'
            //
            // 2.
            // " <MyElement xmlns="urn:mynamespace"><another>complex</another></MyElement><sibling>value</sibling>"
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

            CheckReaderOnEntry(reader, Saml2Constants.Elements.AttributeValue, Saml2Constants.Namespace);

            string result = string.Empty;
            string whiteSpace = string.Empty;
            while (reader.NodeType == XmlNodeType.Whitespace)
            {
                whiteSpace += reader.Value;
                reader.Read();
            }

            reader.ReadStartElement(Saml2Constants.Elements.AttributeValue, Saml2Constants.Namespace);
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

        /// <summary>
        /// Reads the &lt;saml:AudienceRestriction> element or a 
        /// &lt;saml:Condition> element that specifies an xsi:type
        /// of saml:AudienceRestrictionType.
        /// </summary>
        /// <param name="reader">A <see cref="XmlReader"/> positioned at a <see cref="Saml2AudienceRestriction"/> element.</param>
        /// <returns>A <see cref="Saml2AudienceRestriction"/> instance.</returns>
        public virtual Saml2AudienceRestriction ReadAudienceRestriction(XmlReader reader)
        {
            if (null == reader)
                LogHelper.LogArgumentNullException(nameof(reader));

            // throw if wrong element
            bool isConditionElement = false;
            if (reader.IsStartElement(Saml2Constants.Elements.Condition, Saml2Constants.Namespace))
            {
                isConditionElement = true;
            }
            else if (!reader.IsStartElement(Saml2Constants.Elements.AudienceRestriction, Saml2Constants.Namespace))
            {
                reader.ReadStartElement(Saml2Constants.Elements.AudienceRestriction, Saml2Constants.Namespace);
            }

            try
            {
                // disallow empty
                if (reader.IsEmptyElement)
                    LogReadException(LogMessages.IDX11104, Saml2Constants.Elements.AudienceRestriction);

                Saml2AudienceRestriction audienceRestriction;

                // @xsi:type -- if we're a <Condition> element, this declaration must be present
                XmlUtil.ValidateXsiType(reader, Saml2Constants.Types.AudienceRestrictionType, Saml2Constants.Namespace, isConditionElement);


                // content
                reader.Read();

                // <Audience> - 1-OO
                if (!reader.IsStartElement(Saml2Constants.Elements.Audience, Saml2Constants.Namespace))
                {
                    reader.ReadStartElement(Saml2Constants.Elements.Audience, Saml2Constants.Namespace);
                }

                // We are now laxing the uri check for audience restriction to support interop partners 
                // This is a specific request from server : Bug 11850
                // ReadSimpleUriElement now has a flag that turns lax reading ON/OFF.
                audienceRestriction = new Saml2AudienceRestriction(ReadSimpleUriElement(reader, Saml2Constants.Elements.Audience, UriKind.RelativeOrAbsolute, false).OriginalString);
                while (reader.IsStartElement(Saml2Constants.Elements.Audience, Saml2Constants.Namespace))
                {
                    audienceRestriction.Audiences.Add(ReadSimpleUriElement(reader, Saml2Constants.Elements.Audience, UriKind.RelativeOrAbsolute, false).OriginalString);
                }

                reader.ReadEndElement();
                return audienceRestriction;
            }
            catch (Exception ex)
            {
                throw LogReadException(LogMessages.IDX11102, ex, Saml2Constants.Elements.Audience);
            }
        }

        /// <summary>
        /// Reads the &lt;saml:AuthnContext> element.
        /// </summary>
        /// <remarks>
        /// The default implementation does not handle the optional
        /// &lt;saml:AuthnContextDecl> element. To handle by-value
        /// authentication context declarations, override this method.
        /// </remarks>
        /// <param name="reader">A <see cref="XmlReader"/> positioned at a <see cref="Saml2AuthenticationContext"/> element.</param>
        /// <returns>A <see cref="Saml2AuthenticationContext"/> instance.</returns>
        public virtual Saml2AuthenticationContext ReadAuthenticationContext(XmlReader reader)
        {
            CheckReaderOnEntry(reader, Saml2Constants.Elements.AuthnContext, Saml2Constants.Namespace);
            try
            {
                // @xsi:type
                XmlUtil.ValidateXsiType(reader, Saml2Constants.Types.AuthnContextType, Saml2Constants.Namespace);

                // Content
                reader.ReadStartElement();

                // At least one of ClassRef and ( Decl XOR DeclRef) must be present
                // At this time, we do not support Decl, which is a by-value 
                // authentication context declaration.
                Uri classRef = null;
                Uri declRef = null;

                // <AuthnContextClassRef> - see comment above
                if (reader.IsStartElement(Saml2Constants.Elements.AuthnContextClassRef, Saml2Constants.Namespace))
                    classRef = ReadSimpleUriElement(reader, Saml2Constants.Elements.AuthnContextClassRef, UriKind.RelativeOrAbsolute, false);

                // <AuthnContextDecl> - see comment above
                if (reader.IsStartElement(Saml2Constants.Elements.AuthnContextDecl, Saml2Constants.Namespace))
                    throw LogReadException(LogMessages.IDX11118);

                // <AuthnContextDeclRef> - see comment above
                // If there was no ClassRef, there must be a DeclRef
                if (reader.IsStartElement(Saml2Constants.Elements.AuthnContextDeclRef, Saml2Constants.Namespace))
                    declRef = ReadSimpleUriElement(reader, Saml2Constants.Elements.AuthnContextDeclRef, UriKind.RelativeOrAbsolute, false);
                else if (null == classRef)
                    reader.ReadStartElement(Saml2Constants.Elements.AuthnContextDeclRef, Saml2Constants.Namespace);

                // Now we have enough data to create the object
                // TODO - relax URI - string?
                var authnContext = new Saml2AuthenticationContext(classRef, declRef);

                // <AuthenticatingAuthority> - 0-OO
                while (reader.IsStartElement(Saml2Constants.Elements.AuthenticatingAuthority, Saml2Constants.Namespace))
                    authnContext.AuthenticatingAuthorities.Add(ReadSimpleUriElement(reader, Saml2Constants.Elements.AuthenticatingAuthority, UriKind.RelativeOrAbsolute, false));

                reader.ReadEndElement();
                return authnContext;
            }
            catch (Exception ex)
            {
                throw LogReadException(LogMessages.IDX11102, ex, Saml2Constants.Elements.AuthnContext);
            }
        }

        /// <summary>
        /// Reads the &lt;saml:AuthnStatement> element or a &lt;saml:Statement>
        /// element that specifies an xsi:type of saml:AuthnStatementType.
        /// </summary>
        /// <param name="reader">A <see cref="XmlReader"/> positioned at a <see cref="Saml2AuthenticationStatement"/> element.</param>
        /// <returns>A <see cref="Saml2AuthenticationStatement"/> instance.</returns>
        public virtual Saml2AuthenticationStatement ReadAuthenticationStatement(XmlReader reader)
        {
            CheckReaderOnEntry(reader, Saml2Constants.Elements.AuthnStatement, Saml2Constants.Namespace);
            try
            {
                // Must cache the individual data since the required
                // AuthnContext comes last
                DateTime authnInstant;
                Saml2AuthenticationContext authnContext;
                string sessionIndex;
                DateTime? sessionNotOnOrAfter = null;
                Saml2SubjectLocality subjectLocality = null;

                // defer disallowing empty until after xsi:type
                bool isEmpty = reader.IsEmptyElement;

                // @attributes
                string value;

                // @xsi:type -- if we're a <Statement> element, this declaration must be present
                XmlUtil.ValidateXsiType(reader, Saml2Constants.Types.AuthnStatementType, Saml2Constants.Namespace, false);

                // @AuthnInstant - required
                value = reader.GetAttribute(Saml2Constants.Attributes.AuthnInstant);
                if (string.IsNullOrEmpty(value))
                    throw LogReadException(LogMessages.IDX11106, Saml2Constants.Elements.AuthnStatement, Saml2Constants.Attributes.AuthnInstant);

                authnInstant = XmlConvert.ToDateTime(value, Saml2Constants.AcceptedDateTimeFormats);

                // @SessionIndex - optional
                sessionIndex = reader.GetAttribute(Saml2Constants.Attributes.SessionIndex);

                // @SessionNotOnOrAfter - optional
                value = reader.GetAttribute(Saml2Constants.Attributes.SessionNotOnOrAfter);
                if (!string.IsNullOrEmpty(value))
                    sessionNotOnOrAfter = XmlConvert.ToDateTime(value, Saml2Constants.AcceptedDateTimeFormats);

                // Content
                reader.Read();

                // <SubjectLocality> 0-1
                if (reader.IsStartElement(Saml2Constants.Elements.SubjectLocality, Saml2Constants.Namespace))
                    subjectLocality = ReadSubjectLocality(reader);

                // <AuthnContext> 1
                authnContext = ReadAuthenticationContext(reader);

                reader.ReadEndElement();

                // Construct the actual object
                var authnStatement = new Saml2AuthenticationStatement(authnContext, authnInstant);
                authnStatement.SessionIndex = sessionIndex;
                authnStatement.SessionNotOnOrAfter = sessionNotOnOrAfter;
                authnStatement.SubjectLocality = subjectLocality;
                return authnStatement;
            }
            catch (Exception ex)
            {
                throw LogReadException(LogMessages.IDX11102, ex, Saml2Constants.Elements.AuthnStatement);
            }
        }

        /// <summary>
        /// Reads the &lt;saml:AuthzDecisionStatement> element or a
        /// &lt;saml:Statement element that specifies an xsi:type of
        /// saml:AuthzDecisionStatementType.
        /// </summary>
        /// <param name="reader">A <see cref="XmlReader"/> positioned at a <see cref="Saml2AuthorizationDecisionStatement"/> element.</param>
        /// <returns>A <see cref="Saml2AuthorizationDecisionStatement"/> instance.</returns>
        public virtual Saml2AuthorizationDecisionStatement ReadAuthorizationDecisionStatement(XmlReader reader)
        {
            CheckReaderOnEntry(reader, Saml2Constants.Elements.AuthzDecisionStatement, Saml2Constants.Namespace);
            try
            {
                // Need the attributes before we can instantiate
                Saml2AuthorizationDecisionStatement statement;
                Saml2AccessDecision decision;
                Uri resource;

                // @attributes
                string value;

                // @xsi:type
                XmlUtil.ValidateXsiType(reader, Saml2Constants.Types.AuthzDecisionStatementType, Saml2Constants.Namespace, false);

                // @Decision - required
                value = reader.GetAttribute(Saml2Constants.Attributes.Decision);
                if (string.IsNullOrEmpty(value))
                    throw LogReadException(LogMessages.IDX11106, Saml2Constants.Elements.AuthzDecisionStatement, Saml2Constants.Attributes.Decision);
                else if (StringComparer.Ordinal.Equals(Saml2AccessDecision.Permit.ToString(), value))
                    decision = Saml2AccessDecision.Permit;
                else if (StringComparer.Ordinal.Equals(Saml2AccessDecision.Deny.ToString(), value))
                    decision = Saml2AccessDecision.Deny;
                else if (StringComparer.Ordinal.Equals(Saml2AccessDecision.Indeterminate.ToString(), value))
                    decision = Saml2AccessDecision.Indeterminate;
                else
                    throw LogReadException(LogMessages.IDX11135, value);

                // @Resource - required
                value = reader.GetAttribute(Saml2Constants.Attributes.Resource);
                if (null == value)
                {
                    throw LogReadException(LogMessages.IDX11106, Saml2Constants.Elements.AuthzDecisionStatement, Saml2Constants.Attributes.Resource);
                }
                else if (0 == value.Length)
                {
                    resource = Saml2AuthorizationDecisionStatement.EmptyResource;
                }
                else
                {
                    if (!UriUtil.CanCreateValidUri(value, UriKind.Absolute))
                        throw LogReadException(LogMessages.IDX11107, Saml2Constants.Elements.AuthzDecisionStatement, Saml2Constants.Attributes.Resource, value);

                    resource = new Uri(value);
                }

                // Content
                statement = new Saml2AuthorizationDecisionStatement(resource, decision);
                reader.Read();

                // <Action> 1-OO
                do
                {
                    statement.Actions.Add(ReadAction(reader));
                }
                while (reader.IsStartElement(Saml2Constants.Elements.Action, Saml2Constants.Namespace));

                // <Evidence> 0-1
                if (reader.IsStartElement(Saml2Constants.Elements.Evidence, Saml2Constants.Namespace))
                    statement.Evidence = ReadEvidence(reader);

                reader.ReadEndElement();
                return statement;
            }
            catch (Exception ex)
            {
                throw LogReadException(LogMessages.IDX11102, ex, Saml2Constants.Elements.AuthnStatement);
            }
        }

        /// <summary>
        /// Reads the &lt;saml:Conditions> element.
        /// </summary>
        /// <remarks>
        /// To handle custom &lt;saml:Condition> elements, override this
        /// method.
        /// </remarks>
        /// <param name="reader">A <see cref="XmlReader"/> positioned at a <see cref="Saml2Conditions"/> element.</param>
        /// <returns>A <see cref="Saml2Conditions"/> instance.</returns>
        public virtual Saml2Conditions ReadConditions(XmlReader reader)
        {
            CheckReaderOnEntry(reader, Saml2Constants.Elements.Conditions, Saml2Constants.Namespace);
            try
            {
                Saml2Conditions conditions = new Saml2Conditions();
                bool isEmpty = reader.IsEmptyElement;

                // @xsi:type
                XmlUtil.ValidateXsiType(reader, Saml2Constants.Types.ConditionsType, Saml2Constants.Namespace);

                // @NotBefore - optional
                var value = reader.GetAttribute(Saml2Constants.Attributes.NotBefore);
                if (!string.IsNullOrEmpty(value))
                    conditions.NotBefore = XmlConvert.ToDateTime(value, Saml2Constants.AcceptedDateTimeFormats);

                // @NotOnOrAfter - optional
                value = reader.GetAttribute(Saml2Constants.Attributes.NotOnOrAfter);
                if (!string.IsNullOrEmpty(value))
                    conditions.NotOnOrAfter = XmlConvert.ToDateTime(value, Saml2Constants.AcceptedDateTimeFormats);

                // Content
                reader.ReadStartElement();
                if (!isEmpty)
                {
                    // <Condition|AudienceRestriction|OneTimeUse|ProxyRestriction>, 0-OO
                    while (reader.IsStartElement())
                    {
                        // <Condition> - 0-OO
                        if (reader.IsStartElement(Saml2Constants.Elements.Condition, Saml2Constants.Namespace))
                        {
                            // Since Condition is abstract, must process based on xsi:type
                            XmlQualifiedName declaredType = XmlUtil.GetXsiType(reader);

                            // No type, throw
                            if (null == declaredType
                                || XmlUtil.EqualsQName(declaredType, Saml2Constants.Types.ConditionAbstractType, Saml2Constants.Namespace))
                            {
                                throw LogReadException(LogMessages.IDX11119, reader.LocalName, reader.NamespaceURI);
                            }
                            else if (XmlUtil.EqualsQName(declaredType, Saml2Constants.Types.AudienceRestrictionType, Saml2Constants.Namespace))
                            {
                                conditions.AudienceRestrictions.Add(ReadAudienceRestriction(reader));
                            }
                            else if (XmlUtil.EqualsQName(declaredType, Saml2Constants.Types.OneTimeUseType, Saml2Constants.Namespace))
                            {
                                if (conditions.OneTimeUse)
                                    throw LogReadException(LogMessages.IDX11120, Saml2Constants.Elements.OneTimeUse);

                                ReadEmptyContentElement(reader);
                                conditions.OneTimeUse = true;
                            }
                            else if (XmlUtil.EqualsQName(declaredType, Saml2Constants.Types.ProxyRestrictionType, Saml2Constants.Namespace))
                            {
                                if (null != conditions.ProxyRestriction)
                                    throw LogReadException(LogMessages.IDX11120, Saml2Constants.Elements.ProxyRestricton);

                                conditions.ProxyRestriction = ReadProxyRestriction(reader);
                            }
                            else
                            {
                                // Unknown type - Instruct the user to override to handle custom <Condition>
                                throw LogReadException(LogMessages.IDX11121);
                            }
                        }
                        else if (reader.IsStartElement(Saml2Constants.Elements.AudienceRestriction, Saml2Constants.Namespace))
                        {
                            conditions.AudienceRestrictions.Add(ReadAudienceRestriction(reader));
                        }
                        else if (reader.IsStartElement(Saml2Constants.Elements.OneTimeUse, Saml2Constants.Namespace))
                        {
                            if (conditions.OneTimeUse)
                            {
                                throw LogReadException(LogMessages.IDX11120, Saml2Constants.Elements.OneTimeUse);
                            }

                            ReadEmptyContentElement(reader);
                            conditions.OneTimeUse = true;
                        }
                        else if (reader.IsStartElement(Saml2Constants.Elements.ProxyRestricton, Saml2Constants.Namespace))
                        {
                            if (null != conditions.ProxyRestriction)
                                throw LogReadException(LogMessages.IDX11120, Saml2Constants.Elements.ProxyRestricton);

                            conditions.ProxyRestriction = ReadProxyRestriction(reader);
                        }
                        else
                        {
                            break;
                        }
                    }

                    reader.ReadEndElement();
                }

                return conditions;
            }
            catch (Exception ex)
            {
                throw LogReadException(LogMessages.IDX11102, ex, Saml2Constants.Elements.Conditions);
            }
        }

        /// <summary>
        /// Reads the &lt;saml:EncryptedId> element.
        /// </summary>
        /// <param name="reader"><see cref="XmlReader"/> pointing at the XML EncryptedId element</param>
        /// <returns>An instance of <see cref="Saml2NameIdentifier"/> representing the EncryptedId that was read</returns>
        /// <exception cref="ArgumentNullException">The input parameter 'reader' is null.</exception>
        /// <exception cref="XmlException">The 'reader' is not positioned at an 'EncryptedID' element.</exception>
        public virtual Saml2NameIdentifier ReadEncryptedId(XmlReader reader)
        {
            throw new NotImplementedException("not implemented yet");
            //if (null == reader)
            //{
            //    throw LogHelper.LogArgumentNullException(nameof(reader));
            //}

            //reader.MoveToContent();

            //if (!reader.IsStartElement(Saml2Constants.Elements.EncryptedID, Saml2Constants.Namespace))
            //{
            //    // throw if wrong element
            //    reader.ReadStartElement(Saml2Constants.Elements.EncryptedID, Saml2Constants.Namespace);
            //}

            //Collection<EncryptedKeyIdentifierClause> clauses = new Collection<EncryptedKeyIdentifierClause>();
            //EncryptingCredentials encryptingCredentials = null;
            //Saml2NameIdentifier saml2NameIdentifier = null;

            //using (StringReader sr = new StringReader(reader.ReadOuterXml()))
            //{
            //    using (XmlDictionaryReader wrappedReader = new WrappedXmlDictionaryReader(XmlReader.Create(sr), XmlDictionaryReaderQuotas.Max))
            //    {
            //        XmlReader plaintextReader = CreatePlaintextReaderFromEncryptedData(
            //                    wrappedReader,
            //                    Configuration.ServiceTokenResolver,
            //                    this.KeyInfoSerializer,
            //                    clauses,
            //                    out encryptingCredentials);

            //        saml2NameIdentifier = this.ReadNameIdType(plaintextReader);
            //        saml2NameIdentifier.EncryptingCredentials = encryptingCredentials;
            //        foreach (EncryptedKeyIdentifierClause clause in clauses)
            //        {
            //            saml2NameIdentifier.ExternalEncryptedKeys.Add(clause);
            //        }
            //    }
            //}

            //return saml2NameIdentifier;
        }

        /// <summary>
        /// Reads the &lt;saml:Evidence> element.
        /// </summary>
        /// <param name="reader">A <see cref="XmlReader"/> positioned at a <see cref="Saml2Evidence"/> element.</param>
        /// <returns>A <see cref="Saml2Evidence"/> instance.</returns>
        public virtual Saml2Evidence ReadEvidence(XmlReader reader)
        {
            CheckReaderOnEntry(reader, Saml2Constants.Elements.Evidence, Saml2Constants.Namespace);
            try
            {
                Saml2Evidence evidence = new Saml2Evidence();

                // @attributes

                // @xsi:type
                XmlUtil.ValidateXsiType(reader, Saml2Constants.Types.EvidenceType, Saml2Constants.Namespace);

                reader.Read();

                // <AssertionIDRef|AssertionURIRef|Assertion|EncryptedAssertion> 0-OO
                while (reader.IsStartElement())
                {
                    if (reader.IsStartElement(Saml2Constants.Elements.AssertionIDRef, Saml2Constants.Namespace))
                    {
                        evidence.AssertionIdReferences.Add(ReadSimpleNCNameElement(reader, Saml2Constants.Elements.AssertionIDRef));
                    }
                    else if (reader.IsStartElement(Saml2Constants.Elements.AssertionURIRef, Saml2Constants.Namespace))
                    {
                        evidence.AssertionUriReferences.Add(ReadSimpleUriElement(reader, Saml2Constants.Elements.AssertionURIRef, UriKind.RelativeOrAbsolute, false));
                    }
                    else if (reader.IsStartElement(Saml2Constants.Elements.Assertion, Saml2Constants.Namespace))
                    {
                        evidence.Assertions.Add(ReadAssertion(reader));
                    }
                    else if (reader.IsStartElement(Saml2Constants.Elements.EncryptedAssertion, Saml2Constants.Namespace))
                    {
                        evidence.Assertions.Add(ReadAssertion(reader));
                    }
                }

                if (0 == evidence.AssertionIdReferences.Count
                        && 0 == evidence.Assertions.Count
                        && 0 == evidence.AssertionUriReferences.Count)
                    throw LogReadException(LogMessages.IDX11122);

                reader.ReadEndElement();

                return evidence;
            }
            catch (Exception ex)
            {
                throw LogReadException(LogMessages.IDX11102, ex, Saml2Constants.Elements.Evidence);
            }
        }

        /// <summary>
        /// Reads the &lt;saml:Issuer> element.
        /// </summary>
        /// <param name="reader">A <see cref="XmlReader"/> positioned at a <see cref="Saml2NameIdentifier"/> element.</param>
        /// <returns>A <see cref="Saml2NameIdentifier"/> instance.</returns>
        public virtual Saml2NameIdentifier ReadIssuer(XmlReader reader)
        {
            CheckReaderOnEntry(reader, Saml2Constants.Elements.Issuer, Saml2Constants.Namespace);
            return ReadNameIdType(reader);
        }

        /// <summary>
        /// Reads the &lt;saml:NameID> element.
        /// </summary>
        /// <param name="reader">A <see cref="XmlReader"/> positioned at a <see cref="Saml2NameIdentifier"/> element.</param>
        /// <returns>An instance of <see cref="Saml2NameIdentifier"/></returns>
        /// <exception cref="ArgumentNullException">The input parameter 'reader' is null.</exception>
        public virtual Saml2NameIdentifier ReadNameId(XmlReader reader)
        {
            if (reader == null)
                throw LogHelper.LogArgumentNullException(nameof(reader));

            // throw if wrong element
            if (!reader.IsStartElement(Saml2Constants.Elements.NameID, Saml2Constants.Namespace))
                LogReadException(LogMessages.IDX11105, Saml2Constants.Elements.NameID, reader.LocalName);

            return ReadNameIdType(reader);
        }

        /// <summary>
        /// Both &lt;Issuer> and &lt;NameID> are of NameIDType. This method reads
        /// the content of either one of those elements.
        /// </summary>
        /// <param name="reader">A <see cref="XmlReader"/> positioned at a <see cref="Saml2NameIdentifier"/> element.</param>
        /// <returns>An instance of <see cref="Saml2NameIdentifier"/></returns>
        public virtual Saml2NameIdentifier ReadNameIdType(XmlReader reader)
        {
            try
            {
                reader.MoveToContent();

                Saml2NameIdentifier nameIdentifier = new Saml2NameIdentifier("__TemporaryName__");

                // @attributes
                string value;

                // @xsi:type
                XmlUtil.ValidateXsiType(reader, Saml2Constants.Types.NameIDType, Saml2Constants.Namespace);

                // @Format - optional
                value = reader.GetAttribute(Saml2Constants.Attributes.Format);
                if (!string.IsNullOrEmpty(value))
                {
                    if (!UriUtil.CanCreateValidUri(value, UriKind.Absolute))
                        throw LogReadException(LogMessages.IDX11107, Saml2Constants.Types.NameIDType, Saml2Constants.Attributes.Format, reader.LocalName);

                    nameIdentifier.Format = new Uri(value);
                }

                // @NameQualifier - optional
                value = reader.GetAttribute(Saml2Constants.Attributes.NameQualifier);
                if (!string.IsNullOrEmpty(value))
                {
                    nameIdentifier.NameQualifier = value;
                }

                // @SPNameQualifier - optional
                value = reader.GetAttribute(Saml2Constants.Attributes.SPNameQualifier);
                if (!string.IsNullOrEmpty(value))
                {
                    nameIdentifier.SPNameQualifier = value;
                }

                // @SPProvidedID - optional
                value = reader.GetAttribute(Saml2Constants.Attributes.SPProvidedID);
                if (!string.IsNullOrEmpty(value))
                {
                    nameIdentifier.SPProvidedId = value;
                }

                // Content is string
                nameIdentifier.Value = reader.ReadElementContentAsString();

                // According to section 8.3.6, if the name identifier format is of type 'urn:oasis:names:tc:SAML:2.0:nameid-format:entity'
                // the name identifier value must be a uri and name qualifier, spname qualifier, and spproded id must be omitted.
                if (nameIdentifier.Format != null &&
                    StringComparer.Ordinal.Equals(nameIdentifier.Format.AbsoluteUri, Saml2Constants.NameIdentifierFormats.Entity.AbsoluteUri))
                {
                    if (!UriUtil.CanCreateValidUri(nameIdentifier.Value, UriKind.Absolute))
                        throw LogReadException(LogMessages.IDX11107, Saml2Constants.Elements.NameID, Saml2Constants.Types.NameIDType, reader.LocalName);

                    if (!string.IsNullOrEmpty(nameIdentifier.NameQualifier)
                        || !string.IsNullOrEmpty(nameIdentifier.SPNameQualifier)
                        || !string.IsNullOrEmpty(nameIdentifier.SPProvidedId))
                        throw LogReadException(LogMessages.IDX11124, nameIdentifier.Value, Saml2Constants.NameIdentifierFormats.Entity.AbsoluteUri);
                }
                return nameIdentifier;
            }
            catch (Exception ex)
            {
                throw LogReadException(LogMessages.IDX11102, ex, Saml2Constants.Types.NameIDType);
            }
        }

        /// <summary>
        /// Reads the &lt;saml:ProxyRestriction> element, or a &lt;saml:Condition>
        /// element that specifies an xsi:type of saml:ProxyRestrictionType.
        /// </summary>
        /// <remarks>
        /// In the default implementation, the maximum value of the Count attribute
        /// is limited to Int32.MaxValue.
        /// </remarks>
        /// <param name="reader">A <see cref="XmlReader"/> positioned at a <see cref="Saml2ProxyRestriction"/> element.</param>
        /// <returns>An instance of <see cref="Saml2ProxyRestriction"/></returns>
        public virtual Saml2ProxyRestriction ReadProxyRestriction(XmlReader reader)
        {
            if (reader == null)
                throw LogHelper.LogArgumentNullException(nameof(reader));

            // throw if wrong element
            bool isConditionElement = false;
            if (reader.IsStartElement(Saml2Constants.Elements.Condition, Saml2Constants.Namespace))
                isConditionElement = true;
            else if (!reader.IsStartElement(Saml2Constants.Elements.ProxyRestricton, Saml2Constants.Namespace))

                reader.ReadStartElement(Saml2Constants.Elements.ProxyRestricton, Saml2Constants.Namespace);

            try
            {
                Saml2ProxyRestriction proxyRestriction = new Saml2ProxyRestriction();
                bool isEmpty = reader.IsEmptyElement;

                // @attributes
                string value;

                // @xsi:type -- if we're a <Condition> element, this declaration must be present
                XmlUtil.ValidateXsiType(reader, Saml2Constants.Types.ProxyRestrictionType, Saml2Constants.Namespace, isConditionElement);

                // @Count - optional
                value = reader.GetAttribute(Saml2Constants.Attributes.Count);
                if (!string.IsNullOrEmpty(value))
                {
                    proxyRestriction.Count = XmlConvert.ToInt32(value);
                }

                // content
                reader.Read();
                if (!isEmpty)
                {
                    // <Audience> - 0-OO
                    while (reader.IsStartElement(Saml2Constants.Elements.Audience, Saml2Constants.Namespace))
                    {
                        proxyRestriction.Audiences.Add(ReadSimpleUriElement(reader, Saml2Constants.Elements.Audience, UriKind.RelativeOrAbsolute, false));
                    }

                    reader.ReadEndElement();
                }

                return proxyRestriction;
            }
            catch (Exception ex)
            {
                throw LogReadException(LogMessages.IDX11102, ex, Saml2Constants.Elements.ProxyRestricton);
            }
        }

        /// <summary>
        /// Deserializes the SAML Signing KeyInfo
        /// </summary>
        /// <param name="reader">A <see cref="XmlReader"/> positioned at a than can be positioned at a ds:KeyInfo element.</param>
        /// <param name="assertion">The <see cref="Saml2Assertion"/> that is having the signature checked.</param>
        /// <returns>The <see cref="SecurityKeyIdentifier"/> that defines the key to use to check the signature.</returns>
        /// <exception cref="ArgumentNullException">Input parameter 'reader' is null.</exception>
        public virtual SecurityKeyIdentifier ReadSigningKeyInfo(XmlReader reader, Saml2Assertion assertion)
        {
            if (null == reader)
                throw LogHelper.LogArgumentNullException(nameof(reader));

            // TODO - SecurityKey read / write
            reader.Skip();

            return null;
            //SecurityKeyIdentifier ski;

            //if (this.KeyInfoSerializer.CanReadKeyIdentifier(reader))
            //{
            //    ski = this.KeyInfoSerializer.ReadKeyIdentifier(reader);
            //}
            //else
            //{
            //    KeyInfo keyInfo = new KeyInfo(this.KeyInfoSerializer);
            //    keyInfo.ReadXml(XmlDictionaryReader.CreateDictionaryReader(reader));
            //    ski = keyInfo.KeyIdentifier;
            //}

            //// no key info
            //if (ski.Count == 0)
            //{
            //    return new SecurityKeyIdentifier(new Saml2SecurityKeyIdentifierClause(assertion));
            //}

            //return ski;
        }

        /// <summary>
        /// Reads the &lt;saml:Statement> element.
        /// </summary>
        /// <param name="reader">A <see cref="XmlReader"/> positioned at a <see cref="Saml2Statement"/> element.</param>
        /// <returns>An instance of <see cref="Saml2Statement"/> derived type.</returns>
        /// <remarks>
        /// The default implementation only handles Statement elements which
        /// specify an xsi:type of saml:AttributeStatementType,
        /// saml:AuthnStatementType, and saml:AuthzDecisionStatementType. To
        /// handle custom statements, override this method.
        /// </remarks>
        public virtual Saml2Statement ReadStatement(XmlReader reader)
        {
            if (null == reader)
            {
                throw LogHelper.LogArgumentNullException(nameof(reader));
            }

            // throw if wrong element
            if (!reader.IsStartElement(Saml2Constants.Elements.Statement, Saml2Constants.Namespace))
            {
                reader.ReadStartElement(Saml2Constants.Elements.Statement, Saml2Constants.Namespace);
            }

            // Since Statement is an abstract type, we have to switch off the xsi:type declaration
            XmlQualifiedName declaredType = XmlUtil.GetXsiType(reader);

            // No declaration, or declaring that this is just a "Statement", is invalid since
            // statement is abstract
            if (null == declaredType
                || XmlUtil.EqualsQName(declaredType, Saml2Constants.Types.StatementAbstractType, Saml2Constants.Namespace))
            {
                throw LogReadException(LogMessages.IDX11119, reader.LocalName, reader.NamespaceURI);
            }

            // Reroute to the known statement types if applicable
            if (XmlUtil.EqualsQName(declaredType, Saml2Constants.Types.AttributeStatementType, Saml2Constants.Namespace))
                return ReadAttributeStatement(reader);
            else if (XmlUtil.EqualsQName(declaredType, Saml2Constants.Types.AuthnStatementType, Saml2Constants.Namespace))
                return ReadAuthenticationStatement(reader);
            else if (XmlUtil.EqualsQName(declaredType, Saml2Constants.Types.AuthzDecisionStatementType, Saml2Constants.Namespace))
                return ReadAuthorizationDecisionStatement(reader);
            else
                throw LogReadException(LogMessages.IDX11119, declaredType.Name, declaredType.Namespace);
        }

        /// <summary>
        /// Reads the &lt;saml:Subject> element.
        /// </summary>
        /// <param name="reader">A <see cref="XmlReader"/> positioned at a <see cref="Saml2Subject"/> element.</param>
        /// <returns>An instance of <see cref="Saml2Subject"/> .</returns>
        /// <remarks>
        /// The default implementation does not handle the optional
        /// &lt;EncryptedID> element. To handle encryped IDs in the Subject,
        /// override this method.
        /// </remarks>
        public virtual Saml2Subject ReadSubject(XmlReader reader)
        {
            CheckReaderOnEntry(reader, Saml2Constants.Elements.Subject, Saml2Constants.Namespace);
            try
            {
                // @attributes

                // @xsi:type
                XmlUtil.ValidateXsiType(reader, Saml2Constants.Types.SubjectType, Saml2Constants.Namespace);

                // <elements>
                Saml2Subject subject = new Saml2Subject();
                reader.Read();

                // <NameID> | <EncryptedID> | <BaseID> 0-1
                subject.NameId = ReadSubjectId(reader, Saml2Constants.Elements.Subject);

                // <SubjectConfirmation> 0-OO
                while (reader.IsStartElement(Saml2Constants.Elements.SubjectConfirmation, Saml2Constants.Namespace))
                {
                    subject.SubjectConfirmations.Add(ReadSubjectConfirmation(reader));
                }

                reader.ReadEndElement();

                // Must have a NameID or a SubjectConfirmation
                if (null == subject.NameId && 0 == subject.SubjectConfirmations.Count)
                    throw LogReadException(LogMessages.IDX11125);

                return subject;
            }
            catch (Exception ex)
            {
                throw LogReadException(LogMessages.IDX11102, ex, Saml2Constants.Elements.Subject);
            }
        }

        /// <summary>
        /// Reads the &lt;SubjectConfirmation> element.
        /// </summary>
        /// <param name="reader">A <see cref="XmlReader"/> positioned at a <see cref="Saml2SubjectConfirmation"/> element.</param>
        /// <returns>An instance of <see cref="Saml2SubjectConfirmation"/> .</returns>
        public virtual Saml2SubjectConfirmation ReadSubjectConfirmation(XmlReader reader)
        {
            CheckReaderOnEntry(reader, Saml2Constants.Elements.SubjectConfirmation, Saml2Constants.Namespace, true);
            try
            {
                bool isEmpty = reader.IsEmptyElement;

                // @attributes

                // @xsi:type
                XmlUtil.ValidateXsiType(reader, Saml2Constants.Types.SubjectConfirmationType, Saml2Constants.Namespace);

                // @Method - required
                string method = reader.GetAttribute(Saml2Constants.Attributes.Method);
                if (string.IsNullOrEmpty(method))
                    throw LogReadException(LogMessages.IDX11106, Saml2Constants.Elements.SubjectConfirmation, Saml2Constants.Attributes.Method);

                if (!UriUtil.CanCreateValidUri(method, UriKind.Absolute))
                    throw LogReadException(LogMessages.IDX11107, Saml2Constants.Types.SubjectConfirmationType, Saml2Constants.Attributes.Method, reader.LocalName);

                // Construct the appropriate SubjectConfirmation based on the method
                Saml2SubjectConfirmation subjectConfirmation = new Saml2SubjectConfirmation(new Uri(method));

                // <elements>
                reader.Read();
                if (!isEmpty)
                {
                    // <NameID> | <EncryptedID> | <BaseID> 0-1
                    subjectConfirmation.NameIdentifier = ReadSubjectId(reader, Saml2Constants.Elements.SubjectConfirmation);

                    // <SubjectConfirmationData> 0-1
                    if (reader.IsStartElement(Saml2Constants.Elements.SubjectConfirmationData, Saml2Constants.Namespace))
                        subjectConfirmation.SubjectConfirmationData = ReadSubjectConfirmationData(reader);

                    reader.ReadEndElement();
                }

                return subjectConfirmation;
            }
            catch (Exception ex)
            {
                throw LogReadException(LogMessages.IDX11102, ex, Saml2Constants.Elements.SubjectConfirmation);
            }
        }

        /// <summary>
        /// Reads the &lt;saml:SubjectConfirmationData> element.
        /// </summary>
        /// <param name="reader">A <see cref="XmlReader"/> positioned at a <see cref="Saml2SubjectConfirmationData"/> element.</param>
        /// <returns>An instance of <see cref="Saml2SubjectConfirmationData"/> .</returns>
        /// <remarks>
        /// The default implementation handles the unextended element
        /// as well as the extended type saml:KeyInfoConfirmationDataType.
        /// </remarks>
        public virtual Saml2SubjectConfirmationData ReadSubjectConfirmationData(XmlReader reader)
        {
            CheckReaderOnEntry(reader, Saml2Constants.Elements.SubjectConfirmationData, Saml2Constants.Namespace);
            try
            {
                Saml2SubjectConfirmationData confirmationData = new Saml2SubjectConfirmationData();
                bool isEmpty = reader.IsEmptyElement;

                // @attributes
                string value;

                // @xsi:type
                bool requireKeyInfo = false;
                XmlQualifiedName type = XmlUtil.GetXsiType(reader);

                if (null != type)
                {
                    if (XmlUtil.EqualsQName(type, Saml2Constants.Types.KeyInfoConfirmationDataType, Saml2Constants.Namespace))
                        requireKeyInfo = true;
                    else if (!XmlUtil.EqualsQName(type, Saml2Constants.Types.SubjectConfirmationDataType, Saml2Constants.Namespace))
                        throw LogReadException(LogMessages.IDX11126, type.Name, type.Namespace);
                }

                // KeyInfoConfirmationData cannot be empty
                if (requireKeyInfo && isEmpty)
                    throw LogReadException(LogMessages.IDX11127);

                // @Address - optional
                value = reader.GetAttribute(Saml2Constants.Attributes.Address);
                if (!string.IsNullOrEmpty(value))
                {
                    confirmationData.Address = value;
                }

                // @InResponseTo - optional
                value = reader.GetAttribute(Saml2Constants.Attributes.InResponseTo);
                if (!string.IsNullOrEmpty(value))
                {
                    confirmationData.InResponseTo = new Saml2Id(value);
                }

                // @NotBefore - optional
                value = reader.GetAttribute(Saml2Constants.Attributes.NotBefore);
                if (!string.IsNullOrEmpty(value))
                {
                    confirmationData.NotBefore = XmlConvert.ToDateTime(value, Saml2Constants.AcceptedDateTimeFormats);
                }

                // @NotOnOrAfter - optional
                value = reader.GetAttribute(Saml2Constants.Attributes.NotOnOrAfter);
                if (!string.IsNullOrEmpty(value))
                {
                    confirmationData.NotOnOrAfter = XmlConvert.ToDateTime(value, Saml2Constants.AcceptedDateTimeFormats);
                }

                // @Recipient - optional
                value = reader.GetAttribute(Saml2Constants.Attributes.Recipient);
                if (!string.IsNullOrEmpty(value))
                {
                    if (!UriUtil.CanCreateValidUri(value, UriKind.Absolute))
                        throw LogReadException(LogMessages.IDX11107, Saml2Constants.Elements.SubjectConfirmationData, Saml2Constants.Attributes.Recipient, reader.LocalName);

                    confirmationData.Recipient = new Uri(value);
                }

                // Contents
                reader.Read();

                if (!isEmpty)
                {
                    // <ds:KeyInfo> 0-OO OR 1-OO
                    if (requireKeyInfo)
                    {
                        confirmationData.KeyIdentifiers.Add(ReadSubjectKeyInfo(reader));
                    }

                    while (reader.IsStartElement(XmlSignatureConstants.Elements.KeyInfo, XmlSignatureConstants.Namespace))
                    {
                        confirmationData.KeyIdentifiers.Add(ReadSubjectKeyInfo(reader));
                    }

                    // If this isn't KeyInfo restricted, there might be open content here ...
                    if (!requireKeyInfo && XmlNodeType.EndElement != reader.NodeType)
                    {
                        // So throw and tell the user how to handle the open content
                        throw LogReadException(LogMessages.IDX11128, Saml2Constants.Elements.SubjectConfirmationData);
                    }

                    reader.ReadEndElement();
                }

                return confirmationData;
            }
            catch (Exception ex)
            {
                throw LogReadException(LogMessages.IDX11102, ex, Saml2Constants.Elements.SubjectConfirmationData);
            }
        }

        /// <summary>
        /// Writes the &lt;saml:AudienceRestriction> element.
        /// </summary>
        /// <param name="writer">A <see cref="XmlWriter"/> to serialize the <see cref="Saml2AudienceRestriction"/>.</param>
        /// <param name="data">The <see cref="Saml2AudienceRestriction"/> to serialize.</param>
        /// <summary>
        /// This handles the construct used in &lt;Subject> and &lt;SubjectConfirmation> for ID:
        /// <choice>
        ///     <element ref="saml:BaseID" />
        ///     <element ref="saml:NameID" />
        ///     <element ref="saml:EncryptedID" />
        /// </choice>
        /// </summary>
        /// <param name="reader">A <see cref="XmlReader"/> reader positioned at a <see cref="Saml2NameIdentifier"/> element.</param>
        /// <param name="parentElement">The parent element this SubjectID is part of.</param>
        /// <returns>A <see cref="Saml2NameIdentifier"/> constructed from the XML.</returns>
        public virtual Saml2NameIdentifier ReadSubjectId(XmlReader reader, string parentElement)
        {
            // <NameID>, <EncryptedID>, <BaseID>
            if (reader.IsStartElement(Saml2Constants.Elements.NameID, Saml2Constants.Namespace))
            {
                return ReadNameId(reader);
            }
            else if (reader.IsStartElement(Saml2Constants.Elements.EncryptedID, Saml2Constants.Namespace))
            {
                return ReadEncryptedId(reader);
            }
            else if (reader.IsStartElement(Saml2Constants.Elements.BaseID, Saml2Constants.Namespace))
            {
                // Since BaseID is an abstract type, we have to switch off the xsi:type declaration
                XmlQualifiedName declaredType = XmlUtil.GetXsiType(reader);

                // No declaration, or declaring that this is just a "BaseID", is invalid since
                // statement is abstract
                if (null == declaredType
                    || XmlUtil.EqualsQName(declaredType, Saml2Constants.Types.BaseIDAbstractType, Saml2Constants.Namespace))
                    throw LogReadException(LogMessages.IDX11103, typeof(Saml2NameIdentifier));

                // If it's NameID we can handle it
                if (XmlUtil.EqualsQName(declaredType, Saml2Constants.Types.NameIDType, Saml2Constants.Namespace))
                {
                    return ReadNameIdType(reader);
                }
                else
                {
                    // Instruct the user to override to handle custom <BaseID>
                    throw LogReadException(LogMessages.IDX11103, typeof(Saml2NameIdentifier));
                }
            }

            return null;
        }

        /// <summary>
        /// Deserializes the SAML Subject KeyInfo.
        /// </summary>
        /// <param name="reader">XmlReader positioned at a ds:KeyInfo element.</param>
        /// <returns>A <see cref="SecurityKeyIdentifier"/> instance.</returns>
        /// <exception cref="ArgumentNullException">Input parameter 'reader' is null.</exception>
        public virtual SecurityKeyIdentifier ReadSubjectKeyInfo(XmlReader reader)
        {
            // TODO - SecurityKey read / write
            if (null == reader)
                throw LogHelper.LogArgumentNullException(nameof(reader));

            reader.Skip();

            return null;
        }

        /// <summary>
        /// Reads the &lt;saml:SubjectLocality> element.
        /// </summary>
        /// <param name="reader">A <see cref="XmlReader"/> positioned at a <see cref="Saml2SubjectLocality"/> element.</param>
        /// <returns>An instance of <see cref="Saml2SubjectLocality"/> .</returns>
        public virtual Saml2SubjectLocality ReadSubjectLocality(XmlReader reader)
        {
            CheckReaderOnEntry(reader, Saml2Constants.Elements.SubjectLocality, Saml2Constants.Namespace);
            try
            {
                Saml2SubjectLocality subjectLocality = new Saml2SubjectLocality();
                bool isEmpty = reader.IsEmptyElement;

                // @attributes

                // @xsi:type
                XmlUtil.ValidateXsiType(reader, Saml2Constants.Types.SubjectLocalityType, Saml2Constants.Namespace);

                // @Address - optional
                subjectLocality.Address = reader.GetAttribute(Saml2Constants.Attributes.Address);

                // @DNSName - optional
                subjectLocality.DnsName = reader.GetAttribute(Saml2Constants.Attributes.DNSName);

                // Empty content
                reader.Read();
                if (!isEmpty)
                {
                    reader.ReadEndElement();
                }

                return subjectLocality;
            }
            catch (Exception ex)
            {
                throw LogReadException(LogMessages.IDX11102, ex, Saml2Constants.Elements.SubjectLocality);
            }
        }

        /// <summary>
        /// Writes the &lt;saml:Action> element.
        /// </summary>
        /// <param name="writer">A <see cref="XmlWriter"/> to serialize the <see cref="Saml2Action"/>.</param>
        /// <param name="action">The <see cref="Saml2Action"/> to serialize.</param>
        public virtual void WriteAction(XmlWriter writer, Saml2Action action)
        {
            if (writer == null)
                throw LogHelper.LogArgumentNullException(nameof(writer));

            if (action == null)
                throw LogHelper.LogArgumentNullException(nameof(action));

            if (null == action.Namespace)
                throw LogHelper.LogArgumentNullException(nameof(action.Namespace));

            if (string.IsNullOrEmpty(action.Namespace.ToString()))
                throw LogHelper.LogArgumentNullException("action.Namespace");

            // <Action>
            writer.WriteStartElement(Saml2Constants.Elements.Action, Saml2Constants.Namespace);

            // @Namespace - required
            writer.WriteAttributeString(Saml2Constants.Attributes.Namespace, action.Namespace.AbsoluteUri);

            // String content
            writer.WriteString(action.Value);

            // </Action>
            writer.WriteEndElement();
        }

        /// <summary>
        /// Writes the &lt;saml:Advice> element.
        /// </summary>
        /// <param name="writer">A <see cref="XmlWriter"/> to serialize the <see cref="Saml2Advice"/>.</param>
        /// <param name="advice">The <see cref="Saml2Advice"/> to serialize.</param>
        public virtual void WriteAdvice(XmlWriter writer, Saml2Advice advice)
        {
            if (null == writer)
                throw LogHelper.LogArgumentNullException(nameof(writer));

            if (null == advice)
                throw LogHelper.LogArgumentNullException(nameof(advice));

            // <Advice>
            writer.WriteStartElement(Saml2Constants.Elements.Advice, Saml2Constants.Namespace);

            // <AssertionIDRef> 0-OO
            foreach (Saml2Id id in advice.AssertionIdReferences)
            {
                writer.WriteElementString(Saml2Constants.Elements.AssertionIDRef, Saml2Constants.Namespace, id.Value);
            }

            // <AssertionURIRef> 0-OO
            foreach (Uri uri in advice.AssertionUriReferences)
            {
                writer.WriteElementString(Saml2Constants.Elements.AssertionURIRef, Saml2Constants.Namespace, uri.AbsoluteUri);
            }

            // <Assertion> 0-OO
            foreach (Saml2Assertion assertion in advice.Assertions)
            {
                WriteAssertion(writer, assertion);
            }

            // </Advice>
            writer.WriteEndElement();
        }

        /// <summary>
        /// Serializes the provided SamlAssertion to the XmlWriter.
        /// </summary>
        /// <param name="writer">A <see cref="XmlWriter"/> to serialize the <see cref="Saml2Assertion"/>.</param>
        /// <param name="assertion">The <see cref="Saml2Assertion"/> to serialize.</param>
        /// <exception cref="ArgumentNullException">The <paramref name="writer"/> or <paramref name="assertion"/> parameters are null.</exception>
        /// <exception cref="InvalidOperationException"> The <paramref name="assertion"/>  has both <see cref="EncryptingCredentials"/> and <see cref="ReceivedEncryptingCredentials"/> properties null.</exception>
        /// <exception cref="InvalidOperationException">The <paramref name="assertion"/> must have a <see cref="Saml2Subject"/> if no <see cref="Saml2Statement"/> are present.</exception>
        /// <exception cref="InvalidOperationException">The SAML2 authentication, attribute, and authorization decision <see cref="Saml2Statement"/> require a <see cref="Saml2Subject"/>.</exception>
        /// <exception cref="CryptographicException">Token encrypting credentials must have a Symmetric Key specified.</exception>
        public virtual void WriteAssertion(XmlWriter writer, Saml2Assertion assertion)
        {
            if (null == writer)
                throw LogHelper.LogArgumentNullException(nameof(writer));

            if (null == assertion)
                throw LogHelper.LogArgumentNullException(nameof(assertion));

            XmlWriter originalWriter = writer;
            MemoryStream plaintextStream = null;
            XmlDictionaryWriter plaintextWriter = null;
            if ((null != assertion.EncryptingCredentials))
            {
                plaintextStream = new MemoryStream();
                writer = plaintextWriter = XmlDictionaryWriter.CreateTextWriter(plaintextStream, Encoding.UTF8, false);
            }

            // If we've saved off the token stream, re-emit it.
            if (assertion.CanWriteSourceData)
            {
                assertion.WriteSourceData(writer);
            }
            else
            {
                // Wrap the writer if necessary for a signature
                // We do not dispose this writer, since as a delegating writer it would
                // dispose the inner writer, which we don't properly own.
                EnvelopedSignatureWriter signatureWriter = null;
                if (null != assertion.SigningCredentials)
                {
                    writer = signatureWriter = new EnvelopedSignatureWriter(writer, assertion.SigningCredentials, assertion.Id.Value);
                }

                if (null == assertion.Subject)
                {
                    // An assertion with no statements MUST contain a <Subject> element. [Saml2Core, line 585]
                    if (assertion.Statements == null || 0 == assertion.Statements.Count)
                    {
                        throw LogHelper.LogExceptionMessage(new Saml2SecurityTokenException("no subject and no statements, not allowed"));
                    }

                    // Furthermore, the built-in statement types all require the presence of a subject.
                    // [Saml2Core, lines 1050, 1168, 1280]
                    foreach (Saml2Statement statement in assertion.Statements)
                    {
                        if (statement is Saml2AuthenticationStatement
                            || statement is Saml2AttributeStatement
                            || statement is Saml2AuthorizationDecisionStatement)
                        {
                            throw LogHelper.LogExceptionMessage(new Saml2SecurityTokenException("unknown statement type"));
                        }
                    }
                }

                // <Assertion>
                writer.WriteStartElement(Saml2Constants.Elements.Assertion, Saml2Constants.Namespace);

                // @ID - required
                writer.WriteAttributeString(Saml2Constants.Attributes.ID, assertion.Id.Value);

                // @IssueInstant - required
                writer.WriteAttributeString(Saml2Constants.Attributes.IssueInstant, XmlConvert.ToString(assertion.IssueInstant.ToUniversalTime(), Saml2Constants.GeneratedDateTimeFormat));

                // @Version - required
                writer.WriteAttributeString(Saml2Constants.Attributes.Version, assertion.Version);

                // <Issuer> 1
                WriteIssuer(writer, assertion.Issuer);

                // <ds:Signature> 0-1
                if (null != signatureWriter)
                    signatureWriter.WriteSignature();

                // <Subject> 0-1
                if (null != assertion.Subject)
                    WriteSubject(writer, assertion.Subject);

                // <Conditions> 0-1
                if (null != assertion.Conditions)
                    WriteConditions(writer, assertion.Conditions);

                // <Advice> 0-1
                if (null != assertion.Advice)
                    WriteAdvice(writer, assertion.Advice);

                // <Statement|AuthnStatement|AuthzDecisionStatement|AttributeStatement>, 0-OO
                foreach (Saml2Statement statement in assertion.Statements)
                    WriteStatement(writer, statement);

                writer.WriteEndElement();
            }

            // Finish off the encryption
            if (null != plaintextWriter)
            {
                // TODO - use CryptoFactory to encrypt
                //((IDisposable)plaintextWriter).Dispose();
                //plaintextWriter = null;

                //EncryptedDataElement encryptedData = new EncryptedDataElement();
                //encryptedData.Type = XmlEncryptionStrings.EncryptedDataTypes.Element;
                //encryptedData.Algorithm = assertion.EncryptingCredentials.Algorithm;
                //encryptedData.KeyIdentifier = assertion.EncryptingCredentials.SecurityKeyIdentifier;

                //// Get the encryption key, which must be symmetric
                //SymmetricSecurityKey encryptingKey = assertion.EncryptingCredentials.SecurityKey as SymmetricSecurityKey;
                //if (encryptingKey == null)
                //{
                //    throw LogHelper.LogExceptionMessage(new CryptographicException(SR.GetString(SR.ID3064)));
                //}

                //// Do the actual encryption
                //SymmetricAlgorithm symmetricAlgorithm = encryptingKey.GetSymmetricAlgorithm(assertion.EncryptingCredentials.Algorithm);
                //encryptedData.Encrypt(symmetricAlgorithm, plaintextStream.GetBuffer(), 0, (int)plaintextStream.Length);
                //((IDisposable)plaintextStream).Dispose();

                //originalWriter.WriteStartElement(Saml2Constants.Elements.EncryptedAssertion, Saml2Constants.Namespace);
                //encryptedData.WriteXml(originalWriter, this.KeyInfoSerializer);
                //foreach (EncryptedKeyIdentifierClause clause in assertion.ExternalEncryptedKeys)
                //{
                //    this.KeyInfoSerializer.WriteKeyIdentifierClause(originalWriter, clause);
                //}

                //originalWriter.WriteEndElement();
            }
        }

        /// <summary>
        /// Writes the &lt;saml:Attribute> element.
        /// </summary>
        /// <param name="writer">A <see cref="XmlWriter"/> to serialize the <see cref="Saml2Attribute"/>.</param>
        /// <param name="attribute">The <see cref="Saml2Attribute"/> to serialize.</param>
        public virtual void WriteAttribute(XmlWriter writer, Saml2Attribute attribute)
        {
            if (null == writer)
            {
                throw LogHelper.LogArgumentNullException(nameof(writer));
            }

            if (null == attribute)
            {
                throw LogHelper.LogArgumentNullException(nameof(attribute));
            }

            // <Attribute>
            writer.WriteStartElement(Saml2Constants.Elements.Attribute, Saml2Constants.Namespace);

            // @Name - required
            writer.WriteAttributeString(Saml2Constants.Attributes.Name, attribute.Name);

            // @NameFormat - optional
            if (null != attribute.NameFormat)
            {
                writer.WriteAttributeString(Saml2Constants.Attributes.NameFormat, attribute.NameFormat.AbsoluteUri);
            }

            // @FriendlyName - optional
            if (null != attribute.FriendlyName)
            {
                writer.WriteAttributeString(Saml2Constants.Attributes.FriendlyName, attribute.FriendlyName);
            }

            // @OriginalIssuer - optional
            if (null != attribute.OriginalIssuer)
                writer.WriteAttributeString(Saml2Constants.Attributes.OriginalIssuer, attribute.OriginalIssuer);

            string xsiTypePrefix = null;
            string xsiTypeSuffix = null;
            if (!StringComparer.Ordinal.Equals(attribute.AttributeValueXsiType, ClaimValueTypes.String))
            {
                // ClaimValueTypes are URIs of the form prefix#suffix, while xsi:type should be a QName.
                // Hence, the tokens-to-claims spec requires that ClaimValueTypes be serialized as xmlns:tn="prefix" xsi:type="tn:suffix"
                int indexOfHash = attribute.AttributeValueXsiType.IndexOf('#');
                xsiTypePrefix = attribute.AttributeValueXsiType.Substring(0, indexOfHash);
                xsiTypeSuffix = attribute.AttributeValueXsiType.Substring(indexOfHash + 1);
            }

            // <AttributeValue> 0-OO (nillable)
            foreach (string value in attribute.Values)
            {
                writer.WriteStartElement(Saml2Constants.Elements.AttributeValue, Saml2Constants.Namespace);

                if (null == value)
                {
                    writer.WriteAttributeString("nil", XmlSchema.InstanceNamespace, XmlConvert.ToString(true));
                }
                else if (value.Length > 0)
                {
                    if ((xsiTypePrefix != null) && (xsiTypeSuffix != null))
                    {
                        writer.WriteAttributeString("xmlns", Saml2Constants.ClaimValueTypeSerializationPrefix, null, xsiTypePrefix);
                        writer.WriteAttributeString("type", XmlSchema.InstanceNamespace, String.Concat(Saml2Constants.ClaimValueTypeSerializationPrefixWithColon, xsiTypeSuffix));
                    }

                    WriteAttributeValue(writer, value, attribute);
                }

                writer.WriteEndElement();
            }

            // </Attribute>
            writer.WriteEndElement();
        }

        /// <summary>
        /// Writes the &lt;saml:AttributeStatement> element.
        /// </summary>
        /// <param name="writer">A <see cref="XmlWriter"/> to serialize the <see cref="Saml2AttributeStatement"/>.</param>
        /// <param name="attributeStatement">The <see cref="Saml2AttributeStatement"/> to serialize.</param>
        public virtual void WriteAttributeStatement(XmlWriter writer, Saml2AttributeStatement attributeStatement)
        {
            if (null == writer)
                throw LogHelper.LogArgumentNullException(nameof(writer));


            if (null == attributeStatement)
                throw LogHelper.LogArgumentNullException(nameof(attributeStatement));

            if (attributeStatement.Attributes == null || 0 == attributeStatement.Attributes.Count)
                throw LogWriteException(LogMessages.IDX11129);

            // <AttributeStatement>
            writer.WriteStartElement(Saml2Constants.Elements.AttributeStatement, Saml2Constants.Namespace);

            // <Attribute> 1-OO
            foreach (Saml2Attribute attribute in attributeStatement.Attributes)
                WriteAttribute(writer, attribute);

            // </AttributeStatement>
            writer.WriteEndElement();
        }

        /// <summary>
        /// Writes the saml:Attribute value.
        /// </summary>
        /// <param name="writer">A <see cref="XmlWriter"/> to serialize the <see cref="Saml2Attribute"/>.</param>
        /// <param name="value">The value of the attribute being serialized.</param>
        /// <param name="attribute">The <see cref="Saml2Attribute"/> to serialize.</param>
        /// <remarks>By default the method writes the value as a string.</remarks>
        /// <exception cref="ArgumentNullException">The input parameter 'writer' is null.</exception>
        public virtual void WriteAttributeValue(XmlWriter writer, string value, Saml2Attribute attribute)
        {
            if (writer == null)
            {
                throw LogHelper.LogArgumentNullException(nameof(writer));
            }

            writer.WriteString(value);
        }

        /// <summary>
        /// Writes the &lt;saml:AudienceRestriction> element.
        /// </summary>
        /// <param name="writer">A <see cref="XmlWriter"/> to serialize the <see cref="Saml2AudienceRestriction"/>.</param>
        /// <param name="audienceRestriction">The <see cref="Saml2AudienceRestriction"/> to serialize.</param>
        public virtual void WriteAudienceRestriction(XmlWriter writer, Saml2AudienceRestriction audienceRestriction)
        {
            if (null == writer)
                throw LogHelper.LogArgumentNullException(nameof(writer));

            if (null == audienceRestriction)
                throw LogHelper.LogArgumentNullException(nameof(audienceRestriction));

            // Schema requires at least one audience.
            if (audienceRestriction.Audiences == null || 0 == audienceRestriction.Audiences.Count)
                throw LogWriteException(LogMessages.IDX11130);

            // <AudienceRestriction>
            writer.WriteStartElement(Saml2Constants.Elements.AudienceRestriction, Saml2Constants.Namespace);

            // <Audience> - 1-OO
            foreach (string audience in audienceRestriction.Audiences)
                writer.WriteElementString(Saml2Constants.Elements.Audience, Saml2Constants.Namespace, audience);

            // </AudienceRestriction>
            writer.WriteEndElement();
        }

        /// <summary>
        /// Writes the &lt;saml:AuthnContext> element.
        /// </summary>
        /// <param name="writer">A <see cref="XmlWriter"/> to serialize the <see cref="Saml2AuthenticationContext"/>.</param>
        /// <param name="authenticationContext">The <see cref="Saml2AuthenticationContext"/> to serialize.</param>
        public virtual void WriteAuthenticationContext(XmlWriter writer, Saml2AuthenticationContext authenticationContext)
        {
            if (null == writer)
                throw LogHelper.LogArgumentNullException(nameof(writer));

            if (null == authenticationContext)
                throw LogHelper.LogArgumentNullException(nameof(authenticationContext));

            // One of ClassRef and DeclRef must be present.
            if (authenticationContext.ClassReference == null && authenticationContext.DeclarationReference == null)
                throw LogWriteException(LogMessages.IDX11149);

            // <AuthnContext>
            writer.WriteStartElement(Saml2Constants.Elements.AuthnContext, Saml2Constants.Namespace);

            // <AuthnContextClassReference> 0-1
            if (authenticationContext.ClassReference != null)
                writer.WriteElementString(Saml2Constants.Elements.AuthnContextClassRef, Saml2Constants.Namespace, authenticationContext.ClassReference.AbsoluteUri);

            // <AuthnContextDeclRef> 0-1
            if (authenticationContext.DeclarationReference != null)
                writer.WriteElementString(Saml2Constants.Elements.AuthnContextDeclRef, Saml2Constants.Namespace, authenticationContext.DeclarationReference.AbsoluteUri);

            // <AuthenticatingAuthority> 0-OO
            foreach (var authority in authenticationContext.AuthenticatingAuthorities)
                writer.WriteElementString(Saml2Constants.Elements.AuthenticatingAuthority, Saml2Constants.Namespace, authority.AbsoluteUri);

            // </AuthnContext>
            writer.WriteEndElement();
        }

        /// <summary>
        /// Writes the &lt;saml:AuthnStatement> element.
        /// </summary>
        /// <param name="writer">A <see cref="XmlWriter"/> to serialize the <see cref="Saml2AuthenticationStatement"/>.</param>
        /// <param name="data">The <see cref="Saml2AuthenticationStatement"/> to serialize.</param>
        public virtual void WriteAuthenticationStatement(XmlWriter writer, Saml2AuthenticationStatement data)
        {
            if (null == writer)
                throw LogHelper.LogArgumentNullException(nameof(writer));

            if (null == data)
                throw LogHelper.LogArgumentNullException(nameof(data));

            // <AuthnStatement>
            writer.WriteStartElement(Saml2Constants.Elements.AuthnStatement, Saml2Constants.Namespace);

            // @AuthnInstant - required
            writer.WriteAttributeString(Saml2Constants.Attributes.AuthnInstant, XmlConvert.ToString(data.AuthenticationInstant.ToUniversalTime(), Saml2Constants.GeneratedDateTimeFormat));

            // @SessionIndex - optional
            if (null != data.SessionIndex)
            {
                writer.WriteAttributeString(Saml2Constants.Attributes.SessionIndex, data.SessionIndex);
            }

            // @SessionNotOnOrAfter - optional
            if (null != data.SessionNotOnOrAfter)
            {
                writer.WriteAttributeString(Saml2Constants.Attributes.SessionNotOnOrAfter, XmlConvert.ToString(data.SessionNotOnOrAfter.Value.ToUniversalTime(), Saml2Constants.GeneratedDateTimeFormat));
            }

            // <SubjectLocality> 0-1
            if (null != data.SubjectLocality)
                WriteSubjectLocality(writer, data.SubjectLocality);

            // <AuthnContext> 1
            WriteAuthenticationContext(writer, data.AuthenticationContext);

            // </AuthnStatement>
            writer.WriteEndElement();
        }

        /// <summary>
        /// Writes the &lt;saml:AuthzDecisionStatement> element.
        /// </summary>
        /// <param name="writer">A <see cref="XmlWriter"/> to serialize the <see cref="Saml2AuthorizationDecisionStatement"/>.</param>
        /// <param name="data">The <see cref="Saml2AuthorizationDecisionStatement"/> to serialize.</param>
        public virtual void WriteAuthorizationDecisionStatement(XmlWriter writer, Saml2AuthorizationDecisionStatement data)
        {
            if (null == writer)
            {
                throw LogHelper.LogArgumentNullException(nameof(writer));
            }

            if (null == data)
            {
                throw LogHelper.LogArgumentNullException(nameof(data));
            }

            if (0 == data.Actions.Count)
            {
                throw LogHelper.LogExceptionMessage(
                    new Saml2SecurityTokenException("no actions specified ID4122"));
            }

            // <AuthzDecisionStatement>
            writer.WriteStartElement(Saml2Constants.Elements.AuthzDecisionStatement, Saml2Constants.Namespace);

            // @Decision - required
            writer.WriteAttributeString(Saml2Constants.Attributes.Decision, data.Decision.ToString());

            // @Resource - required
            writer.WriteAttributeString(Saml2Constants.Attributes.Resource, data.Resource.Equals(Saml2AuthorizationDecisionStatement.EmptyResource) ? data.Resource.ToString() : data.Resource.AbsoluteUri);

            // @Action 1-OO
            foreach (Saml2Action action in data.Actions)
                WriteAction(writer, action);

            // Evidence 0-1
            if (null != data.Evidence)
                WriteEvidence(writer, data.Evidence);

            // </AuthzDecisionStatement>
            writer.WriteEndElement();
        }

        /// <summary>
        /// Writes the &lt;saml:Conditions> element.
        /// </summary>
        /// <param name="writer">A <see cref="XmlWriter"/> to serialize the <see cref="Saml2Conditions"/>.</param>
        /// <param name="data">The <see cref="Saml2Conditions"/> to serialize.</param>
        public virtual void WriteConditions(XmlWriter writer, Saml2Conditions data)
        {
            if (null == writer)
                throw LogHelper.LogArgumentNullException(nameof(writer));

            if (null == data)
                throw LogHelper.LogArgumentNullException(nameof(data));

            // <Conditions>
            writer.WriteStartElement(Saml2Constants.Elements.Conditions, Saml2Constants.Namespace);

            // @NotBefore - optional
            if (null != data.NotBefore)
                writer.WriteAttributeString(Saml2Constants.Attributes.NotBefore, XmlConvert.ToString(data.NotBefore.Value.ToUniversalTime(), Saml2Constants.GeneratedDateTimeFormat));


            // @NotOnOrAfter - optional
            if (null != data.NotOnOrAfter)
                writer.WriteAttributeString(Saml2Constants.Attributes.NotOnOrAfter, XmlConvert.ToString(data.NotOnOrAfter.Value.ToUniversalTime(), Saml2Constants.GeneratedDateTimeFormat));

            // <AudienceRestriction> 0-OO
            foreach (Saml2AudienceRestriction audienceRestriction in data.AudienceRestrictions)
                WriteAudienceRestriction(writer, audienceRestriction);

            // <OneTimeUse> - limited to one in SAML spec
            if (data.OneTimeUse)
            {
                writer.WriteStartElement(Saml2Constants.Elements.OneTimeUse, Saml2Constants.Namespace);
                writer.WriteEndElement();
            }

            // <ProxyRestriction> - limited to one in SAML spec
            if (null != data.ProxyRestriction)
                WriteProxyRestriction(writer, data.ProxyRestriction);

            // </Conditions>
            writer.WriteEndElement();
        }

        /// <summary>
        /// Writes the &lt;saml:Evidence> element.
        /// </summary>
        /// <param name="writer">A <see cref="XmlWriter"/> to serialize the <see cref="Saml2Evidence"/>.</param>
        /// <param name="data">The <see cref="Saml2Evidence"/> to serialize.</param>
        public virtual void WriteEvidence(XmlWriter writer, Saml2Evidence data)
        {
            if (null == writer)
                throw LogHelper.LogArgumentNullException(nameof(writer));

            if (null == data)
                throw LogHelper.LogArgumentNullException(nameof(data));

            if ((data.AssertionIdReferences == null || 0 == data.AssertionIdReferences.Count)
               && (data.Assertions == null || 0 == data.Assertions.Count)
               && (data.AssertionUriReferences == null || 0 == data.AssertionUriReferences.Count))
                throw LogWriteException(LogMessages.IDX11122);

            // <Evidence>
            writer.WriteStartElement(Saml2Constants.Elements.Evidence, Saml2Constants.Namespace);

            // <AssertionIDRef> 0-OO
            foreach (Saml2Id id in data.AssertionIdReferences)
                writer.WriteElementString(Saml2Constants.Elements.AssertionIDRef, Saml2Constants.Namespace, id.Value);

            // <AssertionURIRef> 0-OO
            foreach (Uri uri in data.AssertionUriReferences)
                writer.WriteElementString(Saml2Constants.Elements.AssertionURIRef, Saml2Constants.Namespace, uri.AbsoluteUri);

            // <Assertion> 0-OO
            foreach (Saml2Assertion assertion in data.Assertions)
                WriteAssertion(writer, assertion);

            // </Evidence>
            writer.WriteEndElement();
        }

        /// <summary>
        /// Writes the &lt;saml:Issuer> element.
        /// </summary>
        /// <param name="writer">A <see cref="XmlWriter"/> to serialize the <see cref="Saml2NameIdentifier"/>.</param>
        /// <param name="data">The <see cref="Saml2NameIdentifier"/> to serialize.</param>
        public virtual void WriteIssuer(XmlWriter writer, Saml2NameIdentifier data)
        {
            if (null == writer)
                throw LogHelper.LogArgumentNullException(nameof(writer));

            if (null == data)
                throw LogHelper.LogArgumentNullException(nameof(data));

            writer.WriteStartElement(Saml2Constants.Elements.Issuer, Saml2Constants.Namespace);
            WriteNameIdType(writer, data);
            writer.WriteEndElement();
        }

        /// <summary>
        /// Writes the &lt;saml:NameID> element.
        /// </summary>
        /// <param name="writer">A <see cref="XmlWriter"/> to serialize the <see cref="Saml2NameIdentifier"/>.</param>
        /// <param name="nameIdentifier">The <see cref="Saml2NameIdentifier"/> to serialize.</param>
        /// <exception cref="ArgumentNullException">The input parameter 'writer' or 'data' is null.</exception>
        /// <exception cref="CryptographicException">Saml2NameIdentifier encrypting credentials must have a Symmetric Key specified.</exception>
        public virtual void WriteNameId(XmlWriter writer, Saml2NameIdentifier nameIdentifier)
        {
            if (null == writer)
                throw LogHelper.LogArgumentNullException(nameof(writer));

            if (null == nameIdentifier)
                throw LogHelper.LogArgumentNullException(nameof(nameIdentifier));

            // If there are encrypting credentials, then we need to encrypt the name identifier
            if (nameIdentifier.EncryptingCredentials != null)
            {
                EncryptingCredentials encryptingCredentials = nameIdentifier.EncryptingCredentials;

                // TODO - do we need keywrap?
                // Get the encryption key, which must be symmetric
                SymmetricSecurityKey encryptingKey = encryptingCredentials.Key as SymmetricSecurityKey;
                if (encryptingKey == null)
                    throw LogWriteException(LogMessages.IDX11132);

                MemoryStream plaintextStream = null;
                try
                {
                    // Serialize an encrypted name ID
                    plaintextStream = new MemoryStream();

                    using (XmlWriter plaintextWriter = XmlDictionaryWriter.CreateTextWriter(plaintextStream, Encoding.UTF8, false))
                    {
                        plaintextWriter.WriteStartElement(Saml2Constants.Elements.NameID, Saml2Constants.Namespace);
                        WriteNameIdType(plaintextWriter, nameIdentifier);
                        plaintextWriter.WriteEndElement();
                    }

                    EncryptedDataElement encryptedData = new EncryptedDataElement();
                    encryptedData.Type = XmlEncryptionConstants.EncryptedDataTypes.Element;
                    encryptedData.Algorithm = encryptingCredentials.Alg;
                    encryptedData.Key = encryptingCredentials.Key;

                    // TODO - need to provide access to SecurityProvider
                    // Perform encryption
                    //        SymmetricAlgorithm symmetricAlgorithm = encryptingKey.GetSymmetricAlgorithm(encryptingCredentials.Algorithm);
                    //        encryptedData.Encrypt(symmetricAlgorithm, plaintextStream.GetBuffer(), 0, (int)plaintextStream.Length);
                    //        ((IDisposable)plaintextStream).Dispose();

                    //        writer.WriteStartElement(Saml2Constants.Elements.EncryptedID, Saml2Constants.Namespace);
                    //        encryptedData.WriteXml(writer, this.KeyInfoSerializer);

                    //        foreach (EncryptedKeyIdentifierClause clause in nameIdentifier.ExternalEncryptedKeys)
                    //        {
                    //            this.KeyInfoSerializer.WriteKeyIdentifierClause(writer, clause);
                    //        }

                    //        writer.WriteEndElement();
                }
                finally
                {
                    if (plaintextStream != null)
                    {
                        plaintextStream.Dispose();
                        plaintextStream = null;
                    }
                }
                //}
                //else
                //{
                //    writer.WriteStartElement(Saml2Constants.Elements.NameID, Saml2Constants.Namespace);
                //    this.WriteNameIdType(writer, nameIdentifier);
                //    writer.WriteEndElement();
                //}
            }
        }

        /// <summary>
        /// Both &lt;Issuer> and &lt;NameID> are of NameIDType. This method writes
        /// the content of either one of those elements.
        /// </summary>
        /// <param name="writer">A <see cref="XmlWriter"/> to serialize the <see cref="Saml2NameIdentifier"/>.</param>
        /// <param name="data">The <see cref="Saml2NameIdentifier"/> to serialize.</param>
        public virtual void WriteNameIdType(XmlWriter writer, Saml2NameIdentifier data)
        {
            // @Format - optional
            if (null != data.Format)
            {
                writer.WriteAttributeString(Saml2Constants.Attributes.Format, data.Format.AbsoluteUri);
            }

            // @NameQualifier - optional
            if (!string.IsNullOrEmpty(data.NameQualifier))
            {
                writer.WriteAttributeString(Saml2Constants.Attributes.NameQualifier, data.NameQualifier);
            }

            // @SPNameQualifier - optional
            if (!string.IsNullOrEmpty(data.SPNameQualifier))
            {
                writer.WriteAttributeString(Saml2Constants.Attributes.SPNameQualifier, data.SPNameQualifier);
            }

            // @SPProvidedId - optional
            if (!string.IsNullOrEmpty(data.SPProvidedId))
            {
                writer.WriteAttributeString(Saml2Constants.Attributes.SPProvidedID, data.SPProvidedId);
            }

            // Content is string
            writer.WriteString(data.Value);
        }

        /// <summary>
        /// Writes the &lt;saml:ProxyRestriction> element.
        /// </summary>
        /// <param name="writer">A <see cref="XmlWriter"/> to serialize the <see cref="Saml2ProxyRestriction"/>.</param>
        /// <param name="data">The <see cref="Saml2ProxyRestriction"/> to serialize.</param>
        public virtual void WriteProxyRestriction(XmlWriter writer, Saml2ProxyRestriction data)
        {
            if (null == writer)
            {
                throw LogHelper.LogArgumentNullException(nameof(writer));
            }

            if (null == data)
            {
                throw LogHelper.LogArgumentNullException(nameof(data));
            }

            writer.WriteStartElement(Saml2Constants.Elements.ProxyRestricton, Saml2Constants.Namespace);

            // @Count - optional
            if (null != data.Count)
            {
                writer.WriteAttributeString(Saml2Constants.Attributes.Count, XmlConvert.ToString(data.Count.Value));
            }

            // <Audience> - 0-OO
            foreach (Uri uri in data.Audiences)
            {
                writer.WriteElementString(Saml2Constants.Elements.Audience, uri.AbsoluteUri);
            }

            writer.WriteEndElement();
        }

        /// <summary>
        /// Serializes the Signing KeyInfo into the given XmlWriter.
        /// </summary>
        /// <param name="writer">A <see cref="XmlWriter"/> to serialize the <see cref="SecurityKeyIdentifier"/>.</param>
        /// <param name="data">The <see cref="SecurityKeyIdentifier"/> to serialize.</param>
        /// <exception cref="ArgumentNullException">The input parameter 'writer' or 'signingKeyIdentifier' is null.</exception>
        public virtual void WriteSigningKeyInfo(XmlWriter writer, SecurityKeyIdentifier data)
        {
            if (null == writer)
            {
                throw LogHelper.LogArgumentNullException(nameof(writer));
            }

            if (null == data)
            {
                throw LogHelper.LogArgumentNullException(nameof(data));
            }

            // TODO - SecurityKey read / write
        }

        /// <summary>
        /// Writes a Saml2Statement.
        /// </summary>
        /// <remarks>
        /// This method may write a &lt;saml:AttributeStatement>, &lt;saml:AuthnStatement>
        /// or &lt;saml:AuthzDecisionStatement> element. To handle custom Saml2Statement
        /// classes for writing a &lt;saml:Statement> element, override this method.
        /// </remarks>
        /// <param name="writer">A <see cref="XmlWriter"/> to serialize the <see cref="Saml2Statement"/>.</param>
        /// <param name="data">The <see cref="Saml2Statement"/> to serialize.</param>
        public virtual void WriteStatement(XmlWriter writer, Saml2Statement data)
        {
            if (null == writer)
            {
                throw LogHelper.LogArgumentNullException(nameof(writer));
            }

            if (null == data)
            {
                throw LogHelper.LogArgumentNullException(nameof(data));
            }

            Saml2AttributeStatement attributeStatement = data as Saml2AttributeStatement;
            if (null != attributeStatement)
            {
                WriteAttributeStatement(writer, attributeStatement);
                return;
            }

            Saml2AuthenticationStatement authnStatement = data as Saml2AuthenticationStatement;
            if (null != authnStatement)
            {
                WriteAuthenticationStatement(writer, authnStatement);
                return;
            }

            Saml2AuthorizationDecisionStatement authzStatement = data as Saml2AuthorizationDecisionStatement;
            if (null != authzStatement)
            {
                WriteAuthorizationDecisionStatement(writer, authzStatement);
                return;
            }

            throw LogWriteException(LogMessages.IDX11133);
        }

        /// <summary>
        /// Writes the &lt;saml:Subject> element.
        /// </summary>
        /// <param name="writer">A <see cref="XmlWriter"/> to serialize the <see cref="Saml2Subject"/>.</param>
        /// <param name="data">The <see cref="Saml2Subject"/> to serialize.</param>
        public virtual void WriteSubject(XmlWriter writer, Saml2Subject data)
        {
            if (null == writer)
            {
                throw LogHelper.LogArgumentNullException(nameof(writer));
            }

            if (null == data)
            {
                throw LogHelper.LogArgumentNullException(nameof(data));
            }

            // If there's no ID, there has to be a SubjectConfirmation
            if (null == data.NameId && 0 == data.SubjectConfirmations.Count)
            {
                throw LogHelper.LogExceptionMessage(new Saml2SecurityTokenException("both id and subjectconfirmation cannot be null"));
            }

            // <Subject>
            writer.WriteStartElement(Saml2Constants.Elements.Subject, Saml2Constants.Namespace);

            // no attributes

            // <NameID> 0-1
            if (null != data.NameId)
                WriteNameId(writer, data.NameId);

            // <SubjectConfirmation> 0-OO
            foreach (Saml2SubjectConfirmation subjectConfirmation in data.SubjectConfirmations)
                WriteSubjectConfirmation(writer, subjectConfirmation);

            // </Subject>
            writer.WriteEndElement();
        }

        /// <summary>
        /// Writes the &lt;saml:SubjectConfirmation> element.
        /// </summary>
        /// <param name="writer">A <see cref="XmlWriter"/> to serialize the <see cref="Saml2SubjectConfirmation"/>.</param>
        /// <param name="data">The <see cref="Saml2SubjectConfirmation"/> to serialize.</param>
        public virtual void WriteSubjectConfirmation(XmlWriter writer, Saml2SubjectConfirmation data)
        {
            if (null == writer)
            {
                throw LogHelper.LogArgumentNullException(nameof(writer));
            }

            if (null == data)
            {
                throw LogHelper.LogArgumentNullException(nameof(data));
            }

            if (null == data.Method)
            {
                throw LogHelper.LogArgumentNullException(nameof(data.Method));
            }

            if (string.IsNullOrEmpty(data.Method.ToString()))
            {
                throw LogHelper.LogArgumentNullException("data.Method");
            }

            // <SubjectConfirmation>
            writer.WriteStartElement(Saml2Constants.Elements.SubjectConfirmation, Saml2Constants.Namespace);

            // @Method - required
            writer.WriteAttributeString(Saml2Constants.Attributes.Method, data.Method.AbsoluteUri);

            // <NameID> 0-1
            if (null != data.NameIdentifier)
                WriteNameId(writer, data.NameIdentifier);

            // <SubjectConfirmationData> 0-1
            if (null != data.SubjectConfirmationData)
                WriteSubjectConfirmationData(writer, data.SubjectConfirmationData);

            // </SubjectConfirmation>
            writer.WriteEndElement();
        }

        /// <summary>
        /// Writes the &lt;saml:SubjectConfirmationData> element.
        /// </summary>
        /// <remarks>
        /// When the data.KeyIdentifiers collection is not empty, an xsi:type
        /// attribute will be written specifying saml:KeyInfoConfirmationDataType.
        /// </remarks>
        /// <param name="writer">A <see cref="XmlWriter"/> to serialize the <see cref="Saml2SubjectConfirmationData"/>.</param>
        /// <param name="data">The <see cref="Saml2SubjectConfirmationData"/> to serialize.</param>
        public virtual void WriteSubjectConfirmationData(XmlWriter writer, Saml2SubjectConfirmationData data)
        {
            if (null == writer)
                throw LogHelper.LogArgumentNullException(nameof(writer));

            if (null == data)
                throw LogHelper.LogArgumentNullException(nameof(data));

            // <SubjectConfirmationData>
            writer.WriteStartElement(Saml2Constants.Elements.SubjectConfirmationData, Saml2Constants.Namespace);

            // @attributes

            // @xsi:type
            if (data.KeyIdentifiers != null && data.KeyIdentifiers.Count > 0)
            {
                writer.WriteAttributeString("type", XmlSchema.InstanceNamespace, Saml2Constants.Types.KeyInfoConfirmationDataType);
            }

            // @Address - optional
            if (!string.IsNullOrEmpty(data.Address))
            {
                writer.WriteAttributeString(Saml2Constants.Attributes.Address, data.Address);
            }

            // @InResponseTo - optional
            if (null != data.InResponseTo)
            {
                writer.WriteAttributeString(Saml2Constants.Attributes.InResponseTo, data.InResponseTo.Value);
            }

            // @NotBefore - optional
            if (null != data.NotBefore)
            {
                writer.WriteAttributeString(Saml2Constants.Attributes.NotBefore, XmlConvert.ToString(data.NotBefore.Value.ToUniversalTime(), Saml2Constants.GeneratedDateTimeFormat));
            }

            // @NotOnOrAfter - optional
            if (null != data.NotOnOrAfter)
            {
                writer.WriteAttributeString(Saml2Constants.Attributes.NotOnOrAfter, XmlConvert.ToString(data.NotOnOrAfter.Value.ToUniversalTime(), Saml2Constants.GeneratedDateTimeFormat));
            }

            // @Recipient - optional
            if (null != data.Recipient)
            {
                writer.WriteAttributeString(Saml2Constants.Attributes.Recipient, data.Recipient.OriginalString);
            }

            // Content

            // <ds:KeyInfo> 0-OO
            foreach (SecurityKeyIdentifier keyIdentifier in data.KeyIdentifiers)
                WriteSubjectKeyInfo(writer, keyIdentifier);

            // </SubjectConfirmationData>
            writer.WriteEndElement();
        }

        /// <summary>
        /// Serializes the Subject KeyInfo into the given XmlWriter.
        /// </summary>
        /// <param name="writer">A <see cref="XmlWriter"/> to serialize the <see cref="SecurityKeyIdentifier"/>.</param>
        /// <param name="data">The <see cref="SecurityKeyIdentifier"/> to serialize.</param>
        /// <exception cref="ArgumentNullException">The input parameter 'writer' or 'data' is null.</exception>
        public virtual void WriteSubjectKeyInfo(XmlWriter writer, SecurityKeyIdentifier data)
        {
            if (null == writer)
            {
                throw LogHelper.LogArgumentNullException(nameof(writer));
            }

            if (null == data)
            {
                throw LogHelper.LogArgumentNullException(nameof(data));
            }

            // TODO - SecurityKey read / write
            //this.KeyInfoSerializer.WriteKeyIdentifier(writer, data);
        }

        /// <summary>
        /// Writes the &lt;saml:SubjectLocality> element.
        /// </summary>
        /// <param name="writer">A <see cref="XmlWriter"/> to serialize the <see cref="Saml2SubjectLocality"/>.</param>
        /// <param name="data">The <see cref="Saml2SubjectLocality"/> to serialize.</param>
        public virtual void WriteSubjectLocality(XmlWriter writer, Saml2SubjectLocality data)
        {
            if (null == writer)
            {
                throw LogHelper.LogArgumentNullException(nameof(writer));
            }

            if (null == data)
            {
                throw LogHelper.LogArgumentNullException(nameof(data));
            }

            // <SubjectLocality>
            writer.WriteStartElement(Saml2Constants.Elements.SubjectLocality, Saml2Constants.Namespace);

            // @Address - optional
            if (null != data.Address)
            {
                writer.WriteAttributeString(Saml2Constants.Attributes.Address, data.Address);
            }

            // @DNSName - optional
            if (null != data.DnsName)
            {
                writer.WriteAttributeString(Saml2Constants.Attributes.DNSName, data.DnsName);
            }

            // </SubjectLocality>
            writer.WriteEndElement();
        }

        internal static void ReadEmptyContentElement(XmlReader reader)
        {
            bool isEmpty = reader.IsEmptyElement;
            reader.Read();
            if (!isEmpty)
            {
                reader.ReadEndElement();
            }
        }

        internal static Saml2Id ReadSimpleNCNameElement(XmlReader reader, string name)
        {
            try
            {
                if (reader.IsEmptyElement)
                    throw LogReadException(LogMessages.IDX11104, name);

                XmlUtil.ValidateXsiType(reader, "NCName", XmlSchema.Namespace);

                reader.MoveToElement();
                string value = reader.ReadElementContentAsString();

                return new Saml2Id(value);
            }
            catch (Exception ex)
            {
                throw LogHelper.LogExceptionMessage(
                    new Saml2SecurityTokenReadException(
                        LogHelper.FormatInvariant(LogMessages.IDX11102, typeof(Saml2Id)), ex));
            }
        }

        // allow lax reading of relative URIs in some instances for interop
        internal static Uri ReadSimpleUriElement(XmlReader reader, string element, UriKind kind, bool requireUri)
        {
            try
            {
                if (reader.IsEmptyElement)
                    throw LogReadException(LogMessages.IDX11104, "Uri");

                XmlUtil.ValidateXsiType(reader, "anyURI", XmlSchema.Namespace);
                reader.MoveToElement();
                string value = reader.ReadElementContentAsString();

                if (string.IsNullOrEmpty(value))
                    throw LogReadException(LogMessages.IDX11136, element);

                // TODO - kind can change.
                if (requireUri && !UriUtil.CanCreateValidUri(value, kind))
                    throw LogReadException(LogMessages.IDX11107, element, value);

                return new Uri(value, kind);
            }
            catch (Exception ex)
            {
                throw LogReadException(LogMessages.IDX11102, element, ex);
            }
        }

        internal static Exception LogReadException(string message)
        {
            return LogHelper.LogExceptionMessage(new Saml2SecurityTokenReadException(message));
        }

        internal static Exception LogReadException(string message, Exception ex)
        {
            return LogHelper.LogExceptionMessage(new Saml2SecurityTokenReadException(message, ex));
        }

        internal static Exception LogReadException(string format, params object[] args)
        {
            return LogHelper.LogExceptionMessage(new Saml2SecurityTokenReadException(LogHelper.FormatInvariant(format, args)));
        }

        internal static Exception LogReadException(string format, Exception inner, params object[] args)
        {
            return LogHelper.LogExceptionMessage(new Saml2SecurityTokenReadException(LogHelper.FormatInvariant(format, args), inner));
        }

        internal static Exception LogWriteException(string message)
        {
            return LogHelper.LogExceptionMessage(new Saml2SecurityTokenWriteException(message));
        }

        internal static Exception LogWriteException(string message, Exception ex)
        {
            return LogHelper.LogExceptionMessage(new Saml2SecurityTokenWriteException(message, ex));
        }

        internal static Exception LogWriteException(string format, params object[] args)
        {
            return LogHelper.LogExceptionMessage(new Saml2SecurityTokenWriteException(LogHelper.FormatInvariant(format, args)));
        }

        internal static Exception LogWriteException(string format, Exception inner, params object[] args)
        {
            return LogHelper.LogExceptionMessage(new Saml2SecurityTokenWriteException(LogHelper.FormatInvariant(format, args), inner));
        }

        internal static void CheckReaderOnEntry(XmlReader reader, string element, string ns, bool allowEmptyElement = false )
        {
            if (null == reader)
                throw LogHelper.LogArgumentNullException(nameof(reader));

            reader.MoveToContent();
            if (!allowEmptyElement && reader.IsEmptyElement)
                throw LogReadException(LogMessages.IDX11104, element);

            if (!reader.IsStartElement(element, ns))
                throw LogReadException(LogMessages.IDX11105, element, reader.LocalName);
        }
    }
}
