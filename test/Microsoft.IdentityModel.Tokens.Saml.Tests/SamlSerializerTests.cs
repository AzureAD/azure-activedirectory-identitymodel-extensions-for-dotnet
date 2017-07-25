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
using System.Xml;
using Microsoft.IdentityModel.Tests;
using Microsoft.IdentityModel.Xml;
using Xunit;

namespace Microsoft.IdentityModel.Tokens.Saml.Tests
{
    public class SamlSerializerTests
    {
        #region SamlAction
#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("ReadActionTheoryData")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void ReadAction(SamlTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.ReadAction", theoryData);
            var context = new CompareContext($"{this}.ReadAction, {theoryData.TestId}");
            try
            {
                var reader = XmlUtilities.CreateDictionaryReader(theoryData.ActionTestSet.Xml);
                var action = (theoryData.SamlSerializer as SamlSerializerPublic).ReadActionPublic(reader);
                theoryData.ExpectedException.ProcessNoException();

                IdentityComparer.AreEqual(action, theoryData.ActionTestSet.Action, context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<SamlTheoryData> ReadActionTheoryData
        {
            get
            {
                return new TheoryData<SamlTheoryData>
                {
                    new SamlTheoryData
                    {
                        ActionTestSet = ReferenceXml.SamlActionValueNull,
                        ExpectedException = new ExpectedException(typeof(SamlSecurityTokenReadException), "IDX11112:", typeof(ArgumentNullException)),
                        First = true,
                        SamlSerializer = new SamlSerializerPublic(),
                        TestId = nameof(ReferenceXml.SamlActionValueNull)
                    },
                    new SamlTheoryData
                    {
                        ActionTestSet = ReferenceXml.SamlActionValueEmptyString,
                        ExpectedException = new ExpectedException(typeof(SamlSecurityTokenReadException), "IDX11112:", typeof(ArgumentNullException)),
                        SamlSerializer = new SamlSerializerPublic(),
                        TestId = nameof(ReferenceXml.SamlActionValueEmptyString)
                    },
                    new SamlTheoryData
                    {
                        ActionTestSet = ReferenceXml.SamlActionNamespaceNull,
                        SamlSerializer = new SamlSerializerPublic(),
                        TestId = nameof(ReferenceXml.SamlActionNamespaceNull)
                    },
                    new SamlTheoryData
                    {
                        ActionTestSet = ReferenceXml.SamlActionNamespaceEmptyString,
                        SamlSerializer = new SamlSerializerPublic(),
                        TestId = nameof(ReferenceXml.SamlActionNamespaceEmptyString)
                    },
                    new SamlTheoryData
                    {
                        ActionTestSet = ReferenceXml.SamlActionNamespaceNotAbsoluteUri,
                        ExpectedException = new ExpectedException(typeof(SamlSecurityTokenReadException), "IDX11111:"),
                        SamlSerializer = new SamlSerializerPublic(),
                        TestId = nameof(ReferenceXml.SamlActionNamespaceNotAbsoluteUri)
                    },
                    new SamlTheoryData
                    {
                        ActionTestSet = ReferenceXml.SamlActionValid,
                        SamlSerializer = new SamlSerializerPublic(),
                        TestId = nameof(ReferenceXml.SamlActionValid)
                    }
                };
            }
        }
        #endregion

        #region SamlAdvice
#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("ReadAdviceTheoryData")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void ReadAdvice(SamlTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.ReadAdvice", theoryData);
            var context = new CompareContext($"{this}.ReadAdvice, {theoryData.TestId}");
            try
            {
                var reader = XmlUtilities.CreateDictionaryReader(theoryData.AdviceTestSet.Xml);
                var advice = (theoryData.SamlSerializer as SamlSerializerPublic).ReadAdvicePublic(reader);
                theoryData.ExpectedException.ProcessNoException();

                IdentityComparer.AreEqual(advice, theoryData.AdviceTestSet.Advice, context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<SamlTheoryData> ReadAdviceTheoryData
        {
            get
            {
                return new TheoryData<SamlTheoryData>
                {
                    new SamlTheoryData
                    {
                        AdviceTestSet = ReferenceXml.AdviceNoAssertionIDRefAndAssertion,
                        First = true,
                        SamlSerializer = new SamlSerializerPublic(),
                        TestId = nameof(ReferenceXml.AdviceNoAssertionIDRefAndAssertion)
                    },
                    new SamlTheoryData
                    {
                        AdviceTestSet = ReferenceXml.AdviceWithAssertionIDRef,
                        SamlSerializer = new SamlSerializerPublic(),
                        TestId = nameof(ReferenceXml.AdviceWithAssertionIDRef)
                    },
                    new SamlTheoryData
                    {
                        AdviceTestSet = ReferenceXml.SamlAdviceWithAssertions,
                        SamlSerializer = new SamlSerializerPublic(),
                        TestId = nameof(ReferenceXml.SamlAdviceWithAssertions)
                    },
                    new SamlTheoryData
                    {
                        AdviceTestSet = ReferenceXml.SamlAdviceWithWrongElement,
                        ExpectedException = new ExpectedException(typeof(SamlSecurityTokenReadException), "IDX11126"),
                        SamlSerializer = new SamlSerializerPublic(),
                        TestId = nameof(ReferenceXml.SamlAdviceWithWrongElement)
                    },
                    new SamlTheoryData
                    {
                        AdviceTestSet = ReferenceXml.SamlAdviceWithAssertionIDRefAndAssertions,
                        SamlSerializer = new SamlSerializerPublic(),
                        TestId = nameof(ReferenceXml.SamlAdviceWithAssertionIDRefAndAssertions)
                    }
                };
            }
        }
        #endregion

        #region SamlAssertion
#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("ReadAssertionTheoryData")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void ReadAssertion(SamlTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.ReadAssertion", theoryData);
            var context = new CompareContext($"{this}.ReadAssertion, {theoryData.TestId}");
            try
            {
                var reader = XmlUtilities.CreateDictionaryReader(theoryData.AssertionTestSet.Xml);
                var assertion = (theoryData.SamlSerializer as SamlSerializerPublic).ReadAssertionPublic(reader);
                theoryData.ExpectedException.ProcessNoException();

                IdentityComparer.AreEqual(assertion, theoryData.AssertionTestSet.Assertion, context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<SamlTheoryData> ReadAssertionTheoryData
        {
            get
            {
                return new TheoryData<SamlTheoryData>
                {
                    new SamlTheoryData
                    {
                        AssertionTestSet = ReferenceXml.SamlAssertionMissMajorVersion,
                        ExpectedException = new ExpectedException(typeof(SamlSecurityTokenReadException), "IDX11115"),
                        First = true,
                        SamlSerializer = new SamlSerializerPublic(),
                        TestId = nameof(ReferenceXml.SamlAssertionMissMajorVersion)
                    },
                    new SamlTheoryData
                    {
                        AssertionTestSet = ReferenceXml.SamlAssertionWrongMajorVersion,
                        ExpectedException = new ExpectedException(typeof(SamlSecurityTokenReadException), "IDX11116"),
                        SamlSerializer = new SamlSerializerPublic(),
                        TestId = nameof(ReferenceXml.SamlAssertionWrongMajorVersion)
                    },
                    new SamlTheoryData
                    {
                        AssertionTestSet = ReferenceXml.SamlAssertionMissMinorVersion,
                        ExpectedException = new ExpectedException(typeof(SamlSecurityTokenReadException), "IDX11115"),
                        SamlSerializer = new SamlSerializerPublic(),
                        TestId = nameof(ReferenceXml.SamlAssertionMissMinorVersion)
                    },
                    new SamlTheoryData
                    {
                        AssertionTestSet = ReferenceXml.SamlAssertionWrongMinorVersion,
                        ExpectedException = new ExpectedException(typeof(SamlSecurityTokenReadException), "IDX11117"),
                        SamlSerializer = new SamlSerializerPublic(),
                        TestId = nameof(ReferenceXml.SamlAssertionWrongMinorVersion)
                    },
                    new SamlTheoryData
                    {
                        AssertionTestSet = ReferenceXml.SamlAssertionMissAssertionID,
                        ExpectedException = new ExpectedException(typeof(SamlSecurityTokenReadException), "IDX11115"),
                        SamlSerializer = new SamlSerializerPublic(),
                        TestId = nameof(ReferenceXml.SamlAssertionMissAssertionID)
                    },
                    new SamlTheoryData
                    {
                        AssertionTestSet = ReferenceXml.SamlAssertionWrongAssertionID,
                        ExpectedException = new ExpectedException(typeof(SamlSecurityTokenReadException), "IDX11121"),
                        SamlSerializer = new SamlSerializerPublic(),
                        TestId = nameof(ReferenceXml.SamlAssertionWrongAssertionID)
                    },
                    new SamlTheoryData
                    {
                        AssertionTestSet = ReferenceXml.SamlAssertionMissIssuer,
                        ExpectedException = new ExpectedException(typeof(SamlSecurityTokenReadException), "IDX11115"),
                        SamlSerializer = new SamlSerializerPublic(),
                        TestId = nameof(ReferenceXml.SamlAssertionMissIssuer)
                    },
                    new SamlTheoryData
                    {
                        AssertionTestSet = ReferenceXml.SamlAssertionMissIssuerInstant,
                        ExpectedException = new ExpectedException(typeof(SamlSecurityTokenReadException), "IDX11115"),
                        SamlSerializer = new SamlSerializerPublic(),
                        TestId = nameof(ReferenceXml.SamlAssertionMissIssuerInstant)
                    },
                    new SamlTheoryData
                    {
                        AssertionTestSet = ReferenceXml.SamlAssertionNoCondition,
                        SamlSerializer = new SamlSerializerPublic(),
                        TestId = nameof(ReferenceXml.SamlAssertionNoCondition)
                    },
                    new SamlTheoryData
                    {
                        AssertionTestSet = ReferenceXml.SamlAssertionNoAdvice,
                        SamlSerializer = new SamlSerializerPublic(),
                        TestId = nameof(ReferenceXml.SamlAssertionNoAdvice)
                    },
                    new SamlTheoryData
                    {
                        AssertionTestSet = ReferenceXml.SamlAssertionMissStatement,
                        ExpectedException = new ExpectedException(typeof(SamlSecurityTokenReadException), "IDX11130"),
                        SamlSerializer = new SamlSerializerPublic(),
                        TestId = nameof(ReferenceXml.SamlAssertionMissStatement)
                    },
                    new SamlTheoryData
                    {
                        AssertionTestSet = ReferenceXml.SamlAssertionWrongElementInStatementPlace,
                        ExpectedException = new ExpectedException(typeof(SamlSecurityTokenReadException), "IDX11126"),
                        SamlSerializer = new SamlSerializerPublic(),
                        TestId = nameof(ReferenceXml.SamlAssertionWrongElementInStatementPlace)
                    },
                    new SamlTheoryData
                    {
                        AssertionTestSet = ReferenceXml.SamlAssertionNoSignature,
                        SamlSerializer = new SamlSerializerPublic(),
                        TestId = nameof(ReferenceXml.SamlAssertionNoSignature)
                    },
                    new SamlTheoryData
                    {
                        AssertionTestSet = ReferenceXml.SamlAssertionMultiStatements_SameSubject,
                        SamlSerializer = new SamlSerializerPublic(),
                        TestId = nameof(ReferenceXml.SamlAssertionMultiStatements_SameSubject)
                    },
                    new SamlTheoryData
                    {
                        AssertionTestSet = ReferenceXml.SamlAssertionMultiStatements_DifferentSubject,
                        SamlSerializer = new SamlSerializerPublic(),
                        TestId = nameof(ReferenceXml.SamlAssertionMultiStatements_DifferentSubject)
                    },
                    new SamlTheoryData
                    {
                        AssertionTestSet = ReferenceXml.SamlAssertionMultiStatements_DifferentStatementType,
                        SamlSerializer = new SamlSerializerPublic(),
                        TestId = nameof(ReferenceXml.SamlAssertionMultiStatements_DifferentStatementType)
                    }
                };
            }
        }
        #endregion

        #region SamlAttribute
#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("ReadAttributeTheoryData")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void ReadAttribute(SamlTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.ReadAttribute", theoryData);
            var context = new CompareContext($"{this}.ReadAttribute, {theoryData.TestId}");
            try
            {
                var reader = XmlUtilities.CreateDictionaryReader(theoryData.AttributeTestSet.Xml);
                var attribute = (theoryData.SamlSerializer as SamlSerializerPublic).ReadAttributePublic(reader);
                theoryData.ExpectedException.ProcessNoException();

                IdentityComparer.AreEqual(attribute, theoryData.AttributeTestSet.Attribute, context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<SamlTheoryData> ReadAttributeTheoryData
        {
            get
            {
                return new TheoryData<SamlTheoryData>
                {
                    new SamlTheoryData()
                    {
                        AttributeTestSet = ReferenceXml.SamlAttributeNameNull,
                        ExpectedException = new ExpectedException(typeof(SamlSecurityTokenReadException), "IDX11115:"),
                        First = true,
                        SamlSerializer = new SamlSerializerPublic(),
                        TestId = nameof(ReferenceXml.SamlAttributeNameNull)
                    },
                    new SamlTheoryData()
                    {
                        AttributeTestSet = ReferenceXml.SamlAttributeNameEmptyString,
                        ExpectedException = new ExpectedException(typeof(SamlSecurityTokenReadException), "IDX11115:"),
                        SamlSerializer = new SamlSerializerPublic(),
                        TestId = nameof(ReferenceXml.SamlAttributeNameEmptyString)
                    },
                    new SamlTheoryData()
                    {
                        AttributeTestSet = ReferenceXml.SamlAttributeNamespaceNull,
                        ExpectedException = new ExpectedException(typeof(SamlSecurityTokenReadException), "IDX11115:"),
                        SamlSerializer = new SamlSerializerPublic(),
                        TestId = nameof(ReferenceXml.SamlAttributeNamespaceNull)
                    },
                    new SamlTheoryData()
                    {
                        AttributeTestSet = ReferenceXml.SamlAttributeNamespaceEmptyString,
                        ExpectedException = new ExpectedException(typeof(SamlSecurityTokenReadException), "IDX11115:"),
                        SamlSerializer = new SamlSerializerPublic(),
                        TestId = nameof(ReferenceXml.SamlAttributeNamespaceEmptyString)
                    },
                    new SamlTheoryData()
                    {
                        AttributeTestSet = ReferenceXml.SamlAttributeValueNull,
                        ExpectedException = new ExpectedException(typeof(SamlSecurityTokenReadException), "IDX11132:"),
                        SamlSerializer = new SamlSerializerPublic(),
                        TestId = nameof(ReferenceXml.SamlAttributeValueNull)
                    },
                    new SamlTheoryData()
                    {
                        AttributeTestSet = ReferenceXml.SamlAttributeValueEmptyString,
                        SamlSerializer = new SamlSerializerPublic(),
                        TestId = nameof(ReferenceXml.SamlAttributeValueEmptyString)
                    },
                    new SamlTheoryData()
                    {
                        AttributeTestSet = ReferenceXml.SamlAttributeSingleValue,
                        SamlSerializer = new SamlSerializerPublic(),
                        TestId = nameof(ReferenceXml.SamlAttributeSingleValue)
                    },
                    new SamlTheoryData()
                    {
                        AttributeTestSet = ReferenceXml.SamlAttributeMultiValue,
                        SamlSerializer = new SamlSerializerPublic(),
                        TestId = nameof(ReferenceXml.SamlAttributeMultiValue)
                    }
                };
            }
        }
        #endregion

        #region SamlAttributeStatement
#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("ReadAttributeStatementTheoryData")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void ReadAttributeStatement(SamlTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.ReadAttributeStatement", theoryData);
            var context = new CompareContext($"{this}.ReadAttributeStatement, {theoryData.TestId}");
            try
            {
                var reader = XmlUtilities.CreateDictionaryReader(theoryData.AttributeStatementTestSet.Xml);
                var attributeStatement = (theoryData.SamlSerializer as SamlSerializerPublic).ReadAttributeStatementPublic(reader);
                theoryData.ExpectedException.ProcessNoException();

                IdentityComparer.AreEqual(attributeStatement, theoryData.AttributeStatementTestSet.AttributeStatement, context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<SamlTheoryData> ReadAttributeStatementTheoryData
        {
            get
            {
                return new TheoryData<SamlTheoryData>
                {
                    new SamlTheoryData()
                    {
                        AttributeStatementTestSet = ReferenceXml.SamlAttributeStatementMissSubject,
                        ExpectedException = new ExpectedException(typeof(SamlSecurityTokenReadException), "IDX11112:", typeof(XmlReadException)),
                        First = true,
                        SamlSerializer = new SamlSerializerPublic(),
                        TestId = nameof(ReferenceXml.SamlAttributeStatementMissSubject)
                    },
                    new SamlTheoryData()
                    {
                        AttributeStatementTestSet = ReferenceXml.SamlAttributeStatementMissAttribute,
                        ExpectedException = new ExpectedException(typeof(SamlSecurityTokenReadException), "IDX11131:"),
                        SamlSerializer = new SamlSerializerPublic(),
                        TestId = nameof(ReferenceXml.SamlAttributeStatementMissAttribute)
                    },
                    new SamlTheoryData()
                    {
                        AttributeStatementTestSet = ReferenceXml.SamlAttributeStatementSingleAttribute,
                        SamlSerializer = new SamlSerializerPublic(),
                        TestId = nameof(ReferenceXml.SamlAttributeStatementSingleAttribute)
                    },
                    new SamlTheoryData()
                    {
                        AttributeStatementTestSet = ReferenceXml.SamlAttributeStatementMultiAttributes,
                        SamlSerializer = new SamlSerializerPublic(),
                        TestId = nameof(ReferenceXml.SamlAttributeStatementMultiAttributes)
                    }
                };
            }
        }
        #endregion

        #region SamlAudienceRestrictionCondition
#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("ReadAudienceRestrictionConditionTheoryData")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void ReadAudienceRestrictionCondition(SamlTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.ReadAudienceRestrictionCondition", theoryData);
            var context = new CompareContext($"{this}.ReadAudienceRestrictionCondition, {theoryData.TestId}");
            try
            {
                var reader = XmlUtilities.CreateDictionaryReader(theoryData.AudienceRestrictionConditionTestSet.Xml);
                var audienceRestrictionCondition = (theoryData.SamlSerializer as SamlSerializerPublic).ReadAudienceRestrictionConditionPublic(reader);
                theoryData.ExpectedException.ProcessNoException();

                IdentityComparer.AreEqual(audienceRestrictionCondition, theoryData.AudienceRestrictionConditionTestSet.AudienceRestrictionCondition, context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<SamlTheoryData> ReadAudienceRestrictionConditionTheoryData
        {
            get
            {
                return new TheoryData<SamlTheoryData>
                {
                    new SamlTheoryData
                    {
                        AudienceRestrictionConditionTestSet = ReferenceXml.SamlAudienceRestrictionConditionNoAudience,
                        ExpectedException = new ExpectedException(typeof(SamlSecurityTokenReadException), "IDX11120:"),
                        First = true,
                        SamlSerializer = new SamlSerializerPublic(),
                        TestId = nameof(ReferenceXml.SamlAudienceRestrictionConditionNoAudience)
                    },
                    new SamlTheoryData
                    {
                        AudienceRestrictionConditionTestSet = ReferenceXml.SamlAudienceRestrictionConditionEmptyAudience,
                        ExpectedException = new ExpectedException(typeof(SamlSecurityTokenReadException), "IDX11125:"),
                        SamlSerializer = new SamlSerializerPublic(),
                        TestId = nameof(ReferenceXml.SamlAudienceRestrictionConditionEmptyAudience)
                    },
                    new SamlTheoryData
                    {
                        AudienceRestrictionConditionTestSet = ReferenceXml.SamlAudienceRestrictionConditionInvaidElement,
                        ExpectedException = new ExpectedException(typeof(SamlSecurityTokenReadException), "IDX11134:"),
                        SamlSerializer = new SamlSerializerPublic(),
                        TestId = nameof(ReferenceXml.SamlAudienceRestrictionConditionInvaidElement)
                    },
                    new SamlTheoryData
                    {
                        AudienceRestrictionConditionTestSet = ReferenceXml.SamlAudienceRestrictionConditionSingleAudience,
                        SamlSerializer = new SamlSerializerPublic(),
                        TestId = nameof(ReferenceXml.SamlAudienceRestrictionConditionSingleAudience)
                    },
                    new SamlTheoryData
                    {
                        AudienceRestrictionConditionTestSet = ReferenceXml.SamlAudienceRestrictionConditionMultiAudience,
                        SamlSerializer = new SamlSerializerPublic(),
                        TestId = nameof(ReferenceXml.SamlAudienceRestrictionConditionMultiAudience)
                    }
                };
            }
        }
        #endregion

        #region SamlAuthenticationStatement
#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("ReadAuthenticationStatementTheoryData")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void ReadAuthenticationStatement(SamlTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.ReadAuthenticationStatement", theoryData);
            var context = new CompareContext($"{this}.ReadAuthenticationStatement, {theoryData.TestId}");
            try
            {
                var reader = XmlUtilities.CreateDictionaryReader(theoryData.AuthenticationStatementTestSet.Xml);
                var authenticationStatement = (theoryData.SamlSerializer as SamlSerializerPublic).ReadAuthenticationStatementPublic(reader);
                theoryData.ExpectedException.ProcessNoException();

                IdentityComparer.AreEqual(authenticationStatement, theoryData.AuthenticationStatementTestSet.AuthenticationStatement, context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<SamlTheoryData> ReadAuthenticationStatementTheoryData
        {
            get
            {
                return new TheoryData<SamlTheoryData>
                {
                    new SamlTheoryData
                    {
                        AuthenticationStatementTestSet = ReferenceXml.SamlAuthenticationStatementMissSubject,
                        ExpectedException = new ExpectedException(typeof(SamlSecurityTokenReadException), "IDX11112:", typeof(XmlReadException)),
                        First = true,
                        SamlSerializer = new SamlSerializerPublic(),
                        TestId = nameof(ReferenceXml.SamlAuthenticationStatementMissSubject)
                    },
                    new SamlTheoryData
                    {
                        AuthenticationStatementTestSet = ReferenceXml.SamlAuthenticationStatementMissMethod,
                        ExpectedException = new ExpectedException(typeof(SamlSecurityTokenReadException), "IDX11115:"),
                        SamlSerializer = new SamlSerializerPublic(),
                        TestId = nameof(ReferenceXml.SamlAuthenticationStatementMissMethod)
                    },
                    new SamlTheoryData
                    {
                        AuthenticationStatementTestSet = ReferenceXml.SamlAuthenticationStatementMissInstant,
                        ExpectedException = new ExpectedException(typeof(SamlSecurityTokenReadException), "IDX11115:"),
                        SamlSerializer = new SamlSerializerPublic(),
                        TestId = nameof(ReferenceXml.SamlAuthenticationStatementMissInstant)
                    },
                    new SamlTheoryData
                    {
                        AuthenticationStatementTestSet = ReferenceXml.SamlAuthenticationStatementNoSubjectLocality,
                        SamlSerializer = new SamlSerializerPublic(),
                        TestId = nameof(ReferenceXml.SamlAuthenticationStatementNoSubjectLocality)
                    },
                    new SamlTheoryData
                    {
                        AuthenticationStatementTestSet = ReferenceXml.SamlAuthenticationStatementNoIPAddress,
                        SamlSerializer = new SamlSerializerPublic(),
                        TestId = nameof(ReferenceXml.SamlAuthenticationStatementNoIPAddress)
                    },
                    new SamlTheoryData
                    {
                        AuthenticationStatementTestSet = ReferenceXml.SamlAuthenticationStatementNoDNSAddress,
                        SamlSerializer = new SamlSerializerPublic(),
                        TestId = nameof(ReferenceXml.SamlAuthenticationStatementNoDNSAddress)
                    },
                    new SamlTheoryData
                    {
                        AuthenticationStatementTestSet = ReferenceXml.SamlAuthenticationStatementNoAuthorityBinding,
                        SamlSerializer = new SamlSerializerPublic(),
                        TestId = nameof(ReferenceXml.SamlAuthenticationStatementNoAuthorityBinding)
                    },
                    new SamlTheoryData
                    {
                        AuthenticationStatementTestSet = ReferenceXml.SamlAuthenticationStatementMissAuthorityKind,
                        ExpectedException = new ExpectedException(typeof(SamlSecurityTokenReadException), "IDX11115:"),
                        SamlSerializer = new SamlSerializerPublic(),
                        TestId = nameof(ReferenceXml.SamlAuthenticationStatementMissAuthorityKind)
                    },
                    new SamlTheoryData
                    {
                        AuthenticationStatementTestSet = ReferenceXml.SamlAuthenticationStatementMissLocation,
                        ExpectedException = new ExpectedException(typeof(SamlSecurityTokenReadException), "IDX11513:", typeof(SamlSecurityTokenException)),
                        SamlSerializer = new SamlSerializerPublic(),
                        TestId = nameof(ReferenceXml.SamlAuthenticationStatementMissLocation)
                    },
                    new SamlTheoryData
                    {
                        AuthenticationStatementTestSet = ReferenceXml.SamlAuthenticationStatementMissBinding,
                        ExpectedException = new ExpectedException(typeof(SamlSecurityTokenReadException), "IDX11512:", typeof(SamlSecurityTokenException)),
                        SamlSerializer = new SamlSerializerPublic(),
                        TestId = nameof(ReferenceXml.SamlAuthenticationStatementMissBinding)
                    },
                    new SamlTheoryData
                    {
                        AuthenticationStatementTestSet = ReferenceXml.SamlAuthenticationStatementValid,
                        SamlSerializer = new SamlSerializerPublic(),
                        TestId = nameof(ReferenceXml.SamlAuthenticationStatementValid)
                    },
                    new SamlTheoryData
                    {
                        AuthenticationStatementTestSet = ReferenceXml.SamlAuthenticationStatementMultiBinding,
                        SamlSerializer = new SamlSerializerPublic(),
                        TestId = nameof(ReferenceXml.SamlAuthenticationStatementMultiBinding)
                    }
                };
            }
        }
        #endregion

        #region SamlAuthorizationDecisionStatement
#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("ReadAuthorizationDecisionStatementTheoryData")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void ReadAuthorizationDecisionStatement(SamlTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.ReadAuthorizationDecisionStatement", theoryData);
            var context = new CompareContext($"{this}.ReadAuthorizationDecisionStatement, {theoryData.TestId}");
            try
            {
                var reader = XmlUtilities.CreateDictionaryReader(theoryData.AuthorizationDecisionTestSet.Xml);
                var statement = (theoryData.SamlSerializer as SamlSerializerPublic).ReadAuthorizationDecisionStatementPublic(reader);
                theoryData.ExpectedException.ProcessNoException();

                IdentityComparer.AreEqual(statement, theoryData.AuthorizationDecisionTestSet.AuthorizationDecision, context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<SamlTheoryData> ReadAuthorizationDecisionStatementTheoryData
        {
            get
            {
                return new TheoryData<SamlTheoryData>
                {
                    new SamlTheoryData
                    {
                        AuthorizationDecisionTestSet = ReferenceXml.SamlAuthorizationDecisionMissResource,
                        ExpectedException = new ExpectedException(typeof(SamlSecurityTokenReadException), "IDX11115"),
                        First = true,
                        SamlSerializer = new SamlSerializerPublic(),
                        TestId = nameof(ReferenceXml.SamlAuthorizationDecisionMissResource)
                    },
                    new SamlTheoryData
                    {
                        AuthorizationDecisionTestSet = ReferenceXml.SamlAuthorizationDecisionMissAccessDecision,
                        ExpectedException = new ExpectedException(typeof(SamlSecurityTokenReadException), "IDX11115"),
                        SamlSerializer = new SamlSerializerPublic(),
                        TestId = nameof(ReferenceXml.SamlAuthorizationDecisionMissAccessDecision)
                    },
                    new SamlTheoryData
                    {
                        AuthorizationDecisionTestSet = ReferenceXml.SamlAuthorizationDecisionMissSubject,
                        ExpectedException = new ExpectedException(typeof(SamlSecurityTokenReadException), "IDX11112:", typeof(XmlReadException)),
                        SamlSerializer = new SamlSerializerPublic(),
                        TestId = nameof(ReferenceXml.SamlAuthorizationDecisionMissSubject)
                    },
                    new SamlTheoryData
                    {
                        AuthorizationDecisionTestSet = ReferenceXml.SamlAuthorizationDecisionMissAction,
                        ExpectedException = new ExpectedException(typeof(SamlSecurityTokenReadException), "IDX11102:"),
                        SamlSerializer = new SamlSerializerPublic(),
                        TestId = nameof(ReferenceXml.SamlAuthorizationDecisionMissAction)
                    },
                    new SamlTheoryData
                    {
                        AuthorizationDecisionTestSet = ReferenceXml.SamlAuthorizationDecisionNoEvidence,
                        SamlSerializer = new SamlSerializerPublic(),
                        TestId = nameof(ReferenceXml.SamlAuthorizationDecisionNoEvidence)
                    },
                    new SamlTheoryData
                    {
                        AuthorizationDecisionTestSet = ReferenceXml.SamlAuthorizationDecisionSingleAction,
                        SamlSerializer = new SamlSerializerPublic(),
                        TestId = nameof(ReferenceXml.SamlAuthorizationDecisionSingleAction)
                    },
                    new SamlTheoryData
                    {
                        AuthorizationDecisionTestSet = ReferenceXml.SamlAuthorizationDecisionMultiActions,
                        SamlSerializer = new SamlSerializerPublic(),
                        TestId = nameof(ReferenceXml.SamlAuthorizationDecisionMultiActions)
                    }
                };
            }
        }
        #endregion

        #region SamlConditions
#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("ReadConditionsTheoryData")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void ReadConditions(SamlTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.ReadConditions", theoryData);
            var context = new CompareContext($"{this}.ReadConditions, {theoryData.TestId}");
            try
            {
                var reader = XmlUtilities.CreateDictionaryReader(theoryData.ConditionsTestSet.Xml);
                var conditions = (theoryData.SamlSerializer as SamlSerializerPublic).ReadConditionsPublic(reader);
                theoryData.ExpectedException.ProcessNoException();

                IdentityComparer.AreEqual(conditions, theoryData.ConditionsTestSet.Conditions, context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<SamlTheoryData> ReadConditionsTheoryData
        {
            get
            {
                return new TheoryData<SamlTheoryData>
                {
                    new SamlTheoryData
                    {
                        ConditionsTestSet = ReferenceXml.SamlConditionsNoNbf,
                        First = true,
                        SamlSerializer = new SamlSerializerPublic(),
                        TestId = nameof(ReferenceXml.SamlConditionsNoNbf)
                    },
                    new SamlTheoryData
                    {
                        ConditionsTestSet = ReferenceXml.SamlConditionsNoNotOnOrAfter,
                        SamlSerializer = new SamlSerializerPublic(),
                        TestId = nameof(ReferenceXml.SamlConditionsNoNotOnOrAfter)
                    },
                    new SamlTheoryData
                    {
                        ConditionsTestSet = ReferenceXml.SamlConditionsNoCondition,
                        SamlSerializer = new SamlSerializerPublic(),
                        TestId = nameof(ReferenceXml.SamlConditionsNoCondition)
                    },
                    new SamlTheoryData
                    {
                        ConditionsTestSet = ReferenceXml.SamlConditionsSingleCondition,
                        SamlSerializer = new SamlSerializerPublic(),
                        TestId = nameof(ReferenceXml.SamlConditionsSingleCondition)
                    },
                    new SamlTheoryData
                    {
                        ConditionsTestSet = ReferenceXml.SamlConditionsMultiCondition,
                        SamlSerializer = new SamlSerializerPublic(),
                        TestId = nameof(ReferenceXml.SamlConditionsMultiCondition)
                    }
                };
            }
        }
        #endregion

        #region SamlEvidence
#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("ReadEvidenceTheoryData")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void ReadEvidence(SamlTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.ReadEvidence", theoryData);
            var context = new CompareContext($"{this}.ReadEvidence, {theoryData.TestId}");
            try
            {
                var reader = XmlUtilities.CreateDictionaryReader(theoryData.EvidenceTestSet.Xml);
                var evidence = (theoryData.SamlSerializer as SamlSerializerPublic).ReadEvidencePublic(reader);
                theoryData.ExpectedException.ProcessNoException();

                IdentityComparer.AreEqual(evidence, theoryData.EvidenceTestSet.Evidence, context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<SamlTheoryData> ReadEvidenceTheoryData
        {
            get
            {
                return new TheoryData<SamlTheoryData>
                {
                    new SamlTheoryData
                    {
                        EvidenceTestSet = ReferenceXml.SamlEvidenceMissAssertionIDRefAndAssertion,
                        ExpectedException = new ExpectedException(typeof(SamlSecurityTokenReadException), "IDX11133"),
                        First = true,
                        SamlSerializer = new SamlSerializerPublic(),
                        TestId = nameof(ReferenceXml.SamlEvidenceMissAssertionIDRefAndAssertion)
                    },
                    new SamlTheoryData
                    {
                        EvidenceTestSet = ReferenceXml.SamlEvidenceWithAssertionIDRef,
                        SamlSerializer = new SamlSerializerPublic(),
                        TestId = nameof(ReferenceXml.SamlEvidenceWithAssertionIDRef)
                    },
                    new SamlTheoryData
                    {
                        EvidenceTestSet = ReferenceXml.SamlEvidenceWithAssertions,
                        SamlSerializer = new SamlSerializerPublic(),
                        TestId = nameof(ReferenceXml.SamlEvidenceWithAssertions)
                    },
                    new SamlTheoryData
                    {
                        EvidenceTestSet = ReferenceXml.SamlEvidenceWithWrongElement,
                        ExpectedException = new ExpectedException(typeof(SamlSecurityTokenReadException), "IDX11120"),
                        SamlSerializer = new SamlSerializerPublic(),
                        TestId = nameof(ReferenceXml.SamlEvidenceWithWrongElement)
                    },
                    new SamlTheoryData
                    {
                        EvidenceTestSet = ReferenceXml.SamlEvidenceWithAssertionIDRefAndAssertions,
                        SamlSerializer = new SamlSerializerPublic(),
                        TestId = nameof(ReferenceXml.SamlEvidenceWithAssertionIDRefAndAssertions)
                    }
                };
            }
        }
        #endregion

        #region SamlSubject
#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("ReadSubjectTheoryData")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void ReadSubject(SamlTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.ReadSubject", theoryData);
            var context = new CompareContext($"{this}.ReadSubject, {theoryData.TestId}");
            try
            {
                var reader = XmlUtilities.CreateDictionaryReader(theoryData.SubjectTestSet.Xml);
                var subject = (theoryData.SamlSerializer as SamlSerializerPublic).ReadSubjectPublic(reader);
                theoryData.ExpectedException.ProcessNoException();

                IdentityComparer.AreEqual(subject, theoryData.SubjectTestSet.Subject, context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<SamlTheoryData> ReadSubjectTheoryData
        {
            get
            {
                return new TheoryData<SamlTheoryData>
                {
                    new SamlTheoryData
                    {
                        First = true,
                        SamlSerializer = new SamlSerializerPublic(),
                        SubjectTestSet = ReferenceXml.SamlSubjectNameIdentifierNull,
                        TestId = nameof(ReferenceXml.SamlSubjectNameIdentifierNull)
                    },
                    new SamlTheoryData
                    {
                        SamlSerializer = new SamlSerializerPublic(),
                        SubjectTestSet = ReferenceXml.SamlSubjectNoNameQualifier,
                        TestId = nameof(ReferenceXml.SamlSubjectNoNameQualifier)
                    },
                    new SamlTheoryData
                    {
                        SamlSerializer = new SamlSerializerPublic(),
                        SubjectTestSet = ReferenceXml.SamlSubjectNoFormat,
                        TestId = nameof(ReferenceXml.SamlSubjectNoFormat)
                    },
                    new SamlTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(SamlSecurityTokenReadException), "IDX11104"),
                        SamlSerializer = new SamlSerializerPublic(),
                        SubjectTestSet = ReferenceXml.SamlSubjectNameNull,
                        TestId = nameof(ReferenceXml.SamlSubjectNameNull)
                    },
                    new SamlTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(SamlSecurityTokenReadException), "IDX11104"),
                        SamlSerializer = new SamlSerializerPublic(),
                        SubjectTestSet = ReferenceXml.SamlSubjectNameEmptyString,
                        TestId = nameof(ReferenceXml.SamlSubjectNameEmptyString)
                    },
                    new SamlTheoryData
                    {
                        SamlSerializer = new SamlSerializerPublic(),
                        SubjectTestSet = ReferenceXml.SamlSubjectNoConfirmationData,
                        TestId = nameof(ReferenceXml.SamlSubjectNoConfirmationData)
                    },
                    new SamlTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(SamlSecurityTokenReadException), "IDX11114"),
                        SamlSerializer = new SamlSerializerPublic(),
                        SubjectTestSet = ReferenceXml.SamlSubjectConfirmationMethodNull,
                        TestId = nameof(ReferenceXml.SamlSubjectConfirmationMethodNull)
                    },
                    new SamlTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(SamlSecurityTokenReadException), "IDX11135"),
                        SamlSerializer = new SamlSerializerPublic(),
                        SubjectTestSet = ReferenceXml.SamlSubjectConfirmationMethodEmptyString,
                        TestId = nameof(ReferenceXml.SamlSubjectConfirmationMethodEmptyString)
                    },
                    new SamlTheoryData
                    {
                        SamlSerializer = new SamlSerializerPublic(),
                        SubjectTestSet = ReferenceXml.SamlSubjectWithNameIdentifierAndConfirmation,
                        TestId = nameof(ReferenceXml.SamlSubjectWithNameIdentifierAndConfirmation)
                    },
                    new SamlTheoryData
                    {
                        SamlSerializer = new SamlSerializerPublic(),
                        SubjectTestSet = ReferenceXml.SamlSubjectWithMultiConfirmationMethods,
                        TestId = nameof(ReferenceXml.SamlSubjectWithMultiConfirmationMethods)
                    }
                };
            }
        }
        #endregion

        private class SamlSerializerPublic : SamlSerializer
        {
            public SamlAction ReadActionPublic(XmlDictionaryReader reader)
            {
                return base.ReadAction(reader);
            }

            public SamlAdvice ReadAdvicePublic(XmlDictionaryReader reader)
            {
                return base.ReadAdvice(reader);
            }

            public SamlAssertion ReadAssertionPublic(XmlDictionaryReader reader)
            {
                return base.ReadAssertion(reader);
            }

            public SamlAttribute ReadAttributePublic(XmlDictionaryReader reader)
            {
                return base.ReadAttribute(reader);
            }

            public SamlAttributeStatement ReadAttributeStatementPublic(XmlDictionaryReader reader)
            {
                return base.ReadAttributeStatement(reader);
            }

            public SamlAudienceRestrictionCondition ReadAudienceRestrictionConditionPublic(XmlDictionaryReader reader)
            {
                return base.ReadAudienceRestrictionCondition(reader);
            }

            public SamlAuthenticationStatement ReadAuthenticationStatementPublic(XmlDictionaryReader reader)
            {
                return base.ReadAuthenticationStatement(reader);
            }

            public SamlAuthorizationDecisionStatement ReadAuthorizationDecisionStatementPublic(XmlDictionaryReader reader)
            {
                return base.ReadAuthorizationDecisionStatement(reader);
            }

            public SamlConditions ReadConditionsPublic(XmlDictionaryReader reader)
            {
                return base.ReadConditions(reader);
            }

            public SamlEvidence ReadEvidencePublic(XmlDictionaryReader reader)
            {
                return base.ReadEvidence(reader);
            }

            public SamlSubject ReadSubjectPublic(XmlDictionaryReader reader)
            {
                return base.ReadSubject(reader);
            }
        }
    }
}
