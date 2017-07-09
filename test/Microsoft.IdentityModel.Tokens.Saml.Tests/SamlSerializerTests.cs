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
using System.Xml;
using Microsoft.IdentityModel.Tests;
using Microsoft.IdentityModel.Tokens.Saml;
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
                var sr = new StringReader(theoryData.ActionTestSet.Xml);
                var reader = XmlDictionaryReader.CreateDictionaryReader(XmlReader.Create(sr));
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
                var sr = new StringReader(theoryData.AudienceRestrictionConditionTestSet.Xml);
                var reader = XmlDictionaryReader.CreateDictionaryReader(XmlReader.Create(sr));
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
                var sr = new StringReader(theoryData.ConditionsTestSet.Xml);
                var reader = XmlDictionaryReader.CreateDictionaryReader(XmlReader.Create(sr));
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

        #region SamlAttribute
#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory(Skip = "till 5.2.0"), MemberData("ReadAttributeTheoryData")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void ReadAttribute(SamlTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.ReadAttribute", theoryData);
            var context = new CompareContext($"{this}.ReadAttribute, {theoryData.TestId}");
            try
            {
                var sr = new StringReader(theoryData.AttributeTestSet.Xml);
                var reader = XmlDictionaryReader.CreateDictionaryReader(XmlReader.Create(sr));
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
                        AttributeTestSet = ReferenceXml.SamlAttributeValueEmpty,
                        SamlSerializer = new SamlSerializerPublic(),
                        TestId = nameof(ReferenceXml.SamlAttributeValueEmpty)
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

        private class SamlSerializerPublic : SamlSerializer
        {
            public SamlAction ReadActionPublic(XmlDictionaryReader reader)
            {
                return base.ReadAction(reader);
            }

            public SamlAttribute ReadAttributePublic(XmlDictionaryReader reader)
            {
                return base.ReadAttribute(reader);
            }

            public SamlAudienceRestrictionCondition ReadAudienceRestrictionConditionPublic(XmlDictionaryReader reader)
            {
                return base.ReadAudienceRestrictionCondition(reader);
            }

            public SamlConditions ReadConditionsPublic(XmlDictionaryReader reader)
            {
                return ReadConditions(reader);
            }
        }
    }
}
