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
using System.IO;
using System.Xml;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Tests;
using Xunit;

namespace Microsoft.IdentityModel.Xml.Tests
{
    public class DSigTests
    {

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("SignatureConstructorTheoryData")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void SignatureConstructor(DSigTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.SignatureConstructor", theoryData);
            try
            {
                var signature = new Signature(theoryData.SignedInfoDataSet.SignedInfo);
                theoryData.ExpectedException.ProcessNoException();
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex);
            }
        }

        public static TheoryData<DSigTheoryData> SignatureConstructorTheoryData
        {
            get
            {
                var theoryData = new TheoryData<DSigTheoryData>();

                theoryData.Add(new DSigTheoryData
                {
                    ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                    First = true,
                    SignedInfoDataSet = new SignedInfoTestSet
                    {
                        SignedInfo = null
                    },
                    TestId = "SignedInfo NULL"
                });

                return theoryData;
            }
        }

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("SignedInfoConstructorTheoryData")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void SignedInfoConstructor(DSigTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.SignedInfoConstructor", theoryData);
            List<string> errors = new List<string>();
            try
            {
                var signedInfo = new SignedInfo();
                if (signedInfo.Reference != null)
                    errors.Add("signedInfo.Reference != null");

                if (!string.IsNullOrEmpty(signedInfo.SignatureAlgorithm))
                    errors.Add("!string.IsNullOrEmpty(signedInfo.SignatureAlgorithm)");

                theoryData.ExpectedException.ProcessNoException();
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex);
            }

            TestUtilities.AssertFailIfErrors(errors);
        }

        public static TheoryData<DSigTheoryData> SignedInfoConstructorTheoryData
        {
            get
            {
                var theoryData = new TheoryData<DSigTheoryData>();

                theoryData.Add(new DSigTheoryData
                {
                    First = true,
                    Prefix = XmlSignatureConstants.Prefix,
                    SignatureAlgorithm = XmlSignatureConstants.Elements.SignatureMethod,
                    TestId = "Constructor"
                });

                return theoryData;
            }
        }

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("SignedInfoReadFromTheoryData")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void SignedInfoReadFrom(DSigTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.SignedInfoReadFrom", theoryData);
            List<string> errors = new List<string>();
            try
            {
                var sr = new StringReader(theoryData.SignedInfoDataSet.Xml);
                var reader = XmlDictionaryReader.CreateDictionaryReader(XmlReader.Create(sr));
                var signedInfo = new SignedInfo();
                signedInfo.ReadFrom(reader);
                theoryData.ExpectedException.ProcessNoException();

                DSigXmlComparer.GetDiffs(signedInfo, theoryData.SignedInfoDataSet.SignedInfo, errors);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex);
            }

            TestUtilities.AssertFailIfErrors(errors);
        }

        public static TheoryData<DSigTheoryData> SignedInfoReadFromTheoryData
        {
            get
            {
                // uncomment to view exception displayed to user
                // ExpectedException.DefaultVerbose = true;

                var theoryData = new TheoryData<DSigTheoryData>();

                //theoryData.Add(new DSigTheoryData
                //{
                //    ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                //    First = true,
                //    TestId = "Null XmlReader",
                //    XmlReader = null
                //});

                theoryData.Add(new DSigTheoryData
                {
                    First = true,
                    SignedInfoDataSet = RefernceXml.SignedInfoValid,
                    TestId = nameof(RefernceXml.SignedInfoValid)
                });

                theoryData.Add(new DSigTheoryData
                {
                    SignedInfoDataSet = RefernceXml.SignInfoStartsWithWhiteSpace,
                    TestId = nameof(RefernceXml.SignInfoStartsWithWhiteSpace),
                });

                theoryData.Add(new DSigTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX21011:"),
                    SignedInfoDataSet = RefernceXml.SignedInfoCanonicalizationMethodMissing,
                    TestId = nameof(RefernceXml.SignedInfoCanonicalizationMethodMissing)
                });

                theoryData.Add(new DSigTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX21011:"),
                    SignedInfoDataSet = RefernceXml.SignedInfoReferenceMissing,
                    TestId = nameof(RefernceXml.SignedInfoReferenceMissing)
                });

                theoryData.Add(new DSigTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX21011:"),
                    SignedInfoDataSet = RefernceXml.SignedInfoTransformsMissing,
                    TestId = nameof(RefernceXml.SignedInfoTransformsMissing)
                });

                theoryData.Add(new DSigTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX21011:"),
                    SignedInfoDataSet = RefernceXml.SignedInfoNoTransforms,
                    TestId = nameof(RefernceXml.SignedInfoNoTransforms)
                });

                theoryData.Add(new DSigTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(XmlException), "IDX21018:"),
                    SignedInfoDataSet = RefernceXml.SignedInfoUnknownTransform,
                    TestId = nameof(RefernceXml.SignedInfoUnknownTransform)
                });

                theoryData.Add(new DSigTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX21011:"),
                    SignedInfoDataSet = RefernceXml.SignedInfoMissingDigestMethod,
                    TestId = nameof(RefernceXml.SignedInfoMissingDigestMethod)
                });

                theoryData.Add(new DSigTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX21011:"),
                    SignedInfoDataSet = RefernceXml.SignedInfoMissingDigestValue,
                    TestId = nameof(RefernceXml.SignedInfoMissingDigestValue)
                });

                return theoryData;
            }
        }

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("KeyInfoReadFromTheoryData")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void KeyInfoReadFrom(DSigTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.KeyInfoReadFrom", theoryData);
            List<string> errors = new List<string>();
            try
            {
                var sr = new StringReader(theoryData.KeyInfoDataSet.Xml);
                var reader = XmlDictionaryReader.CreateDictionaryReader(XmlReader.Create(sr));
                var keyInfo = new KeyInfo();
                keyInfo.ReadFrom(reader);
                theoryData.ExpectedException.ProcessNoException();

                DSigXmlComparer.GetDiffs(keyInfo, theoryData.KeyInfoDataSet.KeyInfo, errors);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex);
            }

            TestUtilities.AssertFailIfErrors(errors);
        }

        public static TheoryData<DSigTheoryData> KeyInfoReadFromTheoryData
        {
            get
            {
                // uncomment to view exception displayed to user
                // ExpectedException.DefaultVerbose = true;

                var theoryData = new TheoryData<DSigTheoryData>();

                theoryData.Add(new DSigTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX21011:"),
                    First = true,
                    KeyInfoDataSet = RefernceXml.KeyInfoWrongElement,
                    TestId = nameof(RefernceXml.KeyInfoWrongElement)
                });

                theoryData.Add(new DSigTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX21011:"),
                    First = true,
                    KeyInfoDataSet = RefernceXml.KeyInfoWrongNameSpace,
                    TestId = nameof(RefernceXml.KeyInfoWrongNameSpace)
                });

                theoryData.Add(new DSigTheoryData
                {
                    KeyInfoDataSet = RefernceXml.KeyInfoSingleCertificate,
                    TestId = nameof(RefernceXml.KeyInfoSingleCertificate)
                });

                theoryData.Add(new DSigTheoryData
                {
                    KeyInfoDataSet = RefernceXml.KeyInfoSingleIssuerSerial,
                    TestId = nameof(RefernceXml.KeyInfoSingleIssuerSerial)
                });

                theoryData.Add(new DSigTheoryData
                {
                    KeyInfoDataSet = RefernceXml.KeyInfoSingleSKI,
                    TestId = nameof(RefernceXml.KeyInfoSingleSKI)
                });

                theoryData.Add(new DSigTheoryData
                {
                    KeyInfoDataSet = RefernceXml.KeyInfoSingleSubjectName,
                    TestId = nameof(RefernceXml.KeyInfoSingleSubjectName)
                });

                theoryData.Add(new DSigTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX21015:"),
                    KeyInfoDataSet = RefernceXml.KeyInfoMultipleCertificates,
                    TestId = nameof(RefernceXml.KeyInfoMultipleCertificates)
                });

                theoryData.Add(new DSigTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX21015:"),
                    KeyInfoDataSet = RefernceXml.KeyInfoMultipleIssuerSerial,
                    TestId = nameof(RefernceXml.KeyInfoMultipleIssuerSerial)
                });

                theoryData.Add(new DSigTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX21015:"),
                    KeyInfoDataSet = RefernceXml.KeyInfoMultipleSKI,
                    TestId = nameof(RefernceXml.KeyInfoMultipleSKI)
                });

                theoryData.Add(new DSigTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX21015:"),
                    KeyInfoDataSet = RefernceXml.KeyInfoMultipleSubjectName,
                    TestId = nameof(RefernceXml.KeyInfoMultipleSubjectName)
                });

                theoryData.Add(new DSigTheoryData
                {
                    KeyInfoDataSet = RefernceXml.KeyInfoWithWhitespace,
                    TestId = nameof(RefernceXml.KeyInfoWithWhitespace)
                });

                theoryData.Add(new DSigTheoryData
                {
                    KeyInfoDataSet = RefernceXml.KeyInfoWithUnknownX509DataElements,
                    TestId = nameof(RefernceXml.KeyInfoWithUnknownX509DataElements)
                });

                theoryData.Add(new DSigTheoryData
                {
                    KeyInfoDataSet = RefernceXml.KeyInfoWithAllElements,
                    TestId = nameof(RefernceXml.KeyInfoWithAllElements)
                });

                theoryData.Add(new DSigTheoryData
                {
                    KeyInfoDataSet = RefernceXml.KeyInfoWithUnknownElements,
                    TestId = nameof(RefernceXml.KeyInfoWithUnknownElements)
                });

                theoryData.Add(new DSigTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX21017:", typeof(FormatException)),
                    KeyInfoDataSet = RefernceXml.KeyInfoMalformedCertificate,
                    TestId = nameof(RefernceXml.KeyInfoMalformedCertificate)
                });

                return theoryData;
            }
        }

        public class DSigTheoryData : TheoryDataBase
        {
            public bool ExpectSignedXml { get; set; }

            public KeyInfoTestSet KeyInfoDataSet { get; set; }

            public string Prefix { get; set; }

            public string ReferenceId { get; set; }

            public SecurityKey SecurityKey { get; set; }

            public string SignatureAlgorithm { get; set; }

            public SigningCredentials SigningCredentials { get; set; }

            public SignedInfoTestSet SignedInfoDataSet { get; set; }

            public XmlDictionaryWriter XmlWriter { get; set; }
        }
    }
}
