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
            TestUtilities.WriteHeader($"{this}.SignatureConstructor", theoryData.TestId, theoryData.First);
            try
            {
                var signature = new Signature(theoryData.SignedInfo);
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
                    SignedInfo = null,
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
            TestUtilities.WriteHeader($"{this}.SignedInfoConstructor", theoryData.TestId, theoryData.First);
            List<string> errors = new List<string>();
            try
            {
                var signedInfo = new SignedInfo();
                if (signedInfo.ReferenceCount != 0)
                    errors.Add("signedInfo.ReferenceCount != 0");

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
            TestUtilities.WriteHeader($"{this}.SignedInfoReadFrom", theoryData.TestId, theoryData.First);
            List<string> errors = new List<string>();
            try
            {
                var signedInfo = new SignedInfo();
                signedInfo.ReadFrom(theoryData.XmlReader, theoryData.TransformFactory);
                if (theoryData.SignedInfo != null)
                {
                    if (signedInfo.CanonicalizationMethod != theoryData.SignedInfo.CanonicalizationMethod)
                        errors.Add("signedInfo.CanonicalizationMethod != theoryData.SignedInfo.CanonicalizationMethod");

                    if (signedInfo.SignatureAlgorithm != theoryData.SignedInfo.SignatureAlgorithm)
                        errors.Add("signedInfo.SignatureMethod != theoryData.SignedInfo.SignatureMethod");

                    if (signedInfo.ReferenceCount != theoryData.SignedInfo.ReferenceCount)
                        errors.Add("signedInfo.SignatureMethod != theoryData.SignedInfo.SignatureMethod");
                    else if (signedInfo.ReferenceCount > 0)
                    {
                        for (int i = 0; i < signedInfo.ReferenceCount; i++)
                        {
                            if (signedInfo[i].DigestAlgorithm != theoryData.SignedInfo[i].DigestAlgorithm)
                                errors.Add($"signedInfo[i].DigestMethod != theoryData.SignedInfo[i].DigestMethod. {signedInfo[i].DigestAlgorithm} : {theoryData.SignedInfo[i].DigestAlgorithm}");

                            if (signedInfo[i].Uri != theoryData.SignedInfo[i].Uri)
                                errors.Add($"signedInfo[i].Uri != theoryData.SignedInfo[i].Uri. {signedInfo[i].Uri} : {theoryData.SignedInfo[i].Uri}");

                            if (signedInfo[i].TransformCount != theoryData.SignedInfo[i].TransformCount)
                                errors.Add($"signedInfo[i].Uri != theoryData.SignedInfo[i].Uri. {signedInfo[i].TransformCount} : {theoryData.SignedInfo[i].TransformCount}");
                            else if (signedInfo[i].TransformCount > 0)
                            {
                                for (int j = 0; j < signedInfo[i].TransformCount; j++)
                                {
                                    if (signedInfo[i].TransformChain[j].GetType() != theoryData.SignedInfo[i].TransformChain[j].GetType())
                                        errors.Add($"signedInfo[i].TransformChain[j].GetType() != theoryData.SignedInfo[i].TransformChain[j].GetType(), {signedInfo[i].TransformChain[i].GetType()} : {theoryData.SignedInfo[i].TransformChain[j].GetType()}");
                                }
                            }
                        }
                    }

                }

                theoryData.ExpectedException.ProcessNoException();
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

                theoryData.Add(new DSigTheoryData
                {
                    ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                    First = true,
                    TestId = "Null XmlReader",
                    XmlReader = null
                });

                var sr = new StringReader(RefernceXml.SignInfo);
                var reader = XmlDictionaryReader.CreateDictionaryReader(XmlReader.Create(sr));
                theoryData.Add(new DSigTheoryData
                {
                    SignedInfo = RefernceXml.ExpectedSignedInfo,
                    TestId = nameof(RefernceXml.SignInfo),
                    TransformFactory = TransformFactory.Instance,
                    XmlReader = reader
                });

                sr = new StringReader(RefernceXml.SignInfoStartsWithWhiteSpace);
                reader = XmlDictionaryReader.CreateDictionaryReader(XmlReader.Create(sr));
                theoryData.Add(new DSigTheoryData
                {
                    SignedInfo = RefernceXml.ExpectedSignedInfo,
                    TestId = nameof(RefernceXml.SignInfoStartsWithWhiteSpace),
                    TransformFactory = TransformFactory.Instance,
                    XmlReader = reader
                });

                sr = new StringReader(RefernceXml.SignedInfoCanonicalizationMethodMissing);
                reader = XmlDictionaryReader.CreateDictionaryReader(XmlReader.Create(sr));
                theoryData.Add(new DSigTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(XmlReadException)),
                    SignedInfo = RefernceXml.ExpectedSignedInfo,
                    TestId = nameof(RefernceXml.SignedInfoCanonicalizationMethodMissing),
                    TransformFactory = TransformFactory.Instance,
                    XmlReader = reader
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

                theoryData.KeyInfoDataSet.KeyInfo.GetDiffs(keyInfo, errors);
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
                    First = true,
                    KeyInfoDataSet = RefernceXml.KeyInfoSingleX509Certificate,
                    TestId = nameof(RefernceXml.KeyInfoSingleX509Certificate),
                });

                theoryData.Add(new DSigTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX21015:"),
                    KeyInfoDataSet = RefernceXml.KeyInfoMultipleX509Certificates,
                    TestId = nameof(RefernceXml.KeyInfoMultipleX509Certificates),
                });

                return theoryData;
            }
        }

        public class DSigTheoryData : TheoryDataBase
        {
            public bool ExpectSignedXml { get; set; }

            public KeyInfoDataSet KeyInfoDataSet { get; set; }

            public string Prefix { get; set; }

            public string ReferenceId { get; set; }

            public SecurityKey SecurityKey { get; set; }

            public string SignatureAlgorithm { get; set; }

            public SigningCredentials SigningCredentials { get; set; }

            public SignedInfo SignedInfo { get; set; }

            public TransformFactory TransformFactory { get; set; }

            public XmlDictionaryReader XmlReader { get; set; }

            public XmlDictionaryWriter XmlWriter { get; set; }
        }
    }
}
