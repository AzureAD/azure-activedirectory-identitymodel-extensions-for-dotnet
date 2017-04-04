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
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Tests;
using Microsoft.IdentityModel.Xml;
using Xunit;

namespace Microsoft.IdentityModel.Xml.Tests
{
    public class DSigTheoryData
    {
        public ExpectedException ExpectedException { get; set; }

        public bool ExpectSignedXml { get; set; }

        public string ReferenceId { get; set; }

        public SecurityKey SecurityKey { get; set; }

        public SigningCredentials SigningCredentials { get; set; }

        public SignedInfo SignedInfo { get; set; }

        public SignedXml SignedXml { get; set; }

        public string TestId { get; set; }

        public TransformFactory TransformFactory { get; set; }

        public XmlDictionaryReader XmlReader { get; set; }

        public XmlDictionaryWriter XmlWriter { get; set; }

        public override string ToString()
        {
            return TestId;
        }
    }

    public class DSigTests
    {
        static bool _firstSignedInfoConstructor = true;
        static bool _firstSignedInfoReadFrom = true;

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("ConstructorTheoryData")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void Constructor(DSigTheoryData theoryData)
        {
            TestUtilities.TestHeader($"{this}.Constructor", theoryData.TestId, ref _firstSignedInfoConstructor);
            try
            {

                theoryData.ExpectedException.ProcessNoException();
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex);
            }
        }

        public static TheoryData<DSigTheoryData> ConstructorTheoryData
        {
            get
            {
                var theoryData = new TheoryData<DSigTheoryData>();

                return theoryData;
            }
        }

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("ReadFromTheoryData")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void ReadFrom(DSigTheoryData theoryData)
        {
            TestUtilities.TestHeader($"{this}.ReadFrom", theoryData.TestId, ref _firstSignedInfoReadFrom);
            List<string> errors = new List<string>();
            try
            {
                var signedInfo = new SignedInfo();
                signedInfo.ReadFrom(theoryData.XmlReader, theoryData.TransformFactory);
                if (theoryData.SignedInfo != null)
                {
                    if (signedInfo.CanonicalizationMethod != theoryData.SignedInfo.CanonicalizationMethod)
                        errors.Add("signedInfo.CanonicalizationMethod != theoryData.SignedInfo.CanonicalizationMethod");

                    if (signedInfo.SignatureMethod != theoryData.SignedInfo.SignatureMethod)
                        errors.Add("signedInfo.SignatureMethod != theoryData.SignedInfo.SignatureMethod");

                    if (signedInfo.ReferenceCount != theoryData.SignedInfo.ReferenceCount)
                        errors.Add("signedInfo.SignatureMethod != theoryData.SignedInfo.SignatureMethod");
                    else  if (signedInfo.ReferenceCount > 0)
                    {
                        for (int i = 0; i < signedInfo.ReferenceCount; i++)
                        {
                            if (signedInfo[i].DigestMethod != theoryData.SignedInfo[i].DigestMethod)
                                errors.Add($"signedInfo[i].DigestMethod != theoryData.SignedInfo[i].DigestMethod. {signedInfo[i].DigestMethod} : {theoryData.SignedInfo[i].DigestMethod}");

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

        public static TheoryData<DSigTheoryData> ReadFromTheoryData
        {
            get
            {
                var theoryData = new TheoryData<DSigTheoryData>();

                theoryData.Add(new DSigTheoryData
                {
                    ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                    TestId = "null reader",
                    XmlReader = null
                });

                var sr = new StringReader(RefernceXml.SignInfo);
                var reader = XmlDictionaryReader.CreateDictionaryReader(XmlReader.Create(sr));
                theoryData.Add(new DSigTheoryData
                {
                    ExpectedException = ExpectedException.NoExceptionExpected,
                    SignedInfo = RefernceXml.ExpectedSignedInfo,
                    TestId = nameof(RefernceXml.SignInfo),
                    TransformFactory = TransformFactory.Instance,
                    XmlReader = reader
                });

                sr = new StringReader(RefernceXml.SignInfoStartsWithWhiteSpace);
                reader = XmlDictionaryReader.CreateDictionaryReader(XmlReader.Create(sr));
                theoryData.Add(new DSigTheoryData
                {
                    ExpectedException = ExpectedException.NoExceptionExpected,
                    SignedInfo = RefernceXml.ExpectedSignedInfo,
                    TestId = nameof(RefernceXml.SignInfoStartsWithWhiteSpace),
                    TransformFactory = TransformFactory.Instance,
                    XmlReader = reader
                });
                
                return theoryData;
            }
        }

    }
}
