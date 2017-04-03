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
    public class EnvelopedSignatureTheoryData
    {
        public ExpectedException ExpectedException { get; set; }

        public bool ExpectSignedXml { get; set; }

        public SecurityKey SecurityKey { get; set; }

        public SignedXml SignedXml { get; set; }

        public string TestId { get; set; }

        public XmlReader XmlReader { get; set; }

        public override string ToString()
        {
            return TestId + ", ExpectSignedXml: " + ExpectSignedXml;
        }
    }

    public class EnvelopedSignatureReaderTests
    {

        static bool _firstReadSignedXml = true;

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("EnvelopedSignatureReaderTheoryData")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void ReadSignedXml(EnvelopedSignatureTheoryData theoryData)
        {
            TestUtilities.TestHeader($"{this}.ReadSignedXml", theoryData.TestId, ref _firstReadSignedXml);
            try
            {
                var envelopedReader = new EnvelopedSignatureReader(theoryData.XmlReader);
                while(envelopedReader.Read());

                if (theoryData.ExpectSignedXml)
                {
                    if (envelopedReader.SignedXml == null)
                        Assert.False(true, "theoryData.ExpectSignedXml == true && envelopedReader.SignedXml == null");

                    envelopedReader.SignedXml.VerifySignature(theoryData.SecurityKey);
                    envelopedReader.SignedXml.EnsureDigestValidity(envelopedReader.SignedXml.Signature.SignedInfo[0].ExtractReferredId(), envelopedReader.SignedXml.TokenSource);
                    envelopedReader.SignedXml.CompleteSignatureVerification();
                }

                theoryData.ExpectedException.ProcessNoException();
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex);
            }
        }

        public static TheoryData<EnvelopedSignatureTheoryData> EnvelopedSignatureReaderTheoryData
        {
            get
            {
                var theoryData = new TheoryData<EnvelopedSignatureTheoryData>();

                theoryData.Add(new EnvelopedSignatureTheoryData
                {
                    ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                    TestId = "Null XmlReader in Constructor",
                    XmlReader = null
                });

                var sr = new StringReader(RefrenceXml.Saml2Token_Valid);
                var reader = XmlDictionaryReader.CreateDictionaryReader(XmlReader.Create(sr));
                theoryData.Add(new EnvelopedSignatureTheoryData
                {
                    ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                    ExpectSignedXml = true,
                    TestId = nameof(RefrenceXml.Saml2Token_Valid) + " No Key",
                    XmlReader = reader
                });

                sr = new StringReader(RefrenceXml.Saml2Token_Valid);
                reader = XmlDictionaryReader.CreateDictionaryReader(XmlReader.Create(sr));
                theoryData.Add(new EnvelopedSignatureTheoryData
                {
                    ExpectedException = ExpectedException.NoExceptionExpected,
                    ExpectSignedXml = true,
                    SecurityKey = RefrenceXml.Saml2Token_Valid_SecurityKey,
                    TestId = nameof(RefrenceXml.Saml2Token_Valid),
                    XmlReader = reader
                });

                sr = new StringReader(RefrenceXml.Saml2Token_Valid_SignatureNOTFormated);
                reader = XmlDictionaryReader.CreateDictionaryReader(XmlReader.Create(sr));
                theoryData.Add(new EnvelopedSignatureTheoryData
                {
                    ExpectedException = ExpectedException.CryptographicException(),
                    ExpectSignedXml = true,
                    SecurityKey = RefrenceXml.Saml2Token_Valid_SecurityKey,
                    TestId = nameof(RefrenceXml.Saml2Token_Valid_SignatureNOTFormated),
                    XmlReader = reader
                });

                sr = new StringReader(RefrenceXml.Saml2Token_Valid_Formated);
                reader = XmlDictionaryReader.CreateDictionaryReader(XmlReader.Create(sr));
                theoryData.Add(new EnvelopedSignatureTheoryData
                {
                    ExpectedException = ExpectedException.CryptographicException(),
                    ExpectSignedXml = true,
                    SecurityKey = RefrenceXml.Saml2Token_Valid_SecurityKey,
                    TestId = nameof(RefrenceXml.Saml2Token_Valid_Formated),
                    XmlReader = reader
                });

                return theoryData;
            }
        }
    }
}
