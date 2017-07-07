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
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Microsoft.IdentityModel.Xml.Tests
{
    public class SignatureTests
    {
#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("SignatureConstructorTheoryData")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void SignatureConstructor(SignatureTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.SignatureConstructor", theoryData);
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

        public static TheoryData<SignatureTheoryData> SignatureConstructorTheoryData
        {
            get
            {
                return new TheoryData<SignatureTheoryData>()
                {
                    new SignatureTheoryData
                    {
                        ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                        First = true,
                        SignedInfo = null,
                        TestId = "SignedInfo NULL"
                    }
                };
            }
        }

        #pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("SignatureReadFromTheoryData")]
        #pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void SignatureReadFrom(SignatureTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.SignatureReadFrom", theoryData);
            var context = new CompareContext($"{this}.SignatureReadFrom, {theoryData.TestId}");
            try
            {
                var sr = new StringReader(theoryData.Xml);
                var reader = XmlDictionaryReader.CreateDictionaryReader(XmlReader.Create(sr));
                var signature = new Signature(new SignedInfo());
                signature.ReadFrom(reader);
                theoryData.ExpectedException.ProcessNoException();

                IdentityComparer.AreEqual(signature, theoryData.Signature, context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<SignatureTheoryData> SignatureReadFromTheoryData
        {
            get
            {
                // uncomment to view exception displayed to user
                // ExpectedException.DefaultVerbose = true;

                return new TheoryData<SignatureTheoryData>
                {
                    new SignatureTheoryData
                    {
                        First = true,
                        Signature = ReferenceXml.Signature_UnknownDigestAlgorithm.Signature,
                        TestId = nameof(ReferenceXml.Signature_UnknownDigestAlgorithm),
                        Xml = ReferenceXml.Signature_UnknownDigestAlgorithm.Xml
                    },
                    new SignatureTheoryData
                    {
                        Signature = ReferenceXml.Signature_UnknownSignatureAlgorithm.Signature,
                        TestId = nameof(ReferenceXml.Signature_UnknownSignatureAlgorithm),
                        Xml = ReferenceXml.Signature_UnknownSignatureAlgorithm.Xml
                    }
                };
            }
        }

        #pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("SignatureVerifyTheoryData")]
        #pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void SignatureVerify(SignatureTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.SignatureVerify", theoryData);
            var context = new CompareContext($"{this}.SignatureVerify, {theoryData.TestId}");
            try
            {
                var tokenStreamingReader = XmlUtilities.CreateXmlTokenStreamReader(theoryData.Xml);
                var signature = new Signature(new SignedInfo());
                signature.ReadFrom(tokenStreamingReader);
                signature.TokenSource = tokenStreamingReader;
                signature.Verify(theoryData.SecurityKey);
                theoryData.ExpectedException.ProcessNoException();

                IdentityComparer.AreEqual(signature, theoryData.Signature, context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<SignatureTheoryData> SignatureVerifyTheoryData
        {
            get
            {
                // uncomment to view exception displayed to user
                // ExpectedException.DefaultVerbose = true;

                var theoryData = new TheoryData<SignatureTheoryData>();

                // use SecurityKey that will validate the SignedInfo
                var key  = ReferenceXml.DefaultAADSigningKey;
                key.CryptoProviderFactory = new DSigCryptoProviderFactory();

                theoryData.Add(new SignatureTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(XmlValidationException), "IDX21203:"),
                    SecurityKey = key,
                    Signature = ReferenceXml.Signature_UnknownDigestAlgorithm.Signature,
                    TestId = "CryptoProvider returns a null SignatureProvider",
                    Xml = ReferenceXml.Signature_UnknownDigestAlgorithm.Xml
                });

                key = ReferenceXml.DefaultAADSigningKey;
                key.CryptoProviderFactory = new DSigCryptoProviderFactory
                {
                    SignatureProvider = new DSigSignatureProvider(ReferenceXml.DefaultAADSigningKey, SecurityAlgorithms.RsaSha256)
                };

                theoryData.Add(new SignatureTheoryData
                {
                    ExpectedException = ExpectedException.NotSupportedException("IDX10640:"),
                    SecurityKey = key,
                    Signature = ReferenceXml.Signature_UnknownDigestAlgorithm.Signature,
                    TestId = nameof(ReferenceXml.Signature_UnknownDigestAlgorithm),
                    Xml = ReferenceXml.Signature_UnknownDigestAlgorithm.Xml
                });

                theoryData.Add(new SignatureTheoryData
                {
                    ExpectedException = ExpectedException.NotSupportedException("IDX10634:"),
                    SecurityKey = ReferenceXml.DefaultAADSigningKey,
                    Signature = ReferenceXml.Signature_UnknownSignatureAlgorithm.Signature,
                    TestId = nameof(ReferenceXml.Signature_UnknownSignatureAlgorithm),
                    Xml = ReferenceXml.Signature_UnknownSignatureAlgorithm.Xml
                });

                return theoryData;
            }
        }
    }
    public class SignatureTheoryData : TheoryDataBase
    {
        public SecurityKey SecurityKey { get; set; }

        public Signature Signature { get; set; }

        public SignedInfo SignedInfo { get; set; }

        public string Xml { get; set; }
    }
}
