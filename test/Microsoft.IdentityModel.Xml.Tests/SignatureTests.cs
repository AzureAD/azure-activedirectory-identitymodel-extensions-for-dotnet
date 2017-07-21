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
using Microsoft.IdentityModel.Tests;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Microsoft.IdentityModel.Xml.Tests
{
    public class SignatureTests
    {
#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("SignatureConstructorTheoryData")]
        public void SignatureConstructor(SignatureTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.SignatureConstructor", theoryData);
            var context = new CompareContext($"{this}.SignatureConstructor, {theoryData.TestId}");
            try
            {
                var signature = new Signature()
                {
                    SignedInfo = theoryData.SignedInfo
                };

                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<SignatureTheoryData> SignatureConstructorTheoryData
        {
            get
            {
                return new TheoryData<SignatureTheoryData>()
                {
                    new SignatureTheoryData
                    {
                        ExpectedException = ExpectedException.ArgumentNullException("IDX10000: The parameter 'value' cannot be a 'null' or an empty object."),
                        First = true,
                        SignedInfo = null,
                        TestId = "SignedInfo NULL"
                    }
                };
            }
        }

        [Theory, MemberData("SignatureVerifyTheoryData")]
        public void SignatureVerify(SignatureTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.SignatureVerify", theoryData);
            var context = new CompareContext($"{this}.SignatureVerify, {theoryData.TestId}");
            try
            {
                var signature = theoryData.Serializer.ReadSignature(XmlUtilities.CreateDictionaryReader(theoryData.Xml));
                signature.SignedInfo.References[0].TokenStream = theoryData.TokenStream;
                signature.Verify(theoryData.SecurityKey);
                theoryData.ExpectedException.ProcessNoException(context);
                IdentityComparer.AreEqual(signature, theoryData.Signature, context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
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

                theoryData.Add(new SignatureTheoryData
                {
                    SecurityKey = Default.AsymmetricSigningKey,
                    Signature = SignatureTestSet.DefaultSignature.Signature,
                    TestId = nameof(SignatureTestSet.DefaultSignature),
                    TokenStream = Default.TokenStream,
                    Xml = SignatureTestSet.DefaultSignature.Xml
                });

                // use SecurityKey that will validate the SignedInfo
                var key  = ReferenceXml.DefaultAADSigningKey;
                key.CryptoProviderFactory = new DSigCryptoProviderFactory();

                theoryData.Add(new SignatureTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(XmlValidationException), "IDX21203:"),
                    SecurityKey = key,
                    Signature = SignatureTestSet.UnknownDigestAlgorithm.Signature,
                    TestId = "Signature_CryptoProvider returns a null SignatureProvider",
                    TokenStream = Default.TokenStream,
                    Xml = SignatureTestSet.UnknownDigestAlgorithm.Xml
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
                    Signature = SignatureTestSet.UnknownDigestAlgorithm.Signature,
                    TestId = nameof(SignatureTestSet.UnknownDigestAlgorithm),
                    TokenStream = Default.TokenStream,
                    Xml = SignatureTestSet.UnknownDigestAlgorithm.Xml
                });

                theoryData.Add(new SignatureTheoryData
                {
                    ExpectedException = ExpectedException.NotSupportedException("IDX10634:"),
                    SecurityKey = ReferenceXml.DefaultAADSigningKey,
                    Signature = SignatureTestSet.UnknownSignatureAlgorithm.Signature,
                    TestId = nameof(SignatureTestSet.UnknownSignatureAlgorithm),
                    TokenStream = Default.TokenStream,
                    Xml = SignatureTestSet.UnknownSignatureAlgorithm.Xml
                });

                return theoryData;
            }
        }

        #pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
    }
    public class SignatureTheoryData : TheoryDataBase
    {
        public SecurityKey SecurityKey
        {
            get;
            set;
        }

        public DSigSerializer Serializer
        {
            get;
            set;
        } = new DSigSerializer();

        public Signature Signature
        {
            get;
            set;
        }

        public SignedInfo SignedInfo
        {
            get;
            set;
        }

        public XmlTokenStream TokenStream
        {
            get;
            set;
        }

        public string Xml
        {
            get;
            set;
        }
    }
}
