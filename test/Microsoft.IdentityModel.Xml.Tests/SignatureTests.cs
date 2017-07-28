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
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tests;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Microsoft.IdentityModel.Xml.Tests
{
    public class SignatureTests
    {
#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Fact]
        public void GetSets()
        {
            var type = typeof(Signature);
            var properties = type.GetProperties();
            Assert.True(properties.Length == 5, $"Number of properties has changed from 5 to: {properties.Length}, adjust tests");
            var context = new GetSetContext
            {
                PropertyNamesAndSetGetValue = new List<KeyValuePair<string, List<object>>>
                {
                    new KeyValuePair<string, List<object>>("Id", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                    new KeyValuePair<string, List<object>>("Prefix", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                    new KeyValuePair<string, List<object>>("KeyInfo", new List<object>{(KeyInfo)null, new KeyInfo(), new KeyInfo()}),
                    new KeyValuePair<string, List<object>>("SignatureValue", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                    new KeyValuePair<string, List<object>>("SignedInfo", new List<object>{(SignedInfo)null, new SignedInfo(), new SignedInfo()}),
                },
                Object = new Signature(),
            };

            TestUtilities.GetSet(context);
            TestUtilities.AssertFailIfErrors($"{this}.GetSets", context.Errors);
        }

        [Theory, MemberData("ConstructorTheoryData")]
        public void Constructor(SignatureTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.Constructor", theoryData);
            var context = new CompareContext($"{this}.Constructor, {theoryData.TestId}");
            try
            {
                var signature = new Signature(theoryData.SignedInfo);
                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<SignatureTheoryData> ConstructorTheoryData
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
                    },
                    new SignatureTheoryData
                    {
                        SignedInfo = new SignedInfo(),
                        TestId = "SignedInfo"
                    }
                };
            }
        }

        [Theory, MemberData("VerifyTheoryData")]
        public void Verify(SignatureTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.Verify", theoryData);
            var context = new CompareContext($"{this}.Verify, {theoryData.TestId}");
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

        public static TheoryData<SignatureTheoryData> VerifyTheoryData
        {
            get
            {
                // uncomment to view exception displayed to user
                // ExpectedException.DefaultVerbose = true;

                var theoryData = new TheoryData<SignatureTheoryData>();
                theoryData.Add(new SignatureTheoryData
                {
                    First = true,
                    Signature = SignatureTestSet.DefaultSignature.Signature,
                    TestId = nameof(SignatureTestSet.DefaultSignature),
                    Xml = SignatureTestSet.DefaultSignature.Xml
                });

                theoryData.Add(new SignatureTheoryData
                {
                    ExpectedException = ExpectedException.ArgumentNullException(),
                    SecurityKey = null,
                    Signature = SignatureTestSet.DefaultSignature.Signature,
                    TestId = "SecurityKey is null",
                    Xml = SignatureTestSet.DefaultSignature.Xml
                });

                var key = ReferenceXml.DefaultAADSigningKey;
                key.CryptoProviderFactory = new CustomCryptoProviderFactory();
                theoryData.Add(new SignatureTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(XmlValidationException), "IDX21207:"),
                    SecurityKey = key,
                    Signature = SignatureTestSet.UnknownDigestAlgorithm.Signature,
                    TestId = "Signature_CryptoProvider returns a null SignatureProvider",
                    Xml = SignatureTestSet.UnknownDigestAlgorithm.Xml
                });

                key = ReferenceXml.DefaultAADSigningKey;
                key.CryptoProviderFactory = new CustomCryptoProviderFactory
                {
                    SignatureProvider = new CustomSignatureProvider(ReferenceXml.DefaultAADSigningKey, SecurityAlgorithms.RsaSha256)
                    {
                        VerifyResult = true,
                    },
                    SupportedAlgorithms = new List<string> { Default.SignatureMethod },
                    HashAlgorithm = SHA256.Create()
                };

                theoryData.Add(new SignatureTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(XmlValidationException), "IDX21208:"),
                    SecurityKey = key,
                    Signature = SignatureTestSet.UnknownDigestAlgorithm.Signature,
                    TestId = nameof(SignatureTestSet.UnknownDigestAlgorithm),
                    Xml = SignatureTestSet.UnknownDigestAlgorithm.Xml
                });

                theoryData.Add(new SignatureTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(XmlValidationException), "IDX21207:"),
                    Signature = SignatureTestSet.UnknownSignatureAlgorithm.Signature,
                    TestId = nameof(SignatureTestSet.UnknownSignatureAlgorithm),
                    Xml = SignatureTestSet.UnknownSignatureAlgorithm.Xml
                });

                return theoryData;
            }
        }

       //public static DSigSerializerTheoryData KeyInfoTest(KeyInfoTestSet keyInfo, ExpectedException expectedException = null, bool first = false)
       // {
       //     return new DSigSerializerTheoryData
       //     {
       //         ExpectedException = expectedException ?? ExpectedException.NoExceptionExpected,
       //         First = first,
       //         KeyInfo = keyInfo.KeyInfo,
       //         TestId = keyInfo.TestId ?? nameof(keyInfo),
       //         Xml = keyInfo.Xml,
       //     };
       // }

        private static SignatureTheoryData SignatureTest(SignatureTestSet testSet, SecurityKey key, XmlTokenStream tokenStream, ExpectedException expectedException = null, bool first = false)
        {
            return new SignatureTheoryData
            {
                ExpectedException = expectedException ?? ExpectedException.NoExceptionExpected,
                SecurityKey = key,
                Signature = testSet.Signature,
                TestId = testSet.TestId ?? nameof(testSet),
                TokenStream = tokenStream,
                Xml = testSet.Xml
            };
        }
        #pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
    }

    public class SignatureTheoryData : TheoryDataBase
    {
        public SecurityKey SecurityKey
        {
            get;
            set;
        } = Default.AsymmetricSigningKey;

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
        } = Default.TokenStream;

        public string Xml
        {
            get;
            set;
        }
    }
}
