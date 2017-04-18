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
using System.Text;
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
                var signature = new Signature(theoryData.SignedInfoTestSet.SignedInfo);
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
                    SignedInfoTestSet = new SignedInfoTestSet
                    {
                        SignedInfo = null
                    },
                    TestId = "SignedInfo NULL"
                });

                return theoryData;
            }
        }

        #pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("SignatureReadFromTheoryData")]
        #pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void SignatureReadFrom(DSigTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.SignatureReadFrom", theoryData);
            List<string> errors = new List<string>();
            try
            {
                var sr = new StringReader(theoryData.SignatureTestSet.Xml);
                var reader = XmlDictionaryReader.CreateDictionaryReader(XmlReader.Create(sr));
                var signature = new Signature(new SignedInfo());
                signature.ReadFrom(reader);
                theoryData.ExpectedException.ProcessNoException();

                DSigXmlComparer.GetDiffs(signature, theoryData.SignatureTestSet.Signature, errors);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex);
            }

            TestUtilities.AssertFailIfErrors(errors);
        }

        public static TheoryData<DSigTheoryData> SignatureReadFromTheoryData
        {
            get
            {
                // uncomment to view exception displayed to user
                // ExpectedException.DefaultVerbose = true;

                var theoryData = new TheoryData<DSigTheoryData>();

                theoryData.Add(new DSigTheoryData
                {
                    First = true,
                    SignatureTestSet = RefernceXml.Signature_UnknownDigestAlgorithm,
                    TestId = nameof(RefernceXml.Signature_UnknownDigestAlgorithm)
                });

                theoryData.Add(new DSigTheoryData
                {
                    SignatureTestSet = RefernceXml.Signature_UnknownSignatureAlgorithm,
                    TestId = nameof(RefernceXml.Signature_UnknownSignatureAlgorithm)
                });

                return theoryData;
            }
        }

        #pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("SignatureVerifyTheoryData")]
        #pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void SignatureVerify(DSigTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.SignatureVerify", theoryData);

            List<string> errors = new List<string>();
            try
            {
                var sr = new StringReader(theoryData.SignatureTestSet.Xml);
                var reader = XmlDictionaryReader.CreateDictionaryReader(XmlReader.Create(sr));
                var tokenStreamingReader = new TokenStreamingReader(reader);
                var signature = new Signature(new SignedInfo());
                signature.ReadFrom(tokenStreamingReader);
                signature.TokenSource = tokenStreamingReader;
                signature.Verify(theoryData.SignatureTestSet.SecurityKey);
                theoryData.ExpectedException.ProcessNoException();

                DSigXmlComparer.GetDiffs(signature, theoryData.SignatureTestSet.Signature, errors);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex);
            }

            TestUtilities.AssertFailIfErrors(errors);
        }

        public static TheoryData<DSigTheoryData> SignatureVerifyTheoryData
        {
            get
            {
                // uncomment to view exception displayed to user
                // ExpectedException.DefaultVerbose = true;

                var theoryData = new TheoryData<DSigTheoryData>();

                // use SecurityKey that will validate the SignedInfo
                var signatureTestSet = RefernceXml.Signature_UnknownDigestAlgorithm;
                signatureTestSet.SecurityKey = RefernceXml.Saml2Token_Valid_SecurityKey;
                signatureTestSet.SecurityKey.CryptoProviderFactory = new DSigCryptoProviderFactory();
                theoryData.Add(new DSigTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(XmlValidationException), "IDX21203:"),
                    SignatureTestSet = signatureTestSet,
                    TestId = "CryptoProviderFactory returns null SignatureProvider"
                });

                signatureTestSet = RefernceXml.Signature_UnknownDigestAlgorithm;
                signatureTestSet.SecurityKey = RefernceXml.Saml2Token_Valid_SecurityKey;
                signatureTestSet.SecurityKey.CryptoProviderFactory = new DSigCryptoProviderFactory()
                {
                    SignatureProvider = new DSigSignatureProvider(RefernceXml.Saml2Token_Valid_SecurityKey, SecurityAlgorithms.RsaSha256)
                };

                theoryData.Add(new DSigTheoryData
                {
                    ExpectedException = ExpectedException.InvalidOperationException("IDX10640:"),
                    SignatureTestSet = signatureTestSet,
                    TestId = nameof(RefernceXml.Signature_UnknownDigestAlgorithm)
                });

                theoryData.Add(new DSigTheoryData
                {
                    ExpectedException = ExpectedException.ArgumentException("IDX10634:"),          
                    SignatureTestSet = RefernceXml.Signature_UnknownSignatureAlgorithm,
                    TestId = nameof(RefernceXml.Signature_UnknownSignatureAlgorithm)
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
                var sr = new StringReader(theoryData.SignedInfoTestSet.Xml);
                var reader = XmlDictionaryReader.CreateDictionaryReader(XmlReader.Create(sr));
                var signedInfo = new SignedInfo();
                signedInfo.ReadFrom(reader);
                theoryData.ExpectedException.ProcessNoException();

                DSigXmlComparer.GetDiffs(signedInfo, theoryData.SignedInfoTestSet.SignedInfo, errors);
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
                    SignedInfoTestSet = RefernceXml.SignedInfoValid,
                    TestId = nameof(RefernceXml.SignedInfoValid)
                });

                theoryData.Add(new DSigTheoryData
                {
                    SignedInfoTestSet = RefernceXml.SignInfoStartsWithWhiteSpace,
                    TestId = nameof(RefernceXml.SignInfoStartsWithWhiteSpace),
                });

                theoryData.Add(new DSigTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX21011:"),
                    SignedInfoTestSet = RefernceXml.SignedInfoCanonicalizationMethodMissing,
                    TestId = nameof(RefernceXml.SignedInfoCanonicalizationMethodMissing)
                });

                theoryData.Add(new DSigTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX21011:"),
                    SignedInfoTestSet = RefernceXml.SignedInfoReferenceMissing,
                    TestId = nameof(RefernceXml.SignedInfoReferenceMissing)
                });

                theoryData.Add(new DSigTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX21011:"),
                    SignedInfoTestSet = RefernceXml.SignedInfoTransformsMissing,
                    TestId = nameof(RefernceXml.SignedInfoTransformsMissing)
                });

                theoryData.Add(new DSigTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX21011:"),
                    SignedInfoTestSet = RefernceXml.SignedInfoNoTransforms,
                    TestId = nameof(RefernceXml.SignedInfoNoTransforms)
                });

                theoryData.Add(new DSigTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX21011:"),
                    SignedInfoTestSet = RefernceXml.SignedInfoUnknownCanonicalizationtMethod,
                    TestId = nameof(RefernceXml.SignedInfoUnknownCanonicalizationtMethod)
                });


                theoryData.Add(new DSigTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(XmlException), "IDX21018:"),
                    SignedInfoTestSet = RefernceXml.SignedInfoUnknownTransform,
                    TestId = nameof(RefernceXml.SignedInfoUnknownTransform)
                });

                theoryData.Add(new DSigTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX21011:"),
                    SignedInfoTestSet = RefernceXml.SignedInfoMissingDigestMethod,
                    TestId = nameof(RefernceXml.SignedInfoMissingDigestMethod)
                });

                theoryData.Add(new DSigTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX21011:"),
                    SignedInfoTestSet = RefernceXml.SignedInfoMissingDigestValue,
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
                var sr = new StringReader(theoryData.KeyInfoTestSet.Xml);
                var reader = XmlDictionaryReader.CreateDictionaryReader(XmlReader.Create(sr));
                var keyInfo = new KeyInfo();
                keyInfo.ReadFrom(reader);
                theoryData.ExpectedException.ProcessNoException();

                DSigXmlComparer.GetDiffs(keyInfo, theoryData.KeyInfoTestSet.KeyInfo, errors);
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
                    KeyInfoTestSet = RefernceXml.KeyInfoWrongElement,
                    TestId = nameof(RefernceXml.KeyInfoWrongElement)
                });

                theoryData.Add(new DSigTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX21011:"),
                    First = true,
                    KeyInfoTestSet = RefernceXml.KeyInfoWrongNameSpace,
                    TestId = nameof(RefernceXml.KeyInfoWrongNameSpace)
                });

                theoryData.Add(new DSigTheoryData
                {
                    KeyInfoTestSet = RefernceXml.KeyInfoSingleCertificate,
                    TestId = nameof(RefernceXml.KeyInfoSingleCertificate)
                });

                theoryData.Add(new DSigTheoryData
                {
                    KeyInfoTestSet = RefernceXml.KeyInfoSingleIssuerSerial,
                    TestId = nameof(RefernceXml.KeyInfoSingleIssuerSerial)
                });

                theoryData.Add(new DSigTheoryData
                {
                    KeyInfoTestSet = RefernceXml.KeyInfoSingleSKI,
                    TestId = nameof(RefernceXml.KeyInfoSingleSKI)
                });

                theoryData.Add(new DSigTheoryData
                {
                    KeyInfoTestSet = RefernceXml.KeyInfoSingleSubjectName,
                    TestId = nameof(RefernceXml.KeyInfoSingleSubjectName)
                });

                theoryData.Add(new DSigTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX21015:"),
                    KeyInfoTestSet = RefernceXml.KeyInfoMultipleCertificates,
                    TestId = nameof(RefernceXml.KeyInfoMultipleCertificates)
                });

                theoryData.Add(new DSigTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX21015:"),
                    KeyInfoTestSet = RefernceXml.KeyInfoMultipleIssuerSerial,
                    TestId = nameof(RefernceXml.KeyInfoMultipleIssuerSerial)
                });

                theoryData.Add(new DSigTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX21015:"),
                    KeyInfoTestSet = RefernceXml.KeyInfoMultipleSKI,
                    TestId = nameof(RefernceXml.KeyInfoMultipleSKI)
                });

                theoryData.Add(new DSigTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX21015:"),
                    KeyInfoTestSet = RefernceXml.KeyInfoMultipleSubjectName,
                    TestId = nameof(RefernceXml.KeyInfoMultipleSubjectName)
                });

                theoryData.Add(new DSigTheoryData
                {
                    KeyInfoTestSet = RefernceXml.KeyInfoWithWhitespace,
                    TestId = nameof(RefernceXml.KeyInfoWithWhitespace)
                });

                theoryData.Add(new DSigTheoryData
                {
                    KeyInfoTestSet = RefernceXml.KeyInfoWithUnknownX509DataElements,
                    TestId = nameof(RefernceXml.KeyInfoWithUnknownX509DataElements)
                });

                theoryData.Add(new DSigTheoryData
                {
                    KeyInfoTestSet = RefernceXml.KeyInfoWithAllElements,
                    TestId = nameof(RefernceXml.KeyInfoWithAllElements)
                });

                theoryData.Add(new DSigTheoryData
                {
                    KeyInfoTestSet = RefernceXml.KeyInfoWithUnknownElements,
                    TestId = nameof(RefernceXml.KeyInfoWithUnknownElements)
                });

                theoryData.Add(new DSigTheoryData
                {
                    ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX21017:", typeof(FormatException)),
                    KeyInfoTestSet = RefernceXml.KeyInfoMalformedCertificate,
                    TestId = nameof(RefernceXml.KeyInfoMalformedCertificate)
                });

                return theoryData;
            }
        }

        public class DSigTheoryData : TheoryDataBase
        {
            public KeyInfoTestSet KeyInfoTestSet { get; set; }

            public SignatureTestSet SignatureTestSet { get; set; }

            public SigningCredentials SigningCredentials { get; set; }

            public SignedInfoTestSet SignedInfoTestSet { get; set; }
        }

        /// <summary>
        /// DSigCryptoProviderFactory and DSignatureProvider are used to simulate failures and get deeper in the stack
        /// </summary>
        public class DSigCryptoProviderFactory : CryptoProviderFactory
        {
            public DSigCryptoProviderFactory() { }

            public SignatureProvider SignatureProvider { get; set; }

            public override SignatureProvider CreateForSigning(SecurityKey key, string algorithm)
            {
                return SignatureProvider;
            }

            public override SignatureProvider CreateForVerifying(SecurityKey key, string algorithm)
            {
                return SignatureProvider;
            }
        }

        public class DSigSignatureProvider : SignatureProvider
        {
            public DSigSignatureProvider(SecurityKey key, string algorithm)
                : base(key, algorithm)
            { }

            protected override void Dispose(bool disposing)
            {
            }

            public override byte[] Sign(byte[] input)
            {
                return Encoding.UTF8.GetBytes("SignedBytes");
            }

            public override bool Verify(byte[] input, byte[] signature)
            {
                return VerifyResult;
            }

            public bool VerifyResult { get; set; } = true;
        }
    }
}
