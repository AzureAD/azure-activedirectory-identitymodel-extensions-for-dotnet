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
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Tests;
using Xunit;

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant

namespace Microsoft.IdentityModel.Tokens.Tests
{
    public class AsymmetricSignatureTests
    {
        // Throw for NET45 and NET451 targets for derived RSA types.
        [Fact]
        public void UnsupportedRSAType()
        {
#if NET452
            var expectedException = ExpectedException.NotSupportedException();
#endif

#if NET461 || NETCOREAPP2_0
            var expectedException = ExpectedException.NoExceptionExpected;
#endif

            try
            {
                new AsymmetricSignatureProvider(new RsaSecurityKey(new DerivedRsa(2048)), SecurityAlgorithms.RsaSha256, false);
                expectedException.ProcessNoException();
            }
            catch (Exception ex)
            {
                expectedException.ProcessException(ex);
            }
        }

        [Theory, MemberData(nameof(SignVerifyTheoryData))]
        public void SignVerify(SignatureProviderTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.SignVerify", theoryData);
            var bytes = Guid.NewGuid().ToByteArray();
            byte[] signatureDirect = null;
            byte[] signatureFromFactory = null;
            try
            {
                var providerForSigningDirect = new AsymmetricSignatureProvider(theoryData.SigningKey, theoryData.SigningAlgorithm, true);
                var providerForVerifyingDirect = new AsymmetricSignatureProvider(theoryData.VerifyKey, theoryData.VerifyAlgorithm, false);
                var providerForSigningFromFactory = theoryData.SigningKey.CryptoProviderFactory.CreateForSigning(theoryData.SigningKey, theoryData.SigningAlgorithm);
                var providerForVerifyingFromFactory = theoryData.VerifyKey.CryptoProviderFactory.CreateForVerifying(theoryData.VerifyKey, theoryData.VerifyAlgorithm);

                signatureDirect = providerForSigningDirect.Sign(bytes);
                signatureFromFactory = providerForSigningFromFactory.Sign(bytes);

                if (!providerForVerifyingDirect.Verify(bytes, signatureDirect))
                    context.AddDiff($"providerForVerifyingDirect.Verify (signatureDirect) - FAILED. signingKey : signingAlgorithm '{theoryData.SigningKey}' : '{theoryData.SigningAlgorithm}. verifyKey : verifyAlgorithm '{theoryData.VerifyKey}' : '{theoryData.VerifyAlgorithm}");

                if (!providerForVerifyingDirect.Verify(bytes, signatureFromFactory))
                    context.AddDiff($"providerForVerifyingDirect.Verify (signatureFromFactory) - FAILED. signingKey : signingAlgorithm '{theoryData.SigningKey}' : '{theoryData.SigningAlgorithm}. verifyKey : verifyAlgorithm '{theoryData.VerifyKey}' : '{theoryData.VerifyAlgorithm}");

                if (!providerForVerifyingFromFactory.Verify(bytes, signatureDirect))
                    context.AddDiff($"providerForVerifyingFromFactory.Verify (signatureDirect) - FAILED. signingKey : signingAlgorithm '{theoryData.SigningKey}' : '{theoryData.SigningAlgorithm}. verifyKey : verifyAlgorithm '{theoryData.VerifyKey}' : '{theoryData.VerifyAlgorithm}");

                if (!providerForVerifyingFromFactory.Verify(bytes, signatureFromFactory))
                    context.AddDiff($"providerForVerifyingFromFactory.Verify (signatureFromFactory) - FAILED. signingKey : signingAlgorithm '{theoryData.SigningKey}' : '{theoryData.SigningAlgorithm}. verifyKey : verifyAlgorithm '{theoryData.VerifyKey}' : '{theoryData.VerifyAlgorithm}");

                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<SignatureProviderTheoryData> SignVerifyTheoryData
        {
            get
            {
                var theoryData = new TheoryData<SignatureProviderTheoryData>();

                foreach (var certTuple in AsymmetricSignatureTestData.Certificates)
                    AsymmetricSignatureTestData.AddRsaAlgorithmVariations(new SignatureProviderTheoryData
                    {
                        SigningKey = new RsaSecurityKey(certTuple.Item1.PrivateKey as RSA),
                        TestId = "CapiCapi" + certTuple.Item3,
                        VerifyKey = new RsaSecurityKey(certTuple.Item2.PublicKey.Key as RSA)
                    },
                    theoryData);

#if NET461 || NETCOREAPP2_0
                foreach (var certTuple in AsymmetricSignatureTestData.Certificates)
                    AsymmetricSignatureTestData.AddRsaAlgorithmVariations(new SignatureProviderTheoryData
                    {
                        SigningKey = new RsaSecurityKey(certTuple.Item1.PrivateKey as RSA),
                        TestId = "CapiCng" + certTuple.Item3,
                        VerifyKey = new RsaSecurityKey(certTuple.Item2.GetRSAPublicKey())
                    },
                    theoryData);

                foreach (var certTuple in AsymmetricSignatureTestData.Certificates)
                    AsymmetricSignatureTestData.AddRsaAlgorithmVariations(new SignatureProviderTheoryData
                    {
                        SigningKey = new RsaSecurityKey(certTuple.Item1.GetRSAPrivateKey()),
                        TestId = "CngCapi" + certTuple.Item3,
                        VerifyKey = new RsaSecurityKey(certTuple.Item2.PublicKey.Key as RSA)
                    },
                    theoryData);

                foreach (var certTuple in AsymmetricSignatureTestData.Certificates)
                    AsymmetricSignatureTestData.AddRsaAlgorithmVariations(new SignatureProviderTheoryData
                    {
                        SigningKey = new RsaSecurityKey(certTuple.Item1.GetRSAPrivateKey()),
                        TestId = "CngCng" + certTuple.Item3,
                        VerifyKey = new RsaSecurityKey(certTuple.Item2.GetRSAPublicKey())
                    },
                    theoryData);
#endif

                foreach (var ecdsaKeyTuple in AsymmetricSignatureTestData.ECDsaSecurityKeys)
                    AsymmetricSignatureTestData.AddECDsaAlgorithmVariations(new SignatureProviderTheoryData
                    {
                        SigningKey = ecdsaKeyTuple.Item1,
                        TestId = ecdsaKeyTuple.Item3,
                        VerifyKey = ecdsaKeyTuple.Item2
                    },
                    theoryData);

                foreach (var jsonKeyTuple in AsymmetricSignatureTestData.JsonECDsaSecurityKeys)
                    AsymmetricSignatureTestData.AddECDsaAlgorithmVariations(new SignatureProviderTheoryData
                    {
                        SigningKey = jsonKeyTuple.Item1,
                        TestId = jsonKeyTuple.Item3,
                        VerifyKey = jsonKeyTuple.Item2
                    },
                    theoryData);

                foreach (var jsonKeyTuple in AsymmetricSignatureTestData.JsonRsaSecurityKeys)
                    AsymmetricSignatureTestData.AddRsaAlgorithmVariations(new SignatureProviderTheoryData
                    {
                        SigningKey = jsonKeyTuple.Item1,
                        TestId = jsonKeyTuple.Item3,
                        VerifyKey = jsonKeyTuple.Item2
                    },
                    theoryData);

                foreach (var rsaKeyTuple in AsymmetricSignatureTestData.RsaSecurityKeys)
                    AsymmetricSignatureTestData.AddRsaAlgorithmVariations(new SignatureProviderTheoryData
                    {
                        SigningKey = rsaKeyTuple.Item1,
                        TestId = rsaKeyTuple.Item3,
                        VerifyKey = rsaKeyTuple.Item2
                    },
                    theoryData);

                foreach (var x509KeyTuple in AsymmetricSignatureTestData.X509SecurityKeys)
                    AsymmetricSignatureTestData.AddRsaAlgorithmVariations(new SignatureProviderTheoryData
                    {
                        SigningKey = x509KeyTuple.Item1,
                        TestId = x509KeyTuple.Item3,
                        VerifyKey = x509KeyTuple.Item2
                    },
                    theoryData);

                return theoryData;
            }
        }
    }
}

#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
