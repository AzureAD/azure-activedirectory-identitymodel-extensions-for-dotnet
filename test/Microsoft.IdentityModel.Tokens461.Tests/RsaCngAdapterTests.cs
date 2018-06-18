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
using System.Text;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tests;
using Microsoft.IdentityModel.Tokens;
using Xunit;

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant

namespace Microsoft.IdentityModel.Tokens.Tests
{
    public class RsaAdapterTests
    {
        [Theory, MemberData(nameof(RsaCngAdapterTestTheoryData))]
        public void RsaCngAdapterTest(RsaCngAdapterTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.RsaCngAdapterTest", theoryData);

            var cert = KeyingMaterial.CertSelfSigned2048_SHA256;

            var rsaCapiPrivateKey = new RsaSecurityKey(cert.PrivateKey as RSA);
            var rsaCapiPublicKey = new RsaSecurityKey(cert.PublicKey.Key as RSA);
            var clearBytes = Encoding.UTF8.GetBytes("blue star");
            byte[] capiSignatureBytes = null;

            AsymmetricSignatureProvider providerCapiPrivate = null;
            AsymmetricSignatureProvider providerCapiPublic = null;

            // create CAPI providers
            try
            {
                providerCapiPrivate = new AsymmetricSignatureProvider(rsaCapiPrivateKey, theoryData.Algorithm, true);
                capiSignatureBytes = providerCapiPrivate.Sign(clearBytes);
                providerCapiPublic = new AsymmetricSignatureProvider(rsaCapiPublicKey, theoryData.Algorithm, false);
                if (!providerCapiPublic.Verify(clearBytes, capiSignatureBytes))
                    context.AddDiff("providerCapiPublic.Verify(clearBytes, capiSignatureBytes)");
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            var rsaCngPrivateKey = new RsaSecurityKey(cert.GetRSAPrivateKey());
            var rsaCngPublicKey = new RsaSecurityKey(cert.GetRSAPublicKey());
            byte[] cngSignatureBytes = null;
            byte[] cngSignatureBytesByFactory = null;

            // create private signing
            AsymmetricSignatureProvider providerCngPrivate = null;
            try
            {
                providerCngPrivate = new AsymmetricSignatureProvider(rsaCngPrivateKey, theoryData.Algorithm, true);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            // create private signing with CryptoProviderFactory.Default
            SignatureProvider providerCngPrivateByFactory = null;
            try
            {
                providerCngPrivateByFactory = CryptoProviderFactory.Default.CreateForSigning(rsaCngPrivateKey, theoryData.Algorithm);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            // create public verifying
            AsymmetricSignatureProvider providerCngPublic = null;
            try
            {
                providerCngPublic = new AsymmetricSignatureProvider(rsaCngPublicKey, theoryData.Algorithm, false);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            // create public verifying with CryptoProviderFactory.Default
            SignatureProvider providerCngPublicByFactory = null;
            try
            {
                providerCngPublicByFactory = CryptoProviderFactory.Default.CreateForVerifying(rsaCngPublicKey, theoryData.Algorithm);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            try
            {
                cngSignatureBytes = providerCngPrivate.Sign(clearBytes);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            // cngByFactory Sign
            try
            {
                cngSignatureBytesByFactory = providerCngPrivateByFactory.Sign(clearBytes);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            // CngPublic -> CngPrivate validates
            try
            {
                var cngVerify = providerCngPublic.Verify(clearBytes, cngSignatureBytes);
                if (!cngVerify)
                    context.AddDiff($"cngVerify = providerCngPublic.Verify(clearBytes, cngSignatureBytes) == false.");
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            // CngPublicByFactory -> CngPrivate validates
            try
            {
                var cngVerify = providerCngPublicByFactory.Verify(clearBytes, cngSignatureBytes);
                if (!cngVerify)
                    context.AddDiff($"cngVerify = providerCngPublicByFactory.Verify(clearBytes, cngSignatureBytes) == false.");
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            // CngPublic -> CAPI validates
            try
            {
                var cngVerify = providerCngPublic.Verify(clearBytes, capiSignatureBytes);
                if (!cngVerify)
                    context.AddDiff($"cngVerify = providerCngPublic.Verify(clearBytes, capiSignatureBytes) == false.");
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            // CngPublicByFactory -> CAPI validates
            try
            {
                var verify = providerCngPublicByFactory.Verify(clearBytes, capiSignatureBytes);
                if (!verify)
                    context.AddDiff($"verify = providerCngPublicByFactory.Verify(clearBytes, capiSignatureBytes) == false.");
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            // CAPIPublic -> Cng validates
            try
            {
                var verify = providerCapiPublic.Verify(clearBytes, cngSignatureBytes);
                if (!verify)
                    context.AddDiff($"verify = providerCapiPublic.Verify(clearBytes, cngSignatureBytes) == false.");
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            // CAPIPublic -> CngByFactory validates
            try
            {
                var verify = providerCapiPublic.Verify(clearBytes, cngSignatureBytesByFactory);
                if (!verify)
                    context.AddDiff($"verify = providerCapiPublic.Verify(clearBytes, cngSignatureBytesByFactory) == false.");
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }


        public static TheoryData<RsaCngAdapterTheoryData> RsaCngAdapterTestTheoryData
        {
            get
            {
                return new TheoryData<RsaCngAdapterTheoryData>
                {
                    new RsaCngAdapterTheoryData
                    {
                        Algorithm = SecurityAlgorithms.RsaSha256Signature,
                        First = true,
                        TestId = "Test1"
                    },
                    new RsaCngAdapterTheoryData
                    {

                        Algorithm = SecurityAlgorithms.RsaSha256,
                        TestId = "Test2"
                    },
                    new RsaCngAdapterTheoryData
                    {

                        Algorithm = SecurityAlgorithms.RsaSha384Signature,
                        TestId = "Test3"
                    },
                    new RsaCngAdapterTheoryData
                    {

                        Algorithm = SecurityAlgorithms.RsaSha384,
                        TestId = "Test4"
                    },
                    new RsaCngAdapterTheoryData
                    {

                        Algorithm = SecurityAlgorithms.RsaSha512Signature,
                        TestId = "Test5"
                    },
                    new RsaCngAdapterTheoryData
                    {

                        Algorithm = SecurityAlgorithms.RsaSha512,
                        TestId = "Test6"
                    },
                };
            }
        }
    }

    public class RsaCngAdapterTheoryData : TheoryDataBase
    {
        public string Algorithm { get; set; }
    }
}

#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
