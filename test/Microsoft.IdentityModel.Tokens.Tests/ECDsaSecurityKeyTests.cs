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
using Microsoft.IdentityModel.TestUtils;
using Xunit;

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant

namespace Microsoft.IdentityModel.Tokens.Tests
{
    public class ECDsaSecurityKeyTests
    {
        [Fact]
        public void Constructor()
        {

            // testing constructor that takes ECDsa instance
            ECDsaSecurityKeyConstructorWithEcdsa(null, ExpectedException.ArgumentNullException("ecdsa"));
#if !NET_CORE
            ECDsaSecurityKeyConstructorWithEcdsa(new ECDsaCng(), ExpectedException.NoExceptionExpected);
            var ecdsaSecurityKey = new ECDsaSecurityKey(new ECDsaCng());
#elif NET_CORE
            ECDsaSecurityKeyConstructorWithEcdsa(ECDsa.Create(), ExpectedException.NoExceptionExpected);
            var ecdsaSecurityKey = new ECDsaSecurityKey(ECDsa.Create());
#endif
            Assert.True(ecdsaSecurityKey.PrivateKeyStatus == PrivateKeyStatus.Unknown, "ecdsaSecurityKey.FoundPrivateKey is unknown");
        }

        private void ECDsaSecurityKeyConstructorWithEcdsa(ECDsa ecdsa, ExpectedException ee)
        {
            try
            {
                var ecdsaSecurityKey = new ECDsaSecurityKey(ecdsa);
                ee.ProcessNoException();
            }
            catch (Exception exception)
            {
                ee.ProcessException(exception);
            }
        }

        [Fact]
        public void Defaults()
        {
            // there are no defaults.
        }

        [Theory, MemberData(nameof(IsSupportedAlgDataSet))]
        public void IsSupportedAlgorithm(ECDsaSecurityKey key, string alg, bool expectedResult)
        {
            if (key.CryptoProviderFactory.IsSupportedAlgorithm(alg, key) != expectedResult)
                Assert.True(false, string.Format("{0} failed with alg: {1}. ExpectedResult: {2}", key, alg, expectedResult));
        }

        public static TheoryData<ECDsaSecurityKey, string, bool> IsSupportedAlgDataSet
        {
            get
            {
                var dataset = new TheoryData<ECDsaSecurityKey, string, bool>();
                dataset.Add(KeyingMaterial.Ecdsa256Key, SecurityAlgorithms.EcdsaSha256, true);
                dataset.Add(KeyingMaterial.Ecdsa256Key_Public, SecurityAlgorithms.EcdsaSha256Signature, true);
                dataset.Add(KeyingMaterial.Ecdsa384Key, SecurityAlgorithms.Aes128Encryption, false);
                dataset.Add(KeyingMaterial.Ecdsa521Key, SecurityAlgorithms.EcdsaSha384, true);
                ECDsaSecurityKey testKey = new ECDsaSecurityKey(KeyingMaterial.Ecdsa256Key.ECDsa);
                testKey.CryptoProviderFactory = new CustomCryptoProviderFactory(new string[] { SecurityAlgorithms.RsaSsaPssSha256Signature });
                dataset.Add(testKey, SecurityAlgorithms.RsaSsaPssSha256Signature, true);
                return dataset;

            }
        }

        [Fact]
        public void CanComputeJwkThumbprint()
        {
#if NET_CORE
            Assert.True(KeyingMaterial.Ecdsa256Key.CanComputeJwkThumbprint(), "Couldn't compute JWK thumbprint on an ECDsaSecurityKey on .NET Core.");
#else
            Assert.False(KeyingMaterial.Ecdsa256Key.CanComputeJwkThumbprint(), "ECDsaSecurityKey shouldn't be able to compute JWK thumbprint on Deskop (non-netstandard2.0 target).");
#endif
        }
    }
}

#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
