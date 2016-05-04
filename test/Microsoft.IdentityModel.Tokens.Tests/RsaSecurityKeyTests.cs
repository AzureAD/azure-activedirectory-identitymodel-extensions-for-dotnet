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
using System.Globalization;
using System.Security.Cryptography;
using Xunit;

namespace Microsoft.IdentityModel.Tokens.Tests
{
    public class RsaSecurityKeyTests
    {
        [Fact(DisplayName = "RsaSecurityKeyTests: Constructor")]
        public void Constructor()
        {
            // testing constructor that takes rsa parameters
            RsaSecurityKeyConstructor(KeyingMaterial.RsaParameters_1024, ExpectedException.NoExceptionExpected);
            RsaSecurityKeyConstructor(KeyingMaterial.RsaParameters_1024_Public, ExpectedException.NoExceptionExpected);

            // missing modulus or exponent
            RsaSecurityKeyConstructor(KeyingMaterial.RsaParameters_2048_MissingExponent, ExpectedException.ArgumentException("IDX10700"));
            RsaSecurityKeyConstructor(KeyingMaterial.RsaParameters_2048_MissingModulus, ExpectedException.ArgumentException("IDX10700"));

            // testing constructor that takes Rsa instance
            RsaSecurityKeyConstructorWithRsa(null, ExpectedException.ArgumentNullException("rsa"));

            RSA rsaCsp_2048 = new RSACryptoServiceProvider();
            rsaCsp_2048.ImportParameters(KeyingMaterial.RsaParameters_2048);
            RSA rsaCsp_2048_Public = new RSACryptoServiceProvider();
            rsaCsp_2048_Public.ImportParameters(KeyingMaterial.RsaParameters_2048_Public);

            RsaSecurityKeyConstructorWithRsa(rsaCsp_2048, ExpectedException.NoExceptionExpected);
            RsaSecurityKeyConstructorWithRsa(rsaCsp_2048_Public, ExpectedException.NoExceptionExpected);
        }

        private void RsaSecurityKeyConstructor(RSAParameters parameters, ExpectedException ee)
        {
            try
            {
                var rsaSecurityKey = new RsaSecurityKey(parameters);
                ee.ProcessNoException();
            }
            catch (Exception exception)
            {
                ee.ProcessException(exception);
            }
        }

        private void RsaSecurityKeyConstructorWithRsa(RSA rsa, ExpectedException ee)
        {
            try
            {
                var rsaSecurityKey = new RsaSecurityKey(rsa);
                ee.ProcessNoException();
            }
            catch (Exception exception)
            {
                ee.ProcessException(exception);
            }
        }

        [Fact(DisplayName = "RsaSecurityKeyTests: HasPrivateKey")]
        public void HasPrivateKey()
        {
            Assert.True(KeyingMaterial.RsaSecurityKeyWithCspProvider_2048.HasPrivateKey, "KeyingMaterial.RsaSecurityKeyWithCspProvider_2048 does not have the private key.");
            Assert.False(KeyingMaterial.RsaSecurityKeyWithCspProvider_2048_Public.HasPrivateKey, "KeyingMaterial.RsaSecurityKeyWithCspProvider_2048_Public has the private key.");
#if NETCOREAPP1_0
            Assert.True(KeyingMaterial.RsaSecurityKeyWithCngProvider_2048.HasPrivateKey, "KeyingMaterial.RsaSecurityKeyWithCngProvider_2048 does not have the private key.");
            Assert.False(KeyingMaterial.RsaSecurityKeyWithCngProvider_2048_Public.HasPrivateKey, "KeyingMaterial.RsaSecurityKeyWithCngProvider_2048_Public has the private key.");
#endif
            Assert.True(KeyingMaterial.RsaSecurityKey_2048.HasPrivateKey, "KeyingMaterial.RsaSecurityKey_2048 does not have the private key.");
            Assert.False(KeyingMaterial.RsaSecurityKey_2048_Public.HasPrivateKey, "KeyingMaterial.RsaSecurityKey_2048_Public has the private key.");
        }

        [Fact(DisplayName = "RsaSecurityKeyTests: KeySize")]
        public void KeySize()
        {
            Assert.True(KeyingMaterial.RsaSecurityKeyWithCspProvider_2048.KeySize == 2048, string.Format(CultureInfo.InvariantCulture, "Keysize '{0}' != 2048", KeyingMaterial.RsaSecurityKeyWithCspProvider_2048.KeySize));
            Assert.True(KeyingMaterial.RsaSecurityKeyWithCspProvider_2048_Public.KeySize == 2048, string.Format(CultureInfo.InvariantCulture, "Keysize '{0}' != 2048", KeyingMaterial.RsaSecurityKeyWithCspProvider_2048.KeySize));
            Assert.True(KeyingMaterial.RsaSecurityKey_2048.KeySize == 2048, string.Format(CultureInfo.InvariantCulture, "Keysize '{0}' != 2048", KeyingMaterial.RsaSecurityKey_2048.KeySize));
            Assert.True(KeyingMaterial.RsaSecurityKey_4096.KeySize == 4096, string.Format(CultureInfo.InvariantCulture, "Keysize '{0}' != 4096", KeyingMaterial.RsaSecurityKey_4096.KeySize));
        }

        [Fact(DisplayName = "RsaSecurityKeyTests: IsSupportedAlgorithm")]
        public void IsSupportedAlgorithm()
        {
            Assert.True(KeyingMaterial.RsaSecurityKeyWithCspProvider_2048.IsSupportedAlgorithm(SecurityAlgorithms.RsaSha256Signature), "KeyingMaterial.RsaSecurityKeyWithCspProvider_2048.IsSupportedAlgorithm returned false for rsasha256");
            Assert.True(KeyingMaterial.RsaSecurityKeyWithCspProvider_2048_Public.IsSupportedAlgorithm(SecurityAlgorithms.RsaSha256), "KeyingMaterial.RsaSecurityKeyWithCspProvider_2048_Public.IsSupportedAlgorithm returned false for rsasha256");
            Assert.True(!KeyingMaterial.RsaSecurityKeyWithCspProvider_2048.IsSupportedAlgorithm(SecurityAlgorithms.EcdsaSha256), "KeyingMaterial.RsaSecurityKeyWithCspProvider_2048 should not support ecdsa256");
            Assert.True(KeyingMaterial.RsaSecurityKey_2048.IsSupportedAlgorithm(SecurityAlgorithms.RsaSha256Signature), "KeyingMaterial.RsaSecurityKey_2048.IsSupportedAlgorithm returned false for rsasha256");
        }
    }
}
