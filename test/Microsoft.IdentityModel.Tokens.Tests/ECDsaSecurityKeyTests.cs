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
using Xunit;

namespace Microsoft.IdentityModel.Tokens.Tests
{
    public class ECDsaSecurityKeyTests
    {
        [Fact(DisplayName = "ECDsaSecurityKeyTests: Constructor")]
        public void Constructor()
        {
            // testing constructor that takes ECDsa instance
            ECDsaSecurityKeyConstructorWithEcdsa(null, ExpectedException.ArgumentNullException("ecdsa"));
            ECDsaSecurityKeyConstructorWithEcdsa(new ECDsaCng(), ExpectedException.NoExceptionExpected);
            var ecdsaSecurityKey = new ECDsaSecurityKey(new ECDsaCng());
            Assert.True(ecdsaSecurityKey.HasPrivateKey, "ecdsaSecurityKey.HasPrivate is false");
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

        [Fact(DisplayName = "ECDsaSecurityKeyTests: Defaults")]
        public void Defaults()
        {
            // there are no defaults.
        }

        [Fact(DisplayName = "EcdsaSecurityKeyTests: IsSupportedAlgorithm")]
        public void IsSupportedAlgorithm()
        {
            Assert.True(KeyingMaterial.ECDsa256Key.IsSupportedAlgorithm(SecurityAlgorithms.EcdsaSha256), "KeyingMaterial.ECDsa256Key.IsSupportedAlgorithm returned false for ecdsasha256");
            Assert.True(KeyingMaterial.ECDsa256Key_Public.IsSupportedAlgorithm(SecurityAlgorithms.EcdsaSha256Signature), "KeyingMaterial.ECDsa256Key_Public.IsSupportedAlgorithm returned false for ecdsasha256");
            Assert.True(!KeyingMaterial.ECDsa384Key.IsSupportedAlgorithm(SecurityAlgorithms.Aes128Encryption), "KeyingMaterial.ECDsa384Key should not support Aes128Encryption");
            Assert.True(KeyingMaterial.ECDsa521Key.IsSupportedAlgorithm(SecurityAlgorithms.EcdsaSha384), "KeyingMaterial.ECDsa521Key.IsSupportedAlgorithm returned false for EcdsaSha384");
        }
    }
}
