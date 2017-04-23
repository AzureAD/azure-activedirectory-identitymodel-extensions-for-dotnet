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
using Xunit;

namespace Microsoft.IdentityModel.Tokens.Tests
{
    /// <summary>
    /// Tests for AuthenticatedEncryptionProvider Extensibility
    /// </summary>
    public class AuthenticatedEncryptionProviderExtensibilityTests
    {
        [Fact]
        public void Constructor()
        {
            var provider = new DerivedAuthenticatedEncryptionProvider(Default.SymmetricEncryptionKey256, SecurityAlgorithms.Aes128CbcHmacSha256);
            Assert.True(provider.GetKeyBytesCalled);
            Assert.True(provider.IsSupportedAlgorithmCalled);
            Assert.True(provider.ValidateKeySizeCalled);
        }

        [Fact]
        public void DecryptVirtual()
        {
            var provider = new AuthenticatedEncryptionProvider(Default.SymmetricEncryptionKey256, SecurityAlgorithms.Aes128CbcHmacSha256);
            var authenticatedData = Guid.NewGuid().ToByteArray();
            var results = provider.Encrypt(Guid.NewGuid().ToByteArray(), authenticatedData);
            var derivedProvider = new DerivedAuthenticatedEncryptionProvider(Default.SymmetricEncryptionKey256, SecurityAlgorithms.Aes128CbcHmacSha256);
            derivedProvider.Decrypt(results.Ciphertext, authenticatedData, results.IV, results.AuthenticationTag);
            Assert.True(derivedProvider.DecryptCalled);
        }

        [Fact]
        public void EncryptVirtual()
        {
            var provider = new DerivedAuthenticatedEncryptionProvider(Default.SymmetricEncryptionKey256, SecurityAlgorithms.Aes128CbcHmacSha256);
            provider.Encrypt(Guid.NewGuid().ToByteArray(), Guid.NewGuid().ToByteArray());
            Assert.True(provider.EncryptCalled);
        }
#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("GetKeyBytesTheoryData")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void GetKeyBytes(AuthenticatedEncryptionTestParams theoryParams)
        {
            try
            {
                var provider = theoryParams.Provider as DerivedAuthenticatedEncryptionProvider;
                var result = provider.GetKeyBytesPublic(theoryParams.DecryptKey);
                Assert.True(Utility.AreEqual(result, theoryParams.Bytes));
                theoryParams.EE.ProcessNoException();
            }
            catch (Exception ex)
            {
                theoryParams.EE.ProcessException(ex);
            }
        }

        public static TheoryData<AuthenticatedEncryptionTestParams> GetKeyBytesTheoryData()
        {
            var theoryData = new TheoryData<AuthenticatedEncryptionTestParams>();

            theoryData.Add(new AuthenticatedEncryptionTestParams
            {
                Bytes = Default.SymmetricEncryptionKey256.Key,
                DecryptKey = Default.SymmetricEncryptionKey256,
                EE = ExpectedException.NoExceptionExpected,
                Provider = new DerivedAuthenticatedEncryptionProvider(),
                TestId = "Test1"
            });

            theoryData.Add(new AuthenticatedEncryptionTestParams
            {
                DecryptKey = null,
                EE = ExpectedException.ArgumentNullException(),
                Provider = new DerivedAuthenticatedEncryptionProvider(),
                TestId = "Test2"
            });

            theoryData.Add(new AuthenticatedEncryptionTestParams
            {
                DecryptKey = Default.AsymmetricSigningKey,
                EE = ExpectedException.ArgumentException("IDX10667:"),
                Provider = new DerivedAuthenticatedEncryptionProvider(),
                TestId = "Test3"
            });

            theoryData.Add(new AuthenticatedEncryptionTestParams
            {
                Bytes = KeyingMaterial.JsonWebKeySymmetricBytes256,
                DecryptKey = KeyingMaterial.JsonWebKeySymmetric256,
                EE = ExpectedException.NoExceptionExpected,
                Provider = new DerivedAuthenticatedEncryptionProvider(),
                TestId = "Test1"
            });

            return theoryData;
        }

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("IsSupportedAlgorithmTheoryData")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void IsSupportedAlgorithm(AuthenticatedEncryptionTestParams theoryParams)
        {
            try
            {
                var provider = theoryParams.Provider as DerivedAuthenticatedEncryptionProvider;
                var result = provider.IsSupportedAlgorithmPublic(theoryParams.DecryptKey, theoryParams.DecryptAlgorithm);

                Assert.True(result == theoryParams.IsSupportedAlgorithm);
                theoryParams.EE.ProcessNoException();
            }
            catch (Exception ex)
            {
                theoryParams.EE.ProcessException(ex);
            }
        }

        public static TheoryData<AuthenticatedEncryptionTestParams> IsSupportedAlgorithmTheoryData()
        {
            var theoryData = new TheoryData<AuthenticatedEncryptionTestParams>();

            theoryData.Add(new AuthenticatedEncryptionTestParams
            {
                DecryptAlgorithm = SecurityAlgorithms.Aes128CbcHmacSha256,
                DecryptKey = null,
                EE = ExpectedException.NoExceptionExpected,
                IsSupportedAlgorithm = false,
                Provider = new DerivedAuthenticatedEncryptionProvider(Default.SymmetricEncryptionKey256, SecurityAlgorithms.Aes128CbcHmacSha256),
                TestId = "Test1"
            });

            theoryData.Add(new AuthenticatedEncryptionTestParams
            {
                DecryptAlgorithm = SecurityAlgorithms.Aes128CbcHmacSha256,
                DecryptKey = null,
                EE = ExpectedException.NoExceptionExpected,
                IsSupportedAlgorithm = false,
                Provider = new DerivedAuthenticatedEncryptionProvider(Default.SymmetricEncryptionKey256, SecurityAlgorithms.Aes128CbcHmacSha256),
                TestId = "Test2"
            });

            theoryData.Add(new AuthenticatedEncryptionTestParams
            {
                DecryptAlgorithm = SecurityAlgorithms.Aes128Encryption,
                DecryptKey = Default.SymmetricEncryptionKey256,
                EE = ExpectedException.NoExceptionExpected,
                IsSupportedAlgorithm = false,
                Provider = new DerivedAuthenticatedEncryptionProvider(Default.SymmetricEncryptionKey256, SecurityAlgorithms.Aes128CbcHmacSha256),
                TestId = "Test3"
            });

            theoryData.Add(new AuthenticatedEncryptionTestParams
            {
                DecryptAlgorithm = SecurityAlgorithms.Aes128CbcHmacSha256,
                DecryptKey = Default.AsymmetricSigningKey,
                EE = ExpectedException.NoExceptionExpected,
                IsSupportedAlgorithm = false,
                Provider = new DerivedAuthenticatedEncryptionProvider(Default.SymmetricEncryptionKey256, SecurityAlgorithms.Aes128CbcHmacSha256),
                TestId = "Test4"
            });

            return theoryData;
        }

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("ValidateKeySizeTheoryData")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void ValidateKeySize(AuthenticatedEncryptionTestParams theoryParams)
        {
            try
            {
                var provider = theoryParams.Provider as DerivedAuthenticatedEncryptionProvider;
                provider.ValidateKeySizePublic(theoryParams.DecryptKey, theoryParams.DecryptAlgorithm);
                theoryParams.EE.ProcessNoException();
            }
            catch (Exception ex)
            {
                theoryParams.EE.ProcessException(ex);
            }
        }

        public static TheoryData<AuthenticatedEncryptionTestParams> ValidateKeySizeTheoryData()
        {
            var theoryData = new TheoryData<AuthenticatedEncryptionTestParams>();

            theoryData.Add(new AuthenticatedEncryptionTestParams
            {
                DecryptAlgorithm = SecurityAlgorithms.Aes128CbcHmacSha256,
                DecryptKey = null,
                EE = ExpectedException.ArgumentNullException(),
                Provider = new DerivedAuthenticatedEncryptionProvider(),
                TestId = "Test1"
            });

            theoryData.Add(new AuthenticatedEncryptionTestParams
            {
                DecryptAlgorithm = null,
                DecryptKey = Default.SymmetricEncryptionKey256,
                EE = ExpectedException.ArgumentNullException(),
                Provider = new DerivedAuthenticatedEncryptionProvider(),
                TestId = "Test2"
            });

            theoryData.Add(new AuthenticatedEncryptionTestParams
            {
                DecryptAlgorithm = string.Empty,
                DecryptKey = Default.SymmetricEncryptionKey256,
                EE = ExpectedException.ArgumentNullException(),
                Provider = new DerivedAuthenticatedEncryptionProvider(),
                TestId = "Test3"
            });

            theoryData.Add(new AuthenticatedEncryptionTestParams
            {
                DecryptAlgorithm = SecurityAlgorithms.Aes192KeyWrap,
                DecryptKey = Default.SymmetricEncryptionKey256,
                EE = ExpectedException.ArgumentException("IDX10652:"),
                Provider = new DerivedAuthenticatedEncryptionProvider(),
                TestId = "Test4"
            });

            return theoryData;
        }
    }
}
