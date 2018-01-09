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

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant

namespace Microsoft.IdentityModel.Tokens.Tests
{
    /// <summary>
    /// Tests for KeyWrapProvider
    /// Constructors
    ///     - validate parameters (null, empty)
    ///     - algorithms supported
    ///     - properties are set correctly (Algorithm, Context, Key)
    /// WrapKey/UnwrapKey
    ///     - positive tests for keys Algorithms supported.
    ///     - parameter validation for WrapKey
    /// UnwrapKey
    ///     - parameter validataion for UnwrapKey
    /// UnwrapKeyMismatch
    ///     - negative tests for switching (keys, algorithms)
    /// WrapKeyVirtual
    ///     - tests virtual method was called
    /// UnwrapKeyVirtual
    ///     - tests virtual method was called
    /// </summary>
    public class RsaKeyWrapProviderTests
    {
        [Theory, MemberData(nameof(RsaKeyWrapConstructorTheoryData))]
        public void Constructors(string testId, SecurityKey key, string algorithm, bool isDecrypt, ExpectedException ee)
        {
            TestUtilities.WriteHeader("Constructors - " + testId, true);
            try
            {
                var context = Guid.NewGuid().ToString();
                var provider = new RsaKeyWrapProvider(key, algorithm, isDecrypt) { Context = context };

                ee.ProcessNoException();

                Assert.Equal(provider.Algorithm, algorithm);
                Assert.Equal(provider.Context, context);
                Assert.True(ReferenceEquals(provider.Key, key));
            }
            catch (Exception ex)
            {
                ee.ProcessException(ex);
            }
        }

        public static TheoryData<string, SecurityKey, string, bool, ExpectedException> RsaKeyWrapConstructorTheoryData()
        {
            var theoryData = new TheoryData<string, SecurityKey, string, bool, ExpectedException>();

            theoryData.Add(
                "SecurityKey_NULL",
                null,
                null,
                false,
                ExpectedException.ArgumentNullException());

            theoryData.Add(
                "Algorithm_NULL",
                KeyingMaterial.RsaSecurityKey_2048,
                null,
                false,
                ExpectedException.ArgumentNullException());

            theoryData.Add(
                "KeyTooSmall_1024",
                KeyingMaterial.RsaSecurityKey_1024,
                SecurityAlgorithms.RsaOAEP,
                false,
                ExpectedException.NotSupportedException("IDX10661:"));

            theoryData.Add(
                "KeyDoesNotRightType",
                KeyingMaterial.RsaSecurityKey_2048,
                SecurityAlgorithms.Aes128KW,
                false,
                ExpectedException.NotSupportedException("IDX10661:"));

            theoryData.Add(
                "KeyAlgorithmMatch",
                KeyingMaterial.RsaSecurityKey_2048,
                SecurityAlgorithms.RsaPKCS1,
                false,
                ExpectedException.NoExceptionExpected);

            theoryData.Add(
                "X509AlorithmMatch",
                KeyingMaterial.X509SecurityKey2,
                SecurityAlgorithms.RsaPKCS1,
                false,
                ExpectedException.NoExceptionExpected);

            theoryData.Add(
                "JWK_RSA",
                KeyingMaterial.JsonWebKeyRsa256,
                SecurityAlgorithms.RsaPKCS1,
                true,
                ExpectedException.NoExceptionExpected);

            theoryData.Add(
                "OnlyRSAPublicKeyProvided",
                KeyingMaterial.JsonWebKeyRsa256Public,
                SecurityAlgorithms.RsaPKCS1,
                true,
                ExpectedException.NoExceptionExpected);

            return theoryData;
        }

        [Fact]
        public void RsaKeyWrapProviderDispose()
        {
            SecurityKey key = KeyingMaterial.RsaSecurityKey_2048;
            var provider = new RsaKeyWrapProvider(key, SecurityAlgorithms.RsaPKCS1, false);
            key.CryptoProviderFactory.ReleaseRsaKeyWrapProvider(provider);
        }

        [Fact]
        public void UnwrapKey()
        {
            var provider = new DerivedRsaKeyWrapProvider(KeyingMaterial.RsaSecurityKey_2048, SecurityAlgorithms.RsaPKCS1, true);
            var keyBytes = provider.WrapKey(Guid.NewGuid().ToByteArray());
            provider.UnwrapKey(keyBytes);
            Assert.True(provider.UnwrapKeyCalled);
            Assert.True(provider.WrapKeyCalled);
        }

        [Theory, MemberData(nameof(RsaUnwrapMismatchTheoryData))]
        public void RsaUnwrapMismatch(RsaKeyWrapTestParams theoryParams)
        {
            try
            {
                var encryptProvider = new RsaKeyWrapProvider(theoryParams.EncryptKey, theoryParams.EncryptAlgorithm, false);
                byte[] keyToWrap = Guid.NewGuid().ToByteArray();
                var wrappedKey = encryptProvider.WrapKey(keyToWrap);
                var decryptProvider = new RsaKeyWrapProvider(theoryParams.DecryptKey, theoryParams.DecryptAlgorithm, true);
                byte[] unwrappedKey = decryptProvider.UnwrapKey(wrappedKey);
                theoryParams.EE.ProcessNoException();
            }
            catch (Exception ex)
            {
                theoryParams.EE.ProcessException(ex);
            }
        }

        public static TheoryData<RsaKeyWrapTestParams> RsaUnwrapMismatchTheoryData()
        {
            var theoryData = new TheoryData<RsaKeyWrapTestParams>();

            theoryData.Add(new RsaKeyWrapTestParams
            {
                EncryptAlgorithm = SecurityAlgorithms.RsaPKCS1,
                EncryptKey = KeyingMaterial.RsaSecurityKey_2048_Public,
                DecryptAlgorithm = SecurityAlgorithms.RsaOAEP,
                DecryptKey = KeyingMaterial.RsaSecurityKey_2048,
                EE = ExpectedException.KeyWrapException("IDX10659:"),
                TestId = "RSAUnwrapAlgorithmMismatch_RsaPKCS1_RsaOAEP"
            });

            theoryData.Add(new RsaKeyWrapTestParams
            {
                EncryptAlgorithm = SecurityAlgorithms.RsaOAEP,
                EncryptKey = KeyingMaterial.RsaSecurityKey_4096_Public,
                DecryptAlgorithm = SecurityAlgorithms.RsaOAEP,
                DecryptKey = KeyingMaterial.RsaSecurityKey_2048,
                EE = ExpectedException.KeyWrapException("IDX10659:"),
                TestId = "RSAUnwrapKeyMismatch_RsaSecurityKey_4096_RsaSecurityKey_2048"
            });

            theoryData.Add(new RsaKeyWrapTestParams
            {
                EncryptAlgorithm = SecurityAlgorithms.RsaPKCS1,
                EncryptKey = KeyingMaterial.RsaSecurityKey_4096_Public,
                DecryptAlgorithm = SecurityAlgorithms.RsaOAEP,
                DecryptKey = KeyingMaterial.RsaSecurityKey_2048,
                EE = ExpectedException.KeyWrapException("IDX10659:"),
                TestId = "RSAUnwrapAlgorithmAndKeyMismatch_RsaPKCS1_RsaOAEP_RsaSecurityKey_4096_RsaSecurityKey_2048"
            });

            return theoryData;
        }

        [Theory, MemberData(nameof(RsaUnwrapTamperedTheoryData))]
        public void RsaUnwrapTamperedData(RsaKeyWrapTestParams theoryParams)
        {
            try
            {
                theoryParams.Provider.UnwrapKey(theoryParams.WrappedKey);
                theoryParams.EE.ProcessNoException();
            }
            catch (Exception ex)
            {
                theoryParams.EE.ProcessException(ex);
            }
        }

        public static TheoryData<RsaKeyWrapTestParams> RsaUnwrapTamperedTheoryData()
        {
            var theoryData = new TheoryData<RsaKeyWrapTestParams>();

            // tampering: wrapped key
            AddUnwrapTamperedTheoryData(
                "Test1",
                KeyingMaterial.RsaSecurityKey_2048_Public,
                KeyingMaterial.RsaSecurityKey_2048,
                SecurityAlgorithms.RsaPKCS1, theoryData);

            AddUnwrapTamperedTheoryData(
                "Test2",
                KeyingMaterial.RsaSecurityKey_2048_Public,
                KeyingMaterial.RsaSecurityKey_2048,
                SecurityAlgorithms.RsaOAEP, theoryData);

            return theoryData;
        }

        private static void AddUnwrapTamperedTheoryData(
            string testId,
            SecurityKey encrtyptKey,
            SecurityKey decryptKey,
            string algorithm,
            TheoryData<RsaKeyWrapTestParams> theoryData)
        {
            var keyToWrap = Guid.NewGuid().ToByteArray();
            var provider = new RsaKeyWrapProvider(encrtyptKey, algorithm, false);
            var wrappedKey = provider.WrapKey(keyToWrap);

            TestUtilities.XORBytes(wrappedKey);
            theoryData.Add(new RsaKeyWrapTestParams
            {
                DecryptAlgorithm = algorithm,
                DecryptKey = decryptKey,
                EE = ExpectedException.KeyWrapException("IDX10659:"),
                Provider = provider,
                WrappedKey = wrappedKey
            });
        }

        [Theory, MemberData(nameof(RsaUnwrapTheoryData))]
        public void RsaUnwrapParameterCheck(RsaKeyWrapTestParams theoryParams)
        {
            try
            {
                var provider = new RsaKeyWrapProvider(theoryParams.DecryptKey, theoryParams.DecryptAlgorithm, true);
                provider.UnwrapKey(theoryParams.WrappedKey);

                theoryParams.EE.ProcessNoException();
            }
            catch (Exception ex)
            {
                theoryParams.EE.ProcessException(ex);
            }
        }

        public static TheoryData<RsaKeyWrapTestParams> RsaUnwrapTheoryData()
        {
            var theoryData = new TheoryData<RsaKeyWrapTestParams>();

            theoryData.Add(new RsaKeyWrapTestParams
            {
                DecryptAlgorithm = SecurityAlgorithms.RsaPKCS1,
                DecryptKey = KeyingMaterial.RsaSecurityKey_2048,
                WrappedKey = null,
                EE = ExpectedException.ArgumentNullException(),
                TestId = "NullKey"
            });

            theoryData.Add(new RsaKeyWrapTestParams
            {
                DecryptAlgorithm = SecurityAlgorithms.RsaPKCS1,
                DecryptKey = KeyingMaterial.RsaSecurityKey_2048,
                WrappedKey = new byte[0],
                EE = ExpectedException.ArgumentNullException(),
                TestId = "ZeroByteLength"
            });

            return theoryData;
        }

        [Theory, MemberData(nameof(RsaWrapUnwrapTheoryData))]
        public void RsaWrapUnwrapKey(RsaKeyWrapTestParams theoryParams)
        {
            try
            {
                var encryptProvider = new RsaKeyWrapProvider(theoryParams.EncryptKey, theoryParams.EncryptAlgorithm, false);
                var wrappedKey = encryptProvider.WrapKey(theoryParams.KeyToWrap);
                var decryptProvider = new DerivedRsaKeyWrapProvider(theoryParams.DecryptKey, theoryParams.DecryptAlgorithm, true);
                byte[] unwrappedKey = decryptProvider.UnwrapKey(wrappedKey);

                Assert.True(Utility.AreEqual(unwrappedKey, theoryParams.KeyToWrap), "theoryParams.KeyToWrap != unwrappedKey");

                theoryParams.EE.ProcessNoException();
            }
            catch (Exception ex)
            {
                theoryParams.EE.ProcessException(ex);
            }
        }

        public static TheoryData<RsaKeyWrapTestParams> RsaWrapUnwrapTheoryData()
        {
            var theoryData = new TheoryData<RsaKeyWrapTestParams>();

            // round trip positive tests
            AddWrapUnwrapTheoryData(
                "Test1",
                SecurityAlgorithms.RsaPKCS1,
                KeyingMaterial.RsaSecurityKey_2048_Public,
                KeyingMaterial.RsaSecurityKey_2048,
                theoryData);

            AddWrapUnwrapTheoryData(
                "Test2",
                SecurityAlgorithms.RsaOAEP,
                KeyingMaterial.RsaSecurityKey_2048_Public,
                KeyingMaterial.RsaSecurityKey_2048,
                theoryData);

            // Wrap parameter checking
            AddWrapParameterCheckTheoryData(
                "Test3",
                SecurityAlgorithms.RsaPKCS1,
                KeyingMaterial.RsaSecurityKey_2048_Public,
                KeyingMaterial.RsaSecurityKey_2048,
                null,
                ExpectedException.ArgumentNullException(),
                theoryData);

            return theoryData;
        }

        private static void AddWrapUnwrapTheoryData(
            string testId,
            string algorithm,
            SecurityKey encryptKey,
            SecurityKey decryptKey, TheoryData<RsaKeyWrapTestParams> theoryData)
        {
            theoryData.Add(new RsaKeyWrapTestParams
            {
                EncryptAlgorithm = algorithm,
                DecryptAlgorithm = algorithm,
                KeyToWrap = Guid.NewGuid().ToByteArray(),
                EE = ExpectedException.NoExceptionExpected,
                EncryptKey = encryptKey,
                DecryptKey = decryptKey,
                TestId = "AddWrapUnwrapTheoryData_" + testId
            });
        }

        private static void AddWrapParameterCheckTheoryData(
            string testId,
            string algorithm,
            SecurityKey encryptKey,
            SecurityKey decryptKey,
            byte[] keyToWrap,
            ExpectedException ee,
            TheoryData<RsaKeyWrapTestParams> theoryData)
        {
            theoryData.Add(new RsaKeyWrapTestParams
            {
                EncryptAlgorithm = algorithm,
                DecryptAlgorithm = algorithm,
                EncryptKey = encryptKey,
                DecryptKey = decryptKey,
                KeyToWrap = keyToWrap,
                EE = ee,
                TestId = testId
            });
        }

        public class RsaKeyWrapTestParams
        {
            public string DecryptAlgorithm { get; set; }
            public SecurityKey DecryptKey { get; set; }
            public string EncryptAlgorithm { get; set; }
            public ExpectedException EE { get; set; }
            public SecurityKey EncryptKey { get; set; }
            public byte[] KeyToWrap { get; set; }
            public byte[] WrappedKey { get; set; }
            public RsaKeyWrapProvider Provider { get; set; }
            public string TestId { get; set; }
        }
    }
}

#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
