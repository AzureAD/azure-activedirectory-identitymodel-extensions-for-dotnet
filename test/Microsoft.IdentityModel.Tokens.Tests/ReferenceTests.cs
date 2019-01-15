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
using Microsoft.IdentityModel.TestUtils;
using Xunit;

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant

namespace Microsoft.IdentityModel.Tokens.Tests
{
    /// <summary>
    /// Tests for references in specs
    /// https://tools.ietf.org/html/rfc7518#appendix-A.3
    /// </summary>
    public class ReferenceTests
    {

        [Theory, MemberData(nameof(AuthenticatedEncryptionTheoryData))]
        public void AuthenticatedEncryptionReferenceTest(AuthenticationEncryptionTestParams testParams)
        {
            var providerForEncryption = CryptoProviderFactory.Default.CreateAuthenticatedEncryptionProvider(testParams.EncryptionKey, testParams.Algorithm);
            var providerForDecryption = CryptoProviderFactory.Default.CreateAuthenticatedEncryptionProvider(testParams.DecryptionKey, testParams.Algorithm);
            var encryptionResult = providerForEncryption.Encrypt(testParams.Plaintext, testParams.AuthenticationData, testParams.IV);
            var plaintext = providerForDecryption.Decrypt(encryptionResult.Ciphertext, testParams.AuthenticationData, encryptionResult.IV, encryptionResult.AuthenticationTag);

            Assert.True(Utility.AreEqual(encryptionResult.IV, testParams.IV), "Utility.AreEqual(encryptionResult.IV, testParams.IV)");
            Assert.True(Utility.AreEqual(encryptionResult.AuthenticationTag, testParams.AuthenticationTag), "Utility.AreEqual(encryptionResult.AuthenticationTag, testParams.AuthenticationTag)");
            Assert.True(Utility.AreEqual(encryptionResult.Ciphertext, testParams.Ciphertext), "Utility.AreEqual(encryptionResult.Ciphertext, testParams.Ciphertext)");
            Assert.True(Utility.AreEqual(plaintext, testParams.Plaintext), "Utility.AreEqual(plaintext, testParams.Plaintext)");
        }

        public static TheoryData<AuthenticationEncryptionTestParams> AuthenticatedEncryptionTheoryData
        {
            get
            {
                var theoryData = new TheoryData<AuthenticationEncryptionTestParams>();

                theoryData.Add(new AuthenticationEncryptionTestParams
                {
                    Algorithm = AES_128_CBC_HMAC_SHA_256.Algorithm,
                    AuthenticationData = AES_128_CBC_HMAC_SHA_256.A,
                    AuthenticationTag = AES_128_CBC_HMAC_SHA_256.T,
                    Ciphertext = AES_128_CBC_HMAC_SHA_256.E,
                    DecryptionKey = new SymmetricSecurityKey(AES_128_CBC_HMAC_SHA_256.K) { KeyId = "DecryptionKey.AES_128_CBC_HMAC_SHA_256.K" },
                    EncryptionKey = new SymmetricSecurityKey(AES_128_CBC_HMAC_SHA_256.K) { KeyId = "EncryptionKey.AES_128_CBC_HMAC_SHA_256.K" },
                    IV = AES_128_CBC_HMAC_SHA_256.IV,
                    Plaintext = AES_128_CBC_HMAC_SHA_256.P,
                    TestId = "AES_128_CBC_HMAC_SHA_256"
                });

                theoryData.Add(new AuthenticationEncryptionTestParams
                {
                    Algorithm = AES_192_CBC_HMAC_SHA_384.Algorithm,
                    AuthenticationData = AES_192_CBC_HMAC_SHA_384.A,
                    AuthenticationTag = AES_192_CBC_HMAC_SHA_384.T,
                    Ciphertext = AES_192_CBC_HMAC_SHA_384.E,
                    DecryptionKey = new SymmetricSecurityKey(AES_192_CBC_HMAC_SHA_384.K) { KeyId = "DecryptionKey.AES_192_CBC_HMAC_SHA_384.K" },
                    EncryptionKey = new SymmetricSecurityKey(AES_192_CBC_HMAC_SHA_384.K) { KeyId = "EncryptionKey.AES_192_CBC_HMAC_SHA_384.K" },
                    IV = AES_192_CBC_HMAC_SHA_384.IV,
                    Plaintext = AES_192_CBC_HMAC_SHA_384.P,
                    TestId = "AES_192_CBC_HMAC_SHA_384"
                });

                theoryData.Add(new AuthenticationEncryptionTestParams
                {
                    Algorithm = AES_256_CBC_HMAC_SHA_512.Algorithm,
                    AuthenticationData = AES_256_CBC_HMAC_SHA_512.A,
                    AuthenticationTag = AES_256_CBC_HMAC_SHA_512.T,
                    Ciphertext = AES_256_CBC_HMAC_SHA_512.E,
                    DecryptionKey = new SymmetricSecurityKey(AES_256_CBC_HMAC_SHA_512.K) { KeyId = "DecryptionKey.AES_256_CBC_HMAC_SHA_512.K" },
                    EncryptionKey = new SymmetricSecurityKey(AES_256_CBC_HMAC_SHA_512.K) { KeyId = "EncryptionKey.AES_256_CBC_HMAC_SHA_512.K" },
                    IV = AES_256_CBC_HMAC_SHA_512.IV,
                    Plaintext = AES_256_CBC_HMAC_SHA_512.P,
                    TestId = "AES_256_CBC_HMAC_SHA_512"
                });

                return theoryData;
            }
        }

        public class AuthenticationEncryptionTestParams
        {
            public string Algorithm { get; set; }
            public byte[] AuthenticationData { get; set; }
            public byte[] AuthenticationTag { get; set; }
            public byte[] Ciphertext { get; set; }
            public SecurityKey DecryptionKey { get; set; }
            public SecurityKey EncryptionKey { get; set; }
            public byte[] IV { get; set; }
            public byte[] Plaintext { get; set; }
            public string TestId { get; set; }

            public override string ToString()
            {
                return TestId + ", " + Algorithm + ", " + EncryptionKey.KeyId + ", " + DecryptionKey.KeyId;
            }
        }

        [Theory, MemberData(nameof(KeyWrapTheoryData))]
        public void KeyWrapReferenceTest(KeyWrapTestParams testParams)
        {
            if (testParams.Algorithm.Equals(SecurityAlgorithms.Aes128KW, StringComparison.OrdinalIgnoreCase)
                || testParams.Algorithm.Equals(SecurityAlgorithms.Aes256KW, StringComparison.OrdinalIgnoreCase))
            {
                var keyWrapProvider = CryptoProviderFactory.Default.CreateKeyWrapProvider(testParams.Key, testParams.Algorithm);
                var wrappedKey = keyWrapProvider.WrapKey(testParams.KeyToWrap);
                Assert.True(Utility.AreEqual(wrappedKey, testParams.EncryptedKey), "Utility.AreEqual(wrappedKey, testParams.EncryptedKey)");
                Assert.Equal(Base64UrlEncoder.Encode(wrappedKey), testParams.EncodedEncryptedKey);

                byte[] unwrappedKey = keyWrapProvider.UnwrapKey(wrappedKey);
                Assert.True(Utility.AreEqual(unwrappedKey, testParams.KeyToWrap), "Utility.AreEqual(unwrappedKey, testParams.KeyToWrap)");
            }
            else if (testParams.Algorithm.Equals(SecurityAlgorithms.RsaOAEP, StringComparison.OrdinalIgnoreCase)
                    || testParams.Algorithm.Equals(SecurityAlgorithms.RsaPKCS1, StringComparison.OrdinalIgnoreCase))
            {
                var rsaKeyWrapProvider = CryptoProviderFactory.Default.CreateKeyWrapProvider(testParams.Key, testParams.Algorithm);
                byte[] unwrappedKey = rsaKeyWrapProvider.UnwrapKey(testParams.EncryptedKey);
                Assert.True(Utility.AreEqual(unwrappedKey, testParams.KeyToWrap), "Utility.AreEqual(unwrappedKey, testParams.KeyToWrap)");
            }
        }

        public static TheoryData<KeyWrapTestParams> KeyWrapTheoryData
        {
            get
            {
                var theoryData = new TheoryData<KeyWrapTestParams>();

                theoryData.Add(new KeyWrapTestParams
                {
                    Algorithm = AES128_KeyWrap.Algorithm,
                    Key = new SymmetricSecurityKey(Base64UrlEncoder.DecodeBytes(AES128_KeyWrap.K)),
                    KeyToWrap = AES128_KeyWrap.CEK,
                    EncryptedKey = AES128_KeyWrap.EncryptedKey,
                    EncodedEncryptedKey = AES128_KeyWrap.EncodedEncryptedKey,
                    TestId = "AES128_KeyWrap"
                });

                theoryData.Add(new KeyWrapTestParams
                {
                    Algorithm = RSAES_OAEP_KeyWrap.Algorithm,
                    Key = RSAES_OAEP_KeyWrap.Key,
                    KeyToWrap = RSAES_OAEP_KeyWrap.CEK,
                    EncryptedKey = RSAES_OAEP_KeyWrap.EncryptedKey,
                    EncodedEncryptedKey = RSAES_OAEP_KeyWrap.EncodedEncryptedKey,
                    TestId = "RSA_OAEP_KeyWrap"
                });

                theoryData.Add(new KeyWrapTestParams
                {
                    Algorithm = RSAES_PKCS1_KeyWrap.Algorithm,
                    Key = RSAES_PKCS1_KeyWrap.Key,
                    KeyToWrap = RSAES_PKCS1_KeyWrap.CEK,
                    EncryptedKey = RSAES_PKCS1_KeyWrap.EncryptedKey,
                    EncodedEncryptedKey = RSAES_PKCS1_KeyWrap.EncodedEncryptedKey,
                    TestId = "RSAES-PKCS1-v1_5"
                });

                return theoryData;
            }
        }

        public class KeyWrapTestParams
        {
            public string Algorithm { get; set; }
            public SecurityKey Key { get; set; }
            public byte[] KeyToWrap { get; set; }
            public byte[] EncryptedKey { get; set; }
            public string EncodedEncryptedKey { get; set; }
            public string TestId { get; set; }

            public override string ToString()
            {
                return TestId + ", " + Algorithm + ", " + Key.KeyId;
            }
        }
    }
}

#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
