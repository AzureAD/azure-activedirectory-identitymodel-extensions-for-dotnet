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
using Xunit;

namespace Microsoft.IdentityModel.Tokens.Tests
{
    /// <summary>
    /// Tests for KeyWrapProvider
    /// Constructors
    ///     - validate parameters (null, empty)
    ///     - algorithms supported
    ///     - properties are set correctly (Algorithm, Context, Key)
    /// WrapKey/UnwrapKey
    ///     - positive tests for keys (128, 256) X Algorithms supported.
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
    public class KeyWrapProviderTests
    {
#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("KeyWrapConstructorTheoryData")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void Constructors(string testId, SecurityKey key, string algorithm, ExpectedException ee)
        {
            try
            {
                var context = Guid.NewGuid().ToString();
                var provider = new KeyWrapProvider(key, algorithm) { Context = context };

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

        public static TheoryData<string, SecurityKey, string, ExpectedException> KeyWrapConstructorTheoryData()
        {
            var theoryData = new TheoryData<string, SecurityKey, string, ExpectedException>();

            theoryData.Add("Test1", null, null, ExpectedException.ArgumentNullException());
            theoryData.Add("Test2", Default.SymmetricEncryptionKey128, null, ExpectedException.ArgumentNullException());
            theoryData.Add("Test3", Default.SymmetricEncryptionKey128, SecurityAlgorithms.Aes128Encryption, ExpectedException.ArgumentException("IDX10661:"));
            theoryData.Add("Test4", Default.SymmetricEncryptionKey128, SecurityAlgorithms.Aes128KW, ExpectedException.NoExceptionExpected);
            theoryData.Add("Test5", Default.SymmetricEncryptionKey256, SecurityAlgorithms.Aes256KW, ExpectedException.NoExceptionExpected);

            JsonWebKey key = new JsonWebKey();
            key.Kty = JsonWebAlgorithmsKeyTypes.Octet;
            theoryData.Add("Test6", key, SecurityAlgorithms.Aes256KW, ExpectedException.ArgumentException("IDX10661:"));
            theoryData.Add("Test7", Default.SymmetricEncryptionKey128, SecurityAlgorithms.Aes256KW, ExpectedException.ArgumentOutOfRangeException("IDX10662:"));
            theoryData.Add("Test8", Default.SymmetricEncryptionKey256, SecurityAlgorithms.Aes128KW, ExpectedException.ArgumentOutOfRangeException("IDX10662:"));
            theoryData.Add("Test9", Default.SymmetricEncryptionKey256, SecurityAlgorithms.Aes256CbcHmacSha512, ExpectedException.ArgumentException("IDX10661:"));

            return theoryData;
        }

        [Fact]
        public void UnwrapKey()
        {
            var provider = new DerivedKeyWrapProvider(Default.SymmetricEncryptionKey128, SecurityAlgorithms.Aes128KW);
            byte[] wrappedKey = provider.WrapKey(Guid.NewGuid().ToByteArray());
            provider.UnwrapKey(wrappedKey);
            Assert.True(provider.UnwrapKeyCalled);
        }

        [Fact]
        public void WrapKey()
        {
            var provider = new DerivedKeyWrapProvider(Default.SymmetricEncryptionKey128, SecurityAlgorithms.Aes128KW);
            byte[] wrappedKey = provider.WrapKey(Guid.NewGuid().ToByteArray());
            Assert.True(provider.WrapKeyCalled);
        }

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("WrapUnwrapTheoryData")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void WrapUnwrapKey(KeyWrapTestParams theoryParams)
        {
            try
            {
                var provider = new KeyWrapProvider(theoryParams.EncryptKey, theoryParams.EncryptAlgorithm);
                byte[] wrappedKey = provider.WrapKey(theoryParams.KeyToWrap);
                byte[] unwrappedKey = provider.UnwrapKey(wrappedKey);

                Assert.True(Utility.AreEqual(unwrappedKey, theoryParams.KeyToWrap), "theoryParams.KeyToWrap != unwrappedKey");

                theoryParams.EE.ProcessNoException();
            }
            catch (Exception ex)
            {
                theoryParams.EE.ProcessException(ex);
            }
        }

        public static TheoryData<KeyWrapTestParams> WrapUnwrapTheoryData()
        {
            var theoryData = new TheoryData<KeyWrapTestParams>();

            // round trip positive tests
            AddWrapUnwrapTheoryData("Test1", SecurityAlgorithms.Aes128KW, Default.SymmetricEncryptionKey128, theoryData);
            AddWrapUnwrapTheoryData("Test2", SecurityAlgorithms.Aes256KW, Default.SymmetricEncryptionKey256, theoryData);

            // Wrap parameter checking
            AddWrapParameterCheckTheoryData("Test3", SecurityAlgorithms.Aes128KW, Default.SymmetricEncryptionKey128, null, ExpectedException.ArgumentNullException(), theoryData);
            byte[] keyToWrap = new byte[9];
            Array.Copy(Guid.NewGuid().ToByteArray(), keyToWrap, keyToWrap.Length);
            AddWrapParameterCheckTheoryData("Test4", SecurityAlgorithms.Aes128KW, Default.SymmetricEncryptionKey128, keyToWrap, ExpectedException.ArgumentException("IDX10664:"), theoryData);

            return theoryData;
        }

        private static void AddWrapUnwrapTheoryData(string testId, string algorithm, SecurityKey key, TheoryData<KeyWrapTestParams> theoryData)
        {
            theoryData.Add(new KeyWrapTestParams
            {
                EncryptAlgorithm = algorithm,
                KeyToWrap = Guid.NewGuid().ToByteArray(),
                EE = ExpectedException.NoExceptionExpected,
                EncryptKey = key,
                TestId = "AddWrapUnwrapTheoryData_" + testId
            });
        }

        private static void AddWrapParameterCheckTheoryData(string testId, string algorithm, SecurityKey key, byte[] keyToWrap, ExpectedException ee, TheoryData<KeyWrapTestParams> theoryData)
        {
            theoryData.Add(new KeyWrapTestParams
            {
                EncryptAlgorithm = algorithm,
                EncryptKey = key,
                KeyToWrap = keyToWrap,
                EE = ee,
                TestId = testId
            });
        }

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("UnwrapTamperedTheoryData")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void UnwrapTamperedData(KeyWrapTestParams theoryParams)
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

        private static TheoryData<KeyWrapTestParams> UnwrapTamperedTheoryData()
        {
            var theoryData = new TheoryData<KeyWrapTestParams>();

            // tampering: wrapped key
            AddUnwrapTamperedTheoryData("Test1", Default.SymmetricEncryptionKey128, SecurityAlgorithms.Aes128KW, theoryData);
            AddUnwrapTamperedTheoryData("Test2", Default.SymmetricEncryptionKey256, SecurityAlgorithms.Aes256KW, theoryData);

            return theoryData;
        }

        private static void AddUnwrapTamperedTheoryData(string testId, SecurityKey key, string algorithm, TheoryData<KeyWrapTestParams> theoryData)
        {
            var keyToWrap = Guid.NewGuid().ToByteArray();
            var provider = new KeyWrapProvider(key, algorithm);
            var wrappedKey = provider.WrapKey(keyToWrap);

            TestUtilities.XORBytes(wrappedKey);
            theoryData.Add(new KeyWrapTestParams
            {
                EncryptAlgorithm = algorithm,
                EncryptKey = key,
                EE = ExpectedException.KeyWrapUnwrapException("IDX10659:"),
                Provider = provider,
                WrappedKey = wrappedKey
            });
        }

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("UnwrapMismatchTheoryData")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void UnwrapMismatch(KeyWrapTestParams theoryParams)
        {
            try
            {
                var encryptProvider = new KeyWrapProvider(theoryParams.EncryptKey, theoryParams.EncryptAlgorithm);
                byte[] keyToWrap = Guid.NewGuid().ToByteArray();
                byte[] wrappedKey = encryptProvider.WrapKey(keyToWrap);
                var decryptProvider = new KeyWrapProvider(theoryParams.DecryptKey, theoryParams.DecryptAlgorithm);
                byte[] unwrappedKey = decryptProvider.UnwrapKey(wrappedKey);
                theoryParams.EE.ProcessNoException();
            }
            catch (Exception ex)
            {
                theoryParams.EE.ProcessException(ex);
            }
        }

        private static TheoryData<KeyWrapTestParams> UnwrapMismatchTheoryData()
        {
            var theoryData = new TheoryData<KeyWrapTestParams>();

            AddUnwrapMismatchTheoryData("Test1", Default.SymmetricEncryptionKey128, Default.SymmetricEncryptionKey128_2, SecurityAlgorithms.Aes128KW, SecurityAlgorithms.Aes128KW, ExpectedException.KeyWrapUnwrapException("IDX10659:"), theoryData);
            AddUnwrapMismatchTheoryData("Test2", Default.SymmetricEncryptionKey256, Default.SymmetricEncryptionKey256_2, SecurityAlgorithms.Aes256KW, SecurityAlgorithms.Aes256KW, ExpectedException.KeyWrapUnwrapException("IDX10659:"), theoryData);
            AddUnwrapMismatchTheoryData("Test3", Default.SymmetricEncryptionKey128, Default.SymmetricEncryptionKey256, SecurityAlgorithms.Aes128KW, SecurityAlgorithms.Aes256KW, ExpectedException.KeyWrapUnwrapException("IDX10659:"), theoryData);

            return theoryData;
        }

        private static void AddUnwrapMismatchTheoryData(string testId, SecurityKey encryptKey, SecurityKey decryptKey, string encryptAlg, string decryptAlg, ExpectedException ee, TheoryData<KeyWrapTestParams> theoryData)
        {
            theoryData.Add(new KeyWrapTestParams
            {
                EncryptAlgorithm = encryptAlg,
                EncryptKey = encryptKey,
                DecryptAlgorithm = decryptAlg,
                DecryptKey = decryptKey,
                EE = ee,
                TestId = testId
            });
        }


#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("UnwrapTheoryData")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void UnwrapParameterCheck(KeyWrapTestParams theoryParams)
        {
            try
            {
                var provider = new KeyWrapProvider(theoryParams.EncryptKey, theoryParams.EncryptAlgorithm);
                byte[] unwrappedKey = provider.UnwrapKey(theoryParams.WrappedKey);

                theoryParams.EE.ProcessNoException();
            }
            catch (Exception ex)
            {
                theoryParams.EE.ProcessException(ex);
            }
        }

        public static TheoryData<KeyWrapTestParams> UnwrapTheoryData()
        {
            var theoryData = new TheoryData<KeyWrapTestParams>();

            // Unwrap parameter checking
            AddUnwrapParameterCheckTheoryData("Test1", SecurityAlgorithms.Aes128KW, Default.SymmetricEncryptionKey128, null, ExpectedException.ArgumentNullException(), theoryData);

            byte[] wrappedKey = new byte[12];
            Array.Copy(Guid.NewGuid().ToByteArray(), wrappedKey, wrappedKey.Length);
            AddUnwrapParameterCheckTheoryData("Test2", SecurityAlgorithms.Aes128KW, Default.SymmetricEncryptionKey128, wrappedKey, ExpectedException.ArgumentException("IDX10664:"), theoryData);

            return theoryData;
        }

        private static void AddUnwrapParameterCheckTheoryData(string testId, string algorithm, SecurityKey key, byte[] wrappedKey, ExpectedException ee, TheoryData<KeyWrapTestParams> theoryData)
        {
            theoryData.Add(new KeyWrapTestParams
            {
                EncryptAlgorithm = algorithm,
                EncryptKey = key,
                WrappedKey = wrappedKey,
                EE = ee,
                TestId = testId
            });
        }

        public class KeyWrapTestParams
        {
            public string DecryptAlgorithm { get; set; }
            public SecurityKey DecryptKey { get; set; }
            public string EncryptAlgorithm { get; set; }
            public ExpectedException EE { get; set; }
            public SecurityKey EncryptKey { get; set; }
            public byte[] KeyToWrap { get; set; }
            public byte[] WrappedKey { get; set; }
            public KeyWrapProvider Provider { get; set; }
            public string TestId { get; set; }
        }
    }
}
