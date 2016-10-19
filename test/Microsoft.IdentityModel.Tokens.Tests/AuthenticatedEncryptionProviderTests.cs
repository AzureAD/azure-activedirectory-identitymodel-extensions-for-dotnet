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
using Xunit;

namespace Microsoft.IdentityModel.Tokens.Tests
{
    /// <summary>
    /// Tests for AuthenticatedEncryptionProvider
    /// 1. Constructors
    ///     - validate parameters (null, empty)
    ///     - algorithms supported
    ///     - key size
    /// 2. EncryptDecrypt
    ///     - positive tests for keys (256, 384, 512, 768, 1024) X Algorithms supported.
    ///     - parameter validation for Encrypt
    /// 3. Decrypt
    ///     - negative tests for tampering of (ciphertest, iv, authenticationtag, authenticateddata)
    ///     - parameter validataion for Decrypt
    /// </summary>
    public class AuthenticatedEncryptionProviderTests
    {
#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("AEPConstructorTheoryData")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void Constructors(string testId, SymmetricSecurityKey key, string algorithm, ExpectedException ee)
        {
            try
            {
                new AuthenticatedEncryptionProvider(key, algorithm);
                ee.ProcessNoException();
            }
            catch (Exception ex)
            {
                ee.ProcessException(ex);
            }
        }

        public static TheoryData<string, SecurityKey, string, ExpectedException> AEPConstructorTheoryData()
        {
            var theoryData = new TheoryData<string, SecurityKey, string, ExpectedException>();

            theoryData.Add("Test1", null, null, ExpectedException.ArgumentNullException());
            theoryData.Add("Test2", Default.SymmetricEncryptionKey256, null, ExpectedException.ArgumentNullException());
            theoryData.Add("Test3", Default.SymmetricEncryptionKey256, SecurityAlgorithms.Aes128CbcHmacSha256, ExpectedException.NoExceptionExpected);
            theoryData.Add("Test4", Default.SymmetricEncryptionKey512, SecurityAlgorithms.Aes128CbcHmacSha256, ExpectedException.NoExceptionExpected);
            theoryData.Add("Test5", Default.SymmetricEncryptionKey512, SecurityAlgorithms.Aes256CbcHmacSha512, ExpectedException.NoExceptionExpected);
            theoryData.Add("Test6", Default.SymmetricEncryptionKey256, SecurityAlgorithms.Aes128Encryption, ExpectedException.ArgumentException("IDX10652:"));
            theoryData.Add("Test7", Default.SymmetricEncryptionKey128, SecurityAlgorithms.Aes128CbcHmacSha256, ExpectedException.ArgumentOutOfRangeException("IDX10653:"));
            theoryData.Add("Test8", Default.SymmetricEncryptionKey256, SecurityAlgorithms.Aes256CbcHmacSha512, ExpectedException.ArgumentOutOfRangeException("IDX10653:"));

            return theoryData;
        }

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("EncryptDecryptTheoryData")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void EncryptDecrypt(AuthenticatedEncryptionTestParams theoryParams)
        {
            try
            {
                // use a different provider for encrypting and decrypting to ensure key creation / privated vars are set correctly
                var encryptionProvider = new AuthenticatedEncryptionProvider(theoryParams.EncryptKey, theoryParams.DecryptAlgorithm);
                var decryptionProvider = new AuthenticatedEncryptionProvider(theoryParams.DecryptKey, theoryParams.EncryptAlgorithm);
                var results = encryptionProvider.Encrypt(theoryParams.Plaintext, theoryParams.AuthenticatedData);
                var cleartext = decryptionProvider.Decrypt(results.Ciphertext, theoryParams.AuthenticatedData, results.InitializationVector, results.AuthenticationTag);

                Assert.True(Utility.AreEqual(theoryParams.Plaintext, cleartext), "theoryParams.PlainText != clearText");

                theoryParams.EE.ProcessNoException();
            }
            catch (Exception ex)
            {
                theoryParams.EE.ProcessException(ex);
            }
        }

        public static TheoryData<AuthenticatedEncryptionTestParams> EncryptDecryptTheoryData()
        {
            var theoryData = new TheoryData<AuthenticatedEncryptionTestParams>();

            AddEncryptDecryptTheoryData("Test1", SecurityAlgorithms.Aes128CbcHmacSha256, Default.SymmetricEncryptionKey256, theoryData);
            AddEncryptDecryptTheoryData("Test2", SecurityAlgorithms.Aes128CbcHmacSha256, Default.SymmetricEncryptionKey384, theoryData);
            AddEncryptDecryptTheoryData("Test3", SecurityAlgorithms.Aes128CbcHmacSha256, Default.SymmetricEncryptionKey512, theoryData);
            AddEncryptDecryptTheoryData("Test4", SecurityAlgorithms.Aes128CbcHmacSha256, Default.SymmetricEncryptionKey768, theoryData);
            AddEncryptDecryptTheoryData("Test5", SecurityAlgorithms.Aes128CbcHmacSha256, Default.SymmetricEncryptionKey1024, theoryData);
            AddEncryptDecryptTheoryData("Test6", SecurityAlgorithms.Aes256CbcHmacSha512, Default.SymmetricEncryptionKey512, theoryData);
            AddEncryptDecryptTheoryData("Test7", SecurityAlgorithms.Aes256CbcHmacSha512, Default.SymmetricEncryptionKey768, theoryData);
            AddEncryptDecryptTheoryData("Test8", SecurityAlgorithms.Aes256CbcHmacSha512, Default.SymmetricEncryptionKey1024, theoryData);

            // parameter checking
            theoryData.Add(new AuthenticatedEncryptionTestParams
            {
                AuthenticatedData = Guid.NewGuid().ToByteArray(),
                DecryptAlgorithm = SecurityAlgorithms.Aes128CbcHmacSha256,
                DecryptKey = Default.SymmetricEncryptionKey256,
                EE = ExpectedException.ArgumentNullException(),
                EncryptAlgorithm = SecurityAlgorithms.Aes128CbcHmacSha256,
                EncryptKey = Default.SymmetricEncryptionKey256,
                Plaintext = null,
                TestId = "Test9"
            });

            theoryData.Add(new AuthenticatedEncryptionTestParams
            {
                AuthenticatedData = Guid.NewGuid().ToByteArray(),
                DecryptAlgorithm = SecurityAlgorithms.Aes128CbcHmacSha256,
                DecryptKey = Default.SymmetricEncryptionKey256,
                EE = ExpectedException.ArgumentNullException(),
                EncryptAlgorithm = SecurityAlgorithms.Aes128CbcHmacSha256,
                EncryptKey = Default.SymmetricEncryptionKey256,
                Plaintext = new byte[0],
                TestId = "Test10"
            });

            theoryData.Add(new AuthenticatedEncryptionTestParams
            {
                AuthenticatedData = null,
                DecryptAlgorithm = SecurityAlgorithms.Aes128CbcHmacSha256,
                DecryptKey = Default.SymmetricEncryptionKey256,
                EE = ExpectedException.ArgumentNullException(),
                EncryptAlgorithm = SecurityAlgorithms.Aes128CbcHmacSha256,
                EncryptKey = Default.SymmetricEncryptionKey256,
                Plaintext = Guid.NewGuid().ToByteArray(),
                TestId = "Test11"
            });

            return theoryData;
        }

        private static void AddEncryptDecryptTheoryData(string testId, string algorithm, SymmetricSecurityKey key, TheoryData<AuthenticatedEncryptionTestParams> theoryData)
        {
            theoryData.Add(new AuthenticatedEncryptionTestParams
            {
                AuthenticatedData = Guid.NewGuid().ToByteArray(),
                DecryptAlgorithm = algorithm,
                DecryptKey = key,
                EE = ExpectedException.NoExceptionExpected,
                EncryptAlgorithm = algorithm,
                EncryptKey = key,
                Plaintext = Guid.NewGuid().ToByteArray(),
                TestId = "AddEncryptDecryptTheoryData_" + testId
            });
        }

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("DecryptTheoryData")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void Decrypt(AuthenticatedEncryptionTestParams theoryParams)
        {
            try
            {
                theoryParams.Provider.Decrypt(theoryParams.EncryptionResults.Ciphertext, theoryParams.AuthenticatedData, theoryParams.EncryptionResults.InitializationVector, theoryParams.EncryptionResults.AuthenticationTag);
                theoryParams.EE.ProcessNoException();
            }
            catch (Exception ex)
            {
                theoryParams.EE.ProcessException(ex);
            }
        }

        public static TheoryData<AuthenticatedEncryptionTestParams> DecryptTheoryData()
        {
            var theoryData = new TheoryData<AuthenticatedEncryptionTestParams>();

            // test tampering of iv, ciphertext, authenticationData, authenticationTag
            AddDecryptTheoryData("Test1", SecurityAlgorithms.Aes128CbcHmacSha256, Default.SymmetricEncryptionKey256, theoryData);
            AddDecryptTheoryData("Test2", SecurityAlgorithms.Aes128CbcHmacSha256, Default.SymmetricEncryptionKey384, theoryData);
            AddDecryptTheoryData("Test3", SecurityAlgorithms.Aes128CbcHmacSha256, Default.SymmetricEncryptionKey512, theoryData);
            AddDecryptTheoryData("Test4", SecurityAlgorithms.Aes128CbcHmacSha256, Default.SymmetricEncryptionKey768, theoryData);
            AddDecryptTheoryData("Test5", SecurityAlgorithms.Aes128CbcHmacSha256, Default.SymmetricEncryptionKey1024, theoryData);
            AddDecryptTheoryData("Test6", SecurityAlgorithms.Aes256CbcHmacSha512, Default.SymmetricEncryptionKey512, theoryData);
            AddDecryptTheoryData("Test7", SecurityAlgorithms.Aes256CbcHmacSha512, Default.SymmetricEncryptionKey768, theoryData);
            AddDecryptTheoryData("Test8", SecurityAlgorithms.Aes256CbcHmacSha512, Default.SymmetricEncryptionKey1024, theoryData);

            // parameter checking
            var provider = new AuthenticatedEncryptionProvider(Default.SymmetricEncryptionKey1024, SecurityAlgorithms.Aes256CbcHmacSha512);
            theoryData.Add(new AuthenticatedEncryptionTestParams
            {
                AuthenticatedData = null,
                DecryptAlgorithm = SecurityAlgorithms.Aes256CbcHmacSha512,
                EE = ExpectedException.ArgumentNullException(),
                EncryptAlgorithm = SecurityAlgorithms.Aes256CbcHmacSha512,
                EncryptionResults = new AuthenticatedEncryptionResult
                {
                    Ciphertext = null,
                    AuthenticationTag = null
                },
                Provider = provider,
                TestId = "Test9"
            });

            theoryData.Add(new AuthenticatedEncryptionTestParams
            {
                AuthenticatedData = null,
                DecryptAlgorithm = SecurityAlgorithms.Aes256CbcHmacSha512,
                EE = ExpectedException.ArgumentNullException(),
                EncryptAlgorithm = SecurityAlgorithms.Aes256CbcHmacSha512,
                EncryptionResults = new AuthenticatedEncryptionResult
                {
                    AuthenticationTag = null,
                    Ciphertext = new byte[0],
                    InitializationVector = null
                },
                Provider = provider,
                TestId = "Test10"
            });

            theoryData.Add(new AuthenticatedEncryptionTestParams
            {
                AuthenticatedData = null,
                DecryptAlgorithm = SecurityAlgorithms.Aes256CbcHmacSha512,
                EE = ExpectedException.ArgumentNullException(),
                EncryptAlgorithm = SecurityAlgorithms.Aes256CbcHmacSha512,
                EncryptionResults = new AuthenticatedEncryptionResult
                {
                    AuthenticationTag = null,
                    Ciphertext = new byte[10],
                    InitializationVector = null
                },
                Provider = provider,
                TestId = "Test11"
            });

            theoryData.Add(new AuthenticatedEncryptionTestParams
            {
                AuthenticatedData = new byte[10],
                DecryptAlgorithm = SecurityAlgorithms.Aes256CbcHmacSha512,
                EE = ExpectedException.ArgumentNullException(),
                EncryptAlgorithm = SecurityAlgorithms.Aes256CbcHmacSha512,
                EncryptionResults = new AuthenticatedEncryptionResult
                {
                    AuthenticationTag = null,
                    Ciphertext = new byte[10],
                    InitializationVector = null
                },
                Provider = provider,
                TestId = "Test12"
            });

            theoryData.Add(new AuthenticatedEncryptionTestParams
            {
                AuthenticatedData = new byte[10],
                DecryptAlgorithm = SecurityAlgorithms.Aes256CbcHmacSha512,
                EE = ExpectedException.ArgumentNullException(),
                EncryptAlgorithm = SecurityAlgorithms.Aes256CbcHmacSha512,
                EncryptionResults = new AuthenticatedEncryptionResult
                {
                    AuthenticationTag = null,
                    Ciphertext = new byte[10],
                    InitializationVector = new byte[10]
                },
                Provider = provider,
                TestId = "Test13"
            });

            return theoryData;
        }

        private static void AddDecryptTheoryData(string testId, string algorithm, SymmetricSecurityKey key, TheoryData<AuthenticatedEncryptionTestParams> theoryData)
        {
            var authenticatedData = Guid.NewGuid().ToByteArray();
            var plainText = Guid.NewGuid().ToByteArray();
            var provider = new AuthenticatedEncryptionProvider(key, algorithm);
            var results = provider.Encrypt(plainText, authenticatedData);

            theoryData.Add(new AuthenticatedEncryptionTestParams
            {
                AuthenticatedData = Guid.NewGuid().ToByteArray(),
                DecryptAlgorithm = algorithm,
                DecryptKey = key,
                EE = ExpectedException.SecurityTokenDecryptionFailedException("IDX10650:"),
                EncryptAlgorithm = algorithm,
                EncryptKey = key,
                EncryptionResults = results,
                Provider = provider,
                TestId = "AddDecryptTheoryData1_" + testId
            });

            results = provider.Encrypt(plainText, authenticatedData);
            TestUtilities.XORBytes(results.InitializationVector);
            theoryData.Add(new AuthenticatedEncryptionTestParams
            {
                AuthenticatedData = authenticatedData,
                DecryptAlgorithm = algorithm,
                DecryptKey = key,
                EE = ExpectedException.SecurityTokenDecryptionFailedException("IDX10650:"),
                EncryptAlgorithm = algorithm,
                EncryptKey = key,
                EncryptionResults = results,
                Provider = provider,
                TestId = "AddDecryptTheoryData2_" + testId
            });

            results = provider.Encrypt(plainText, authenticatedData);
            TestUtilities.XORBytes(results.AuthenticationTag);
            theoryData.Add(new AuthenticatedEncryptionTestParams
            {
                AuthenticatedData = authenticatedData,
                DecryptAlgorithm = algorithm,
                DecryptKey = key,
                EE = ExpectedException.SecurityTokenDecryptionFailedException("IDX10650:"),
                EncryptAlgorithm = algorithm,
                EncryptKey = key,
                EncryptionResults = results,
                Provider = provider,
                TestId = "AddDecryptTheoryData3_" + testId
            });

            results = provider.Encrypt(plainText, authenticatedData);
            TestUtilities.XORBytes(results.Ciphertext);
            theoryData.Add(new AuthenticatedEncryptionTestParams
            {
                AuthenticatedData = authenticatedData,
                DecryptAlgorithm = algorithm,
                DecryptKey = key,
                EE = ExpectedException.SecurityTokenDecryptionFailedException("IDX10650:"),
                EncryptAlgorithm = algorithm,
                EncryptKey = key,
                EncryptionResults = results,
                Provider = provider,
                TestId = "AddDecryptTheoryData4_" + testId
            });
        }

        public class AuthenticatedEncryptionTestParams
        {
            public byte[] AuthenticatedData { get; set; }
            public string DecryptAlgorithm { get; set; }
            public SymmetricSecurityKey DecryptKey { get; set; }
            public ExpectedException EE { get; set; }
            public string EncryptAlgorithm { get; set; }
            public AuthenticatedEncryptionResult EncryptionResults { get; set; }
            public SymmetricSecurityKey EncryptKey { get; set; }
            public byte[] Plaintext { get; set; }
            public AuthenticatedEncryptionProvider Provider { get; set; }
            public string TestId { get; set; }
        }
    }
}
