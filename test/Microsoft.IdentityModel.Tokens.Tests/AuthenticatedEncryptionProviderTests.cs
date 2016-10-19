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
using System.Text;
using Xunit;

namespace Microsoft.IdentityModel.Tokens.Tests
{
    /// <summary>
    /// Tests for AuthenticatedEncryptionProvider
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
            theoryData.Add("Test4", Default.SymmetricEncryptionKey512, SecurityAlgorithms.Aes256CbcHmacSha512, ExpectedException.NoExceptionExpected);
            theoryData.Add("Test5", Default.SymmetricEncryptionKey256, SecurityAlgorithms.Aes128Encryption, ExpectedException.ArgumentException("IDX10652:"));
            theoryData.Add("Test6", Default.SymmetricEncryptionKey128, SecurityAlgorithms.Aes128CbcHmacSha256, ExpectedException.ArgumentOutOfRangeException("IDX10653:"));
            theoryData.Add("Test7", Default.SymmetricEncryptionKey256, SecurityAlgorithms.Aes256CbcHmacSha512, ExpectedException.ArgumentOutOfRangeException("IDX10653:"));

            return theoryData;
        }

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("EncryptParameterValidationTheoryData")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void EncryptionParameterValidation(string testId, SymmetricSecurityKey key, string algorithm, ExpectedException ee)
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

        public static TheoryData<string, SecurityKey, string, ExpectedException> EncryptParameterValidationTheoryData()
        {
            var theoryData = new TheoryData<string, SecurityKey, string, ExpectedException>();

            theoryData.Add("Test1", null, null, ExpectedException.ArgumentNullException());
            theoryData.Add("Test2", Default.SymmetricEncryptionKey256, null, ExpectedException.ArgumentNullException());
            theoryData.Add("Test3", Default.SymmetricEncryptionKey256, SecurityAlgorithms.Aes128CbcHmacSha256, ExpectedException.NoExceptionExpected);
            theoryData.Add("Test4", Default.SymmetricEncryptionKey512, SecurityAlgorithms.Aes256CbcHmacSha512, ExpectedException.NoExceptionExpected);
            theoryData.Add("Test5", Default.SymmetricEncryptionKey256, SecurityAlgorithms.Aes128Encryption, ExpectedException.ArgumentException("IDX10652:"));
            theoryData.Add("Test6", Default.SymmetricEncryptionKey128, SecurityAlgorithms.Aes128CbcHmacSha256, ExpectedException.ArgumentOutOfRangeException("IDX10653:"));
            theoryData.Add("Test7", Default.SymmetricEncryptionKey256, SecurityAlgorithms.Aes256CbcHmacSha512, ExpectedException.ArgumentOutOfRangeException("IDX10653:"));

            return theoryData;
        }

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("EncryptDecryptTheoryData")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void EncryptDecrypt(AuthenticatedEncryptionTestParams theoryParams)
        {
            try
            {
                var provider = new AuthenticatedEncryptionProvider(theoryParams.Key, theoryParams.Algorithm);
                var results = provider.Encrypt(theoryParams.PlainText, theoryParams.AuthenticatedData);
                var clearText = provider.Decrypt(results.Ciphertext, theoryParams.AuthenticatedData, results.InitializationVector, results.AuthenticationTag);

                Assert.True(Utility.AreEqual(theoryParams.PlainText, clearText), "theoryParams.PlainText != clearText");

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
                Algorithm = SecurityAlgorithms.Aes128CbcHmacSha256,
                PlainText = null,
                EE = ExpectedException.ArgumentNullException(),
                Key = Default.SymmetricEncryptionKey256,
                TestId = "Test9",
            });

            theoryData.Add(new AuthenticatedEncryptionTestParams
            {
                AuthenticatedData = Guid.NewGuid().ToByteArray(),
                Algorithm = SecurityAlgorithms.Aes128CbcHmacSha256,
                PlainText = new byte[0],
                EE = ExpectedException.ArgumentNullException(),
                Key = Default.SymmetricEncryptionKey256,
                TestId = "Test10",
            });

            theoryData.Add(new AuthenticatedEncryptionTestParams
            {
                AuthenticatedData = null,
                Algorithm = SecurityAlgorithms.Aes128CbcHmacSha256,
                PlainText = Guid.NewGuid().ToByteArray(),
                EE = ExpectedException.ArgumentNullException(),
                Key = Default.SymmetricEncryptionKey256,
                TestId = "Test11",
            });

            return theoryData;
        }

        private static void AddEncryptDecryptTheoryData(string testId, string algorithm, SymmetricSecurityKey key, TheoryData<AuthenticatedEncryptionTestParams> theoryData)
        {
            theoryData.Add(new AuthenticatedEncryptionTestParams
            {
                AuthenticatedData = Guid.NewGuid().ToByteArray(),
                Algorithm = algorithm,
                PlainText = Guid.NewGuid().ToByteArray(),
                EE = ExpectedException.NoExceptionExpected,
                Key = key,
                TestId = testId,
            });
        }

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("DecryptTheoryData")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void Decrypt(AuthenticatedEncryptionTestParams theoryParams)
        {
            try
            {
                var clearText = theoryParams.Provider.Decrypt(theoryParams.EncryptionResults.Ciphertext, theoryParams.AuthenticatedData, theoryParams.EncryptionResults.InitializationVector, theoryParams.EncryptionResults.AuthenticationTag);
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

            AddDecryptTheoryData(SecurityAlgorithms.Aes128CbcHmacSha256, Default.SymmetricEncryptionKey256, theoryData);
            AddDecryptTheoryData(SecurityAlgorithms.Aes128CbcHmacSha256, Default.SymmetricEncryptionKey384, theoryData);
            AddDecryptTheoryData(SecurityAlgorithms.Aes128CbcHmacSha256, Default.SymmetricEncryptionKey512, theoryData);
            AddDecryptTheoryData(SecurityAlgorithms.Aes128CbcHmacSha256, Default.SymmetricEncryptionKey768, theoryData);
            AddDecryptTheoryData(SecurityAlgorithms.Aes128CbcHmacSha256, Default.SymmetricEncryptionKey1024, theoryData);
            AddDecryptTheoryData(SecurityAlgorithms.Aes256CbcHmacSha512, Default.SymmetricEncryptionKey512, theoryData);
            AddDecryptTheoryData(SecurityAlgorithms.Aes256CbcHmacSha512, Default.SymmetricEncryptionKey768, theoryData);
            AddDecryptTheoryData(SecurityAlgorithms.Aes256CbcHmacSha512, Default.SymmetricEncryptionKey1024, theoryData);

            // parameter checking
            var provider = new AuthenticatedEncryptionProvider(Default.SymmetricEncryptionKey1024, SecurityAlgorithms.Aes256CbcHmacSha512);
            theoryData.Add(new AuthenticatedEncryptionTestParams
            {
                Algorithm = SecurityAlgorithms.Aes256CbcHmacSha512,
                AuthenticatedData = null,
                EE = ExpectedException.ArgumentNullException(),
                Provider = provider,
                EncryptionResults = new AuthenticatedEncryptionResult
                {
                    Ciphertext = null,
                    AuthenticationTag = null
                },
                TestId = "TestId1"
            });

            theoryData.Add(new AuthenticatedEncryptionTestParams
            {
                Algorithm = SecurityAlgorithms.Aes256CbcHmacSha512,
                AuthenticatedData = null,
                EE = ExpectedException.ArgumentNullException(),
                Provider = provider,
                EncryptionResults = new AuthenticatedEncryptionResult
                {
                    AuthenticationTag = null,
                    Ciphertext = new byte[0],
                    InitializationVector = null
                },
                TestId = "TestId2"
            });

            theoryData.Add(new AuthenticatedEncryptionTestParams
            {
                Algorithm = SecurityAlgorithms.Aes256CbcHmacSha512,
                AuthenticatedData = null,
                EE = ExpectedException.ArgumentNullException(),
                Provider = provider,
                EncryptionResults = new AuthenticatedEncryptionResult
                {
                    AuthenticationTag = null,
                    Ciphertext = new byte[10],
                    InitializationVector = null
                },
                TestId = "TestId3"
            });

            theoryData.Add(new AuthenticatedEncryptionTestParams
            {
                Algorithm = SecurityAlgorithms.Aes256CbcHmacSha512,
                AuthenticatedData = new byte[10],
                EE = ExpectedException.ArgumentNullException(),
                Provider = provider,
                EncryptionResults = new AuthenticatedEncryptionResult
                {
                    AuthenticationTag = null,
                    Ciphertext = new byte[10],
                    InitializationVector = null
                },
                TestId = "TestId4"
            });

            theoryData.Add(new AuthenticatedEncryptionTestParams
            {
                Algorithm = SecurityAlgorithms.Aes256CbcHmacSha512,
                AuthenticatedData = new byte[10],
                EE = ExpectedException.ArgumentNullException(),
                Provider = provider,
                EncryptionResults = new AuthenticatedEncryptionResult
                {
                    AuthenticationTag = null,
                    Ciphertext = new byte[10],
                    InitializationVector = new byte[10]
                },
                TestId = "TestId5"
            });

            return theoryData;
        }

        private static void AddDecryptTheoryData(string algorithm, SymmetricSecurityKey key, TheoryData<AuthenticatedEncryptionTestParams> theoryData)
        {
            var authenticatedData = Guid.NewGuid().ToByteArray();
            var plainText = Guid.NewGuid().ToByteArray();
            var provider = new AuthenticatedEncryptionProvider(key, algorithm);
            var results = provider.Encrypt(plainText, authenticatedData);

            // authenticated
            theoryData.Add(new AuthenticatedEncryptionTestParams
            {
                Algorithm = algorithm,
                AuthenticatedData = Guid.NewGuid().ToByteArray(),
                EE = ExpectedException.SecurityTokenDecryptionFailedException("IDX10650:"),
                EncryptionResults = results,
                Provider = provider,
                Key = key,
                TestId = algorithm + key.KeyId + "_ID1"
            });

            results = provider.Encrypt(plainText, authenticatedData);
            TestUtilities.XORBytes(results.InitializationVector);
            theoryData.Add(new AuthenticatedEncryptionTestParams
            {
                Algorithm = algorithm,
                AuthenticatedData = authenticatedData,
                EE = ExpectedException.SecurityTokenDecryptionFailedException("IDX10650:"),
                EncryptionResults = results,
                Provider = provider,
                Key = key,
                TestId = algorithm + key.KeyId + "_ID2"
            });

            results = provider.Encrypt(plainText, authenticatedData);
            TestUtilities.XORBytes(results.AuthenticationTag);
            theoryData.Add(new AuthenticatedEncryptionTestParams
            {
                Algorithm = algorithm,
                AuthenticatedData = authenticatedData,
                EE = ExpectedException.SecurityTokenDecryptionFailedException("IDX10650:"),
                EncryptionResults = results,
                Provider = provider,
                Key = key,
                TestId = algorithm + key.KeyId + "_ID3"
            });

            results = provider.Encrypt(plainText, authenticatedData);
            TestUtilities.XORBytes(results.Ciphertext);
            theoryData.Add(new AuthenticatedEncryptionTestParams
            {
                Algorithm = algorithm,
                AuthenticatedData = authenticatedData,
                EE = ExpectedException.SecurityTokenDecryptionFailedException("IDX10650:"),
                EncryptionResults = results,
                Provider = provider,
                Key = key,
                TestId = algorithm + key.KeyId + "_ID4"
            });
        }

        public class AuthenticatedEncryptionTestParams
        {
            public string Algorithm { get; set; }
            public byte[] AuthenticatedData { get; set; }
            public ExpectedException EE { get; set; }
            public AuthenticatedEncryptionResult EncryptionResults { get; set; }
            public SymmetricSecurityKey Key { get; set; }
            public byte[] PlainText { get; set; }
            public AuthenticatedEncryptionProvider Provider { get; set; }
            public string TestId { get; set; }
        }
    }
}
