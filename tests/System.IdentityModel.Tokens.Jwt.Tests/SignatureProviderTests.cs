//-----------------------------------------------------------------------
// Copyright (c) Microsoft Open Technologies, Inc.
// All Rights Reserved
// Apache License 2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
// http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//-----------------------------------------------------------------------

using Microsoft.IdentityModel.Test;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.IdentityModel.Tokens;
using System.Security.Cryptography;

namespace System.IdentityModel.Test
{

    /// <summary>
    /// This class tests:
    /// SignatureProviderFactory
    /// SignatureProvider
    /// SymmetricSignatureProvider
    /// AsymmetricSignatureProvider
    /// </summary>
    [TestClass]
    public class SignatureProviderTests
    {
        /// <summary>
        /// Test Context Wrapper instance on top of TestContext. Provides better accessor functions
        /// </summary>
        protected TestContextProvider _testContextProvider;

        public TestContext TestContext { get; set; }

        [ClassInitialize]
        public static void ClassSetup(TestContext testContext)
        { }

        [ClassCleanup]
        public static void ClassCleanup()
        { }

        [TestInitialize]
        public void Initialize()
        {
#if _Verbose
            _verbose = true;
#endif

            _testContextProvider = new TestContextProvider(TestContext);
        }

        [TestMethod]
        [TestProperty("TestCaseID", "4A9C4A2E-C50F-4A57-A85B-2D6D4F14ADF1")]
        [Description("Tests for SignatureProviderFactory")]
        public void SignatureProviderFactory_Tests()
        {
            SignatureProviderFactory factory = new SignatureProviderFactory();

            // Asymmetric / Symmetric both need signature alg specified
            FactoryCreateFor("Siging:    - algorithm string.Empty", KeyingMaterial.AsymmetricKey_1024, string.Empty, factory, ExpectedException.ArgumentException());
            FactoryCreateFor("Verifying: - algorithm string.Empty", KeyingMaterial.AsymmetricKey_1024, string.Empty, factory, ExpectedException.ArgumentException());

            // Keytype not supported
            FactoryCreateFor("Siging:    - SecurityKey type not Asymmetric or Symmetric", NotAsymmetricOrSymmetricSecurityKey.New, SecurityAlgorithms.HmacSha256Signature, factory, ExpectedException.ArgumentException("Jwt10500"));
            FactoryCreateFor("Verifying: - SecurityKey type not Asymmetric or Symmetric", NotAsymmetricOrSymmetricSecurityKey.New, SecurityAlgorithms.RsaSha256Signature, factory, ExpectedException.ArgumentException("Jwt10500"));

            // Private keys missing
            FactoryCreateFor("Siging:    - SecurityKey without private key", KeyingMaterial.DefaultAsymmetricKey_Public_2048, SecurityAlgorithms.RsaSha256Signature, factory, ExpectedException.InvalidOperationException(substringExpected: "Jwt10514", inner: typeof(NotSupportedException)));
            FactoryCreateFor("Verifying: - SecurityKey without private key", KeyingMaterial.DefaultAsymmetricKey_Public_2048, SecurityAlgorithms.RsaSha256Signature, factory, ExpectedException.NoExceptionExpected);

            // Key size checks
            FactoryCreateFor("Siging:    - AsymmetricKeySize Key to small", KeyingMaterial.AsymmetricKey_1024, SecurityAlgorithms.RsaSha256Signature, factory, ExpectedException.ArgumentOutOfRangeException("Jwt10530"));

            SignatureProviderFactory.MinimumAsymmetricKeySizeInBitsForVerifying = 2048;
            FactoryCreateFor("Verifying: - AsymmetricKeySize Key to small", KeyingMaterial.AsymmetricKey_1024, SecurityAlgorithms.RsaSha256Signature, factory, ExpectedException.ArgumentOutOfRangeException("Jwt10531"));
            SignatureProviderFactory.MinimumAsymmetricKeySizeInBitsForVerifying = SignatureProviderFactory.AbsoluteMinimumAsymmetricKeySizeInBitsForVerifying;

            SignatureProviderFactory.MinimumSymmetricKeySizeInBits = 512;
            FactoryCreateFor("Siging:    - SymmetricKeySize Key to small", KeyingMaterial.DefaultSymmetricSecurityKey_256, SecurityAlgorithms.HmacSha256Signature, factory, ExpectedException.ArgumentOutOfRangeException("Jwt10503"));
            FactoryCreateFor("Verifying: - SymmetricKeySize Key to small", KeyingMaterial.DefaultSymmetricSecurityKey_256, SecurityAlgorithms.HmacSha256Signature, factory, ExpectedException.ArgumentOutOfRangeException("Jwt10503"));
            SignatureProviderFactory.MinimumSymmetricKeySizeInBits = SignatureProviderFactory.AbsoluteMinimumSymmetricKeySizeInBits;

            ExpectedException expectedException = ExpectedException.ArgumentOutOfRangeException("Jwt10513");
            // setting keys too small
            try
            {
                Console.WriteLine(string.Format("Testcase: '{0}'", "SignatureProviderFactory.MinimumAsymmetricKeySizeInBitsForSigning < AbsoluteMinimumAsymmetricKeySizeInBitsForSigning"));
                SignatureProviderFactory.MinimumAsymmetricKeySizeInBitsForSigning = SignatureProviderFactory.AbsoluteMinimumAsymmetricKeySizeInBitsForSigning - 10;
                expectedException.ProcessNoException();
                SignatureProviderFactory.MinimumAsymmetricKeySizeInBitsForSigning = SignatureProviderFactory.AbsoluteMinimumAsymmetricKeySizeInBitsForSigning;
            }
            catch (Exception ex)
            {
                expectedException.ProcessException(ex);
            }

            expectedException = ExpectedException.ArgumentOutOfRangeException("Jwt10527");
            try
            {
                Console.WriteLine(string.Format("Testcase: '{0}'", "SignatureProviderFactory.MinimumAsymmetricKeySizeInBitsForVerifying < AbsoluteMinimumAsymmetricKeySizeInBitsForVerifying"));
                SignatureProviderFactory.MinimumAsymmetricKeySizeInBitsForVerifying = SignatureProviderFactory.AbsoluteMinimumAsymmetricKeySizeInBitsForVerifying - 10;
                expectedException.ProcessNoException();
            }
            catch (Exception ex)
            {
                expectedException.ProcessException(ex);
            }

            expectedException = ExpectedException.ArgumentOutOfRangeException("Jwt10528");
            try
            {
                Console.WriteLine(string.Format("Testcase: '{0}'", "SignatureProviderFactory.MinimumSymmetricKeySizeInBits < AbsoluteMinimumSymmetricKeySizeInBits"));
                SignatureProviderFactory.MinimumSymmetricKeySizeInBits = SignatureProviderFactory.AbsoluteMinimumSymmetricKeySizeInBits - 10;
                expectedException.ProcessNoException();
            }
            catch (Exception ex)
            {
                expectedException.ProcessException(ex);
            }
        }

        private void FactoryCreateFor(string testcase, SecurityKey key, string algorithm, SignatureProviderFactory factory, ExpectedException expectedException)
        {
            Console.WriteLine(string.Format("Testcase: '{0}'", testcase));

            try
            {
                if (testcase.StartsWith("Siging"))
                {
                    factory.CreateForSigning(key, algorithm);
                }
                else
                {
                    factory.CreateForVerifying(key, algorithm);
                }

                expectedException.ProcessNoException();
            }
            catch (Exception ex)
            {
                expectedException.ProcessException(ex);
            }
        }

        [TestMethod]
        [TestProperty("TestCaseID", "F7B5A336-BF04-4589-9F8E-36451E1E3B7F")]
        [Description("AsymmetricSignatureProvider Constructor")]
        public void AsymmetricSignatureProvider_Constructor()
        {
            AsymmetricSecurityKey privateKey = KeyingMaterial.DefaultX509SigningCreds_2048_RsaSha2_Sha2.SigningKey as AsymmetricSecurityKey;
            AsymmetricSecurityKey publicKey = KeyingMaterial.DefaultX509SigningCreds_Public_2048_RsaSha2_Sha2.SigningKey as AsymmetricSecurityKey;
            string sha2SignatureAlgorithm = KeyingMaterial.DefaultX509SigningCreds_2048_RsaSha2_Sha2.SignatureAlgorithm;

            // no errors
            AsymmetricConstructorVariation("Signing:  - Creates with no errors", privateKey, sha2SignatureAlgorithm, expectedException: ExpectedException.NoExceptionExpected);
            AsymmetricConstructorVariation("Verifying: - Creates with no errors (Private Key)", privateKey, sha2SignatureAlgorithm, expectedException: ExpectedException.NoExceptionExpected);
            AsymmetricConstructorVariation("Verifying: - Creates with no errors (Public Key)", publicKey, sha2SignatureAlgorithm, expectedException: ExpectedException.NoExceptionExpected);

            // null, empty algorithm digest
            AsymmetricConstructorVariation("Signing:   - NUll key", null, sha2SignatureAlgorithm, expectedException: ExpectedException.ArgumentNullException());
            AsymmetricConstructorVariation("Signing:   - SignatureAlorithm == null", privateKey, null, expectedException: ExpectedException.ArgumentNullException());
            AsymmetricConstructorVariation("Signing:   - SignatureAlorithm == whitespace", privateKey, "    ", expectedException: ExpectedException.ArgumentException("WIF10002"));

            // Private keys missing
            AsymmetricConstructorVariation("Signing:   - SecurityKey without private key", publicKey, sha2SignatureAlgorithm, expectedException: ExpectedException.InvalidOperationException(inner: typeof(NotSupportedException)));
            AsymmetricConstructorVariation("Verifying: - SecurityKey without private key", publicKey, sha2SignatureAlgorithm, expectedException: ExpectedException.NoExceptionExpected);

            // _formatter not created
            AsymmetricConstructorVariation("Signing:   - key cannot create _formatter", KeyingMaterial.AsymmetricKey_2048, "SecurityAlgorithms.RsaSha256Signature", expectedException: ExpectedException.InvalidOperationException(substringExpected: "Jwt10518", inner: typeof(NotSupportedException)));

            // _deformatter not created
            AsymmetricConstructorVariation("Verifying: - key cannot create _deformatter", KeyingMaterial.DefaultAsymmetricKey_Public_2048, "SecurityAlgorithms.RsaSha256Signature", expectedException: ExpectedException.InvalidOperationException(substringExpected: "Jwt10518", inner: typeof(NotSupportedException)));

            Console.WriteLine("Test missing: key.GetHashAlgorithmForSignature( signingCredentials.SignatureAlgorithm );"); //TODO: Should this be fixed?
        }

        private void AsymmetricConstructorVariation(string testcase, AsymmetricSecurityKey key, string algorithm, ExpectedException expectedException)
        {

            Console.WriteLine(string.Format("Testcase: '{0}'", testcase));

            AsymmetricSignatureProvider provider = null;
            try
            {
                if (testcase.StartsWith("Signing"))
                {
                    provider = new AsymmetricSignatureProvider(key, algorithm, true);
                }
                else
                {
                    provider = new AsymmetricSignatureProvider(key, algorithm, false);
                }
                expectedException.ProcessNoException();
            }
            catch (Exception ex)
            {
                expectedException.ProcessException(ex);
            }
        }

        [TestMethod]
        [TestProperty("TestCaseID", "8A43293F-196C-47B8-8C1D-59CDAD30C39E")]
        [Description("Tests for AsymmetricSignatureProvider.Dispose")]
        public void AsymmetricSignatureProvider_Dispose()
        {
            AsymmetricSignatureProvider provider = new AsymmetricSignatureProvider(KeyingMaterial.DefaultAsymmetricKey_Public_2048, SecurityAlgorithms.RsaSha256Signature);
            provider.Dispose();

            ExpectedException expectedException = ExpectedException.ObjectDisposedException;
            try
            {
                provider.Sign(new byte[256]);
            }
            catch (Exception ex)
            {
                expectedException.ProcessException(ex);
            }

            try
            {
                provider.Verify(new byte[256], new byte[256]);
            }
            catch (Exception ex)
            {
                expectedException.ProcessException(ex);
            }

            try
            {
                provider.Dispose();
            }
            catch (Exception ex)
            {
                Assert.Fail(string.Format("AsymmetricSignatureProvider.Dispose called twice, caught exception: '{0}'", ex));
            }
        }

        [TestMethod]
        [TestProperty("TestCaseID", "FC949834-617F-4C57-8643-C30F160E309D")]
        [Description("Ensures that AsymmetricSignatureProvider defaults are as expected")]
        public void AsymmetricSignatureProvider_Defaults()
        {
            try
            {
                AsymmetricSignatureProvider asymmetricSignatureProvider = new AsymmetricSignatureProvider(KeyingMaterial.DefaultX509SigningCreds_2048_RsaSha2_Sha2.SigningKey as AsymmetricSecurityKey, KeyingMaterial.DefaultX509SigningCreds_2048_RsaSha2_Sha2.SignatureAlgorithm, false);
            }
            catch (Exception)
            {
                Assert.Fail("AsymmetricSignatureProvider creation should not throw");
            }

            try
            {
                AsymmetricSignatureProvider asymmetricSignatureProvider = new AsymmetricSignatureProvider(KeyingMaterial.DefaultX509SigningCreds_2048_RsaSha2_Sha2.SigningKey as AsymmetricSecurityKey, KeyingMaterial.DefaultX509SigningCreds_2048_RsaSha2_Sha2.SignatureAlgorithm, true);
            }
            catch (Exception)
            {
                Assert.Fail("AsymmetricSignatureProvider creation should not throw");
            }
        }

        [TestMethod]
        [TestProperty("TestCaseID", "4923DA59-3F32-4995-84D3-C49B0A08EEDE")]
        [Description("Tests for Asymmetric and Symmetric SignAndVerify")]
        public void SignatureProviders_SignAndVerify()
        {
            // asymmetric
            try
            {
                Random r = new Random();
                AsymmetricSignatureProvider provider = new AsymmetricSignatureProvider(KeyingMaterial.AsymmetricKey_2048, SecurityAlgorithms.RsaSha256Signature);
                byte[] bytesin = new byte[1024];
                r.NextBytes(bytesin);
                byte[] signature = provider.Sign(bytesin);
            }
            catch (Exception ex)
            {
                Assert.IsFalse(ex.GetType() != typeof(InvalidOperationException), "ex.GetType() != typeof( InvalidOperationException )");
            }

            // asymmetric
            try
            {
                Random r = new Random();
                AsymmetricSignatureProvider provider = new AsymmetricSignatureProvider(KeyingMaterial.AsymmetricKey_2048, SecurityAlgorithms.RsaSha256Signature, true);
                byte[] bytesin = new byte[1024];
                r.NextBytes(bytesin);
                byte[] signature = provider.Sign(bytesin);
                Assert.IsFalse(!provider.Verify(bytesin, signature), string.Format("AsymmetricSignatureProvider did not verify"));
            }
            catch (Exception)
            {
                Assert.Fail("Should have thrown, it is possible that crypto config mapped this.");
            }

            // unknown algorithm
            try
            {
                Random r = new Random();
                AsymmetricSignatureProvider provider = new AsymmetricSignatureProvider(KeyingMaterial.AsymmetricKey_2048, "SecurityAlgorithms.RsaSha256Signature");
                Assert.Fail(string.Format("Should have thrown, it is possible that crypto config mapped this."));
            }
            catch (Exception ex)
            {
                Assert.IsFalse(ex.GetType() != typeof(InvalidOperationException), "ex.GetType() != typeof( InvalidOperationException )");
            }

            // symmetric
            try
            {
                Random r = new Random();
                SymmetricSignatureProvider provider = new SymmetricSignatureProvider(KeyingMaterial.DefaultSymmetricSecurityKey_256, SecurityAlgorithms.HmacSha256Signature);
                byte[] bytesin = new byte[1024];
                r.NextBytes(bytesin);
                byte[] signature = provider.Sign(bytesin);
                Assert.IsFalse(!provider.Verify(bytesin, signature), string.Format("Signature did not verify"));
            }
            catch (Exception ex)
            {
                Assert.Fail(string.Format("Unexpected exception received: '{0}'", ex));
            }

            // unknown algorithm
            try
            {
                Random r = new Random();
                SymmetricSignatureProvider provider = new SymmetricSignatureProvider(KeyingMaterial.DefaultSymmetricSecurityKey_256, "SecurityAlgorithms.HmacSha256Signature");
                Assert.Fail(string.Format("Should have thrown, it is possible that crypto config mapped this."));
            }
            catch (Exception ex)
            {
                Assert.IsFalse(ex.GetType() != typeof(InvalidOperationException), "ex.GetType() != typeof( InvalidOperationException )");
            }
        }

        [TestMethod]
        [TestProperty("TestCaseID", "89AF7B31-7707-4E60-AC32-363C9CA78363")]
        [Description("AsymmetricSignatureProvider Tests")]
        public void AsymmetricSignatureProvider_Publics()
        {
            AsymmetricSignatureProvider provider = new AsymmetricSignatureProvider(KeyingMaterial.DefaultX509SigningCreds_2048_RsaSha2_Sha2.SigningKey as AsymmetricSecurityKey, KeyingMaterial.DefaultX509SigningCreds_2048_RsaSha2_Sha2.SignatureAlgorithm);
            SignatureProvider_SignVariation(provider, null, null, ExpectedException.ArgumentNullException());
            SignatureProvider_SignVariation(provider, new byte[0], null, ExpectedException.ArgumentException("Jwt10524"));
            SignatureProvider_SignVariation(provider, new byte[1], null, ExpectedException.InvalidOperationException("Jwt10520"));

            SignatureProvider_VerifyVariation(provider, null, null, ExpectedException.ArgumentNullException());
            SignatureProvider_VerifyVariation(provider, new byte[1], null, ExpectedException.ArgumentNullException());
            SignatureProvider_VerifyVariation(provider, new byte[0], new byte[1], ExpectedException.ArgumentException("Jwt10525"));
            SignatureProvider_VerifyVariation(provider, new byte[1], new byte[0], ExpectedException.ArgumentException("Jwt10526"));
        }

        [TestMethod]
        [TestProperty("TestCaseID", "F59BC1A3-C2D7-43F6-99FC-D25E57D1B99C")]
        [Description("Tests for SymmetricSignatureProvider Constructor")]
        public void SymmetricSignatureProvider_ConstructorTests()
        {
            // no errors
            SymmetricSignatureProvider_ConstructorVariation("Creates with no errors", KeyingMaterial.DefaultSymmetricSecurityKey_256, SecurityAlgorithms.HmacSha256Signature, ExpectedException.NoExceptionExpected);

            // null, empty algorithm digest
            SymmetricSignatureProvider_ConstructorVariation("Constructor:   - NUll key", null, SecurityAlgorithms.HmacSha256Signature, ExpectedException.ArgumentNullException());
            SymmetricSignatureProvider_ConstructorVariation("Constructor:   - algorithm == string.Empty", KeyingMaterial.DefaultSymmetricSecurityKey_256, string.Empty, ExpectedException.ArgumentException());

            // GetKeyedHashAlgorithm throws
            SymmetricSecurityKey key = new FaultingSymmetricSecurityKey(KeyingMaterial.DefaultSymmetricSecurityKey_256, new CryptographicException("hi from inner"));
            SymmetricSignatureProvider_ConstructorVariation("Constructor:   - SecurityKey.GetKeyedHashAlgorithm throws", key, SecurityAlgorithms.HmacSha256Signature, ExpectedException.InvalidOperationException("Jwt10532", typeof(CryptographicException)));

            // Key returns null KeyedHash
            key = new FaultingSymmetricSecurityKey(KeyingMaterial.DefaultSymmetricSecurityKey_256, null);
            SymmetricSignatureProvider_ConstructorVariation("Constructor:   - SecurityKey returns null KeyedHashAlgorithm", key, SecurityAlgorithms.HmacSha256Signature, ExpectedException.InvalidOperationException("Jwt10533"));

            //_keyedHash.Key = _key.GetSymmetricKey() is null;            
            KeyedHashAlgorithm keyedHashAlgorithm = KeyingMaterial.DefaultSymmetricSecurityKey_256.GetKeyedHashAlgorithm(SecurityAlgorithms.HmacSha256Signature);
            key = new FaultingSymmetricSecurityKey(KeyingMaterial.DefaultSymmetricSecurityKey_256, null, null, keyedHashAlgorithm, null);
            SymmetricSignatureProvider_ConstructorVariation("Constructor:   - key returns null bytes to pass to _keyedHashKey", key, SecurityAlgorithms.HmacSha256Signature, ExpectedException.InvalidOperationException("Jwt10534", typeof(NullReferenceException)));
        }

        private void SymmetricSignatureProvider_ConstructorVariation(string testcase, SymmetricSecurityKey key, string algorithm, ExpectedException expectedException)
        {
            Console.WriteLine(string.Format("Testcase: '{0}'", testcase));

            SymmetricSignatureProvider provider = null;
            try
            {
                if (testcase.StartsWith("Signing"))
                {
                    provider = new SymmetricSignatureProvider(key, algorithm);
                }
                else
                {
                    provider = new SymmetricSignatureProvider(key, algorithm);
                }

                expectedException.ProcessNoException();
            }
            catch (Exception ex)
            {
                expectedException.ProcessException(ex);
            }
        }

        [TestMethod]
        [TestProperty("TestCaseID", "E4E5F329-12D8-431A-A971-21F86299DBB1")]
        [Description("Parameter checking for SymmetricSignatureProvider.Sign and .Verify")]
        public void SymmetricSignatureProvider_Publics()
        {
            SymmetricSignatureProvider provider = new SymmetricSignatureProvider(KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2.SigningKey as SymmetricSecurityKey, KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2.SignatureAlgorithm);

            SignatureProvider_SignVariation(provider, null, null, ExpectedException.ArgumentNullException());
            SignatureProvider_SignVariation(provider, new byte[0], null, ExpectedException.ArgumentException("Jwt10524:"));
            SignatureProvider_SignVariation(provider, new byte[1], null, ExpectedException.NoExceptionExpected);

            SignatureProvider_VerifyVariation(provider, null, null, ExpectedException.ArgumentNullException());
            SignatureProvider_VerifyVariation(provider, new byte[0], null, ExpectedException.ArgumentNullException());
            SignatureProvider_VerifyVariation(provider, new byte[0], new byte[0], ExpectedException.ArgumentException("Jwt10525:"));
            SignatureProvider_VerifyVariation(provider, new byte[1], new byte[0], ExpectedException.ArgumentException("Jwt10526:"));
            SignatureProvider_VerifyVariation(provider, new byte[1], new byte[1], ExpectedException.NoExceptionExpected);

            provider.Dispose();
            SignatureProvider_SignVariation(provider, new byte[1], new byte[1], ExpectedException.ObjectDisposedException);
            SignatureProvider_VerifyVariation(provider, new byte[1], new byte[1], ExpectedException.ObjectDisposedException);
        }

        private void SignatureProvider_VerifyVariation(SignatureProvider provider, byte[] bytes, byte[] signature, ExpectedException expectedException)
        {
            try
            {
                provider.Verify(bytes, signature);
                expectedException.ProcessNoException();
            }
            catch (Exception ex)
            {
                expectedException.ProcessException(ex);
            }
        }

        private void SignatureProvider_SignVariation(SignatureProvider provider, byte[] bytes, byte[] signature, ExpectedException expectedException)
        {
            try
            {
                provider.Sign(bytes);
                expectedException.ProcessNoException();
            }
            catch (Exception ex)
            {
                expectedException.ProcessException(ex);
            }
        }
    }
}
