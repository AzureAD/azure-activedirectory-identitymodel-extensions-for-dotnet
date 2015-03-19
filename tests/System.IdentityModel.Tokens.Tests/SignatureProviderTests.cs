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

using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Security.Cryptography;
using Xunit;

namespace System.IdentityModel.Test
{
    /// <summary>
    /// This class tests:
    /// SignatureProviderFactory
    /// SignatureProvider
    /// SymmetricSignatureProvider
    /// AsymmetricSignatureProvider
    /// </summary>
    public class SignatureProviderTests
    {
        [Fact(DisplayName = "SignatureProviderTests: SignatureProviderFactory")]
        public void SignatureProviderFactory_Tests()
        {
            SignatureProviderFactory factory = new SignatureProviderFactory();

            // Asymmetric / Symmetric both need signature alg specified
            FactoryCreateFor("Siging:    - algorithm string.Empty", KeyingMaterial.X509SecurityKey_1024, string.Empty, factory, ExpectedException.ArgumentException());
            FactoryCreateFor("Verifying: - algorithm string.Empty", KeyingMaterial.X509SecurityKey_1024, string.Empty, factory, ExpectedException.ArgumentException());

            // Keytype not supported
            FactoryCreateFor("Siging:    - SecurityKey type not Asymmetric or Symmetric", NotAsymmetricOrSymmetricSecurityKey.New, SecurityAlgorithms.HmacSha256Signature, factory, ExpectedException.ArgumentException("IDX10600:"));
            FactoryCreateFor("Verifying: - SecurityKey type not Asymmetric or Symmetric", NotAsymmetricOrSymmetricSecurityKey.New, SecurityAlgorithms.RsaSha256Signature, factory, ExpectedException.ArgumentException("IDX10600:"));

            // Private keys missing
            FactoryCreateFor("Siging:    - SecurityKey without private key", KeyingMaterial.RsaSecurityKey_2048_Public, SecurityAlgorithms.RsaSha256Signature, factory, ExpectedException.InvalidOperationException(substringExpected: "IDX10638:"));
            FactoryCreateFor("Verifying: - SecurityKey without private key", KeyingMaterial.RsaSecurityKey_2048_Public, SecurityAlgorithms.RsaSha256Signature, factory, ExpectedException.NoExceptionExpected);

            // Key size checks
            FactoryCreateFor("Siging:    - AsymmetricKeySize Key to small", KeyingMaterial.X509SecurityKey_1024, SecurityAlgorithms.RsaSha256Signature, factory, ExpectedException.ArgumentOutOfRangeException("IDX10630:"));

            SignatureProviderFactory.MinimumAsymmetricKeySizeInBitsForVerifying = 2048;
            FactoryCreateFor("Verifying: - AsymmetricKeySize Key to small", KeyingMaterial.X509SecurityKey_1024, SecurityAlgorithms.RsaSha256Signature, factory, ExpectedException.ArgumentOutOfRangeException("IDX10631:"));
            SignatureProviderFactory.MinimumAsymmetricKeySizeInBitsForVerifying = SignatureProviderFactory.AbsoluteMinimumAsymmetricKeySizeInBitsForVerifying;

#if SymmetricKeySuport
            SignatureProviderFactory.MinimumSymmetricKeySizeInBits = 512;
            FactoryCreateFor("Siging:    - SymmetricKeySize Key to small", KeyingMaterial.DefaultSymmetricSecurityKey_256, SecurityAlgorithms.HmacSha256Signature, factory, ExpectedException.ArgumentOutOfRangeException("IDX10603:"));
            FactoryCreateFor("Verifying: - SymmetricKeySize Key to small", KeyingMaterial.DefaultSymmetricSecurityKey_256, SecurityAlgorithms.HmacSha256Signature, factory, ExpectedException.ArgumentOutOfRangeException("IDX10603"));
            SignatureProviderFactory.MinimumSymmetricKeySizeInBits = SignatureProviderFactory.AbsoluteMinimumSymmetricKeySizeInBits;

            ExpectedException expectedException = ExpectedException.ArgumentOutOfRangeException("IDX10613:");
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

            expectedException = ExpectedException.ArgumentOutOfRangeException("IDX10627:");
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

            expectedException = ExpectedException.ArgumentOutOfRangeException("IDX10628:");
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
#endif
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

        [Fact(DisplayName = "SignatureProviderTests: AsymmetricSignatureProvider Constructor")]
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
            AsymmetricConstructorVariation("Signing:   - SignatureAlorithm == null", privateKey, null, expectedException: ExpectedException.ArgumentException("IDX10640:"));
            AsymmetricConstructorVariation("Signing:   - SignatureAlorithm == whitespace", privateKey, "    ", expectedException: ExpectedException.ArgumentException("IDX10640:"));

            // No Private keys
            AsymmetricConstructorVariation("Signing:   - SecurityKey without private key", publicKey, sha2SignatureAlgorithm, expectedException: ExpectedException.InvalidOperationException());
            AsymmetricConstructorVariation("Verifying: - SecurityKey without private key", publicKey, sha2SignatureAlgorithm, expectedException: ExpectedException.NoExceptionExpected);

            // Signature algorithm not supported
            AsymmetricConstructorVariation("Signing:   - SignatureAlgorithm not supported", KeyingMaterial.X509SecurityKey_1024, "SecurityAlgorithms.RsaSha256Signature", expectedException: ExpectedException.ArgumentException(substringExpected: "IDX10640"));
            AsymmetricConstructorVariation("Verifying: - SignatureAlgorithm not supported", KeyingMaterial.DefaultX509Key_Public_2048, "SecurityAlgorithms.RsaSha256Signature", expectedException: ExpectedException.ArgumentException(substringExpected: "IDX10640"));

            Console.WriteLine("Test missing: key.GetHashAlgorithmForSignature( signingCredentials.SignatureAlgorithm );");
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

        [Fact(DisplayName = "SignatureProviderTests: AsymmetricSignatureProvider.Dispose")]
        public void AsymmetricSignatureProvider_Dispose()
        {
            AsymmetricSignatureProvider provider = new AsymmetricSignatureProvider(KeyingMaterial.DefaultX509Key_Public_2048, SecurityAlgorithms.RsaSha256Signature);
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
                Assert.True(false, string.Format("AsymmetricSignatureProvider.Dispose called twice, caught exception: '{0}'", ex));
            }
        }

        [Fact(DisplayName = "SignatureProviderTests: AsymmetricSignatureProvider - Defaults")]
        public void AsymmetricSignatureProvider_Defaults()
        {
            try
            {
                AsymmetricSignatureProvider asymmetricSignatureProvider = new AsymmetricSignatureProvider(KeyingMaterial.DefaultX509SigningCreds_2048_RsaSha2_Sha2.SigningKey as AsymmetricSecurityKey, KeyingMaterial.DefaultX509SigningCreds_2048_RsaSha2_Sha2.SignatureAlgorithm, false);
            }
            catch (Exception)
            {
                Assert.True(false, "AsymmetricSignatureProvider creation should not throw");
            }

            try
            {
                AsymmetricSignatureProvider asymmetricSignatureProvider = new AsymmetricSignatureProvider(KeyingMaterial.DefaultX509SigningCreds_2048_RsaSha2_Sha2.SigningKey as AsymmetricSecurityKey, KeyingMaterial.DefaultX509SigningCreds_2048_RsaSha2_Sha2.SignatureAlgorithm, true);
            }
            catch (Exception)
            {
                Assert.True(false, "AsymmetricSignatureProvider creation should not throw");
            }
        }

        [Fact(DisplayName = "SignatureProviderTests: AsymmetricSignatureProvider - SupportedAlgorithms")]
        public void AsymmetricSignatureProvider_SupportedAlgorithms()
        {
            var errors = new List<string>();

            foreach (var algorithm in
                new string[] {
                    JwtAlgorithms.ECDSA_SHA256,
                    JwtAlgorithms.ECDSA_SHA384,
                    JwtAlgorithms.ECDSA_SHA512,
                    JwtAlgorithms.HMAC_SHA256,
                    JwtAlgorithms.HMAC_SHA384,
                    JwtAlgorithms.HMAC_SHA512,
                    JwtAlgorithms.RSA_SHA256,
                    JwtAlgorithms.RSA_SHA384,
                    JwtAlgorithms.RSA_SHA512,
                    SecurityAlgorithms.RsaSha1Signature,
                    SecurityAlgorithms.RsaSha256Signature,
                    SecurityAlgorithms.RsaSha384Signature,
                    SecurityAlgorithms.RsaSha512Signature })
            {
                try
                {
                    var provider = new AsymmetricSignatureProvider(KeyingMaterial.DefaultX509Key_2048, algorithm);
                }
                catch(Exception ex)
                {
                    errors.Add("Creation of AsymmetricSignatureProvider with algorithm: " + algorithm + ", threw: " + ex.Message);
                }

                TestUtilities.AssertFailIfErrors("AsymmetricSignatureProvider_SupportedAlgorithms", errors);
            }
        }

        [Fact(DisplayName = "SignatureProviderTests: Verify")]
        public void SignatureProviders_Verify()
        {
            List<string> errors = new List<string>();
            byte[] rawBytes = new byte[8192];
            (new Random()).NextBytes(rawBytes);

            byte[] signature = GetSignature(KeyingMaterial.RsaSecurityKey_2048, SecurityAlgorithms.RsaSha1Signature, rawBytes);
            SignatureProviders_Verify_Variation(KeyingMaterial.RsaSecurityKey_2048, SecurityAlgorithms.RsaSha1Signature, rawBytes, signature, ExpectedException.NoExceptionExpected, errors, true);
            SignatureProviders_Verify_Variation(KeyingMaterial.RsaSecurityKey_2048_Public, SecurityAlgorithms.RsaSha1Signature, rawBytes, signature, ExpectedException.NoExceptionExpected, errors, true);
            // wrong hash
            SignatureProviders_Verify_Variation(KeyingMaterial.RsaSecurityKey_2048, SecurityAlgorithms.RsaSha256Signature, rawBytes, signature, ExpectedException.NoExceptionExpected, errors, false);
            // wrong key
            SignatureProviders_Verify_Variation(KeyingMaterial.RsaSecurityKey_1024_Public, SecurityAlgorithms.RsaSha1Signature, rawBytes, signature, ExpectedException.NoExceptionExpected, errors, false);

            signature = GetSignature(KeyingMaterial.RsaSecurityKey_2048, SecurityAlgorithms.RsaSha256Signature, rawBytes);
            SignatureProviders_Verify_Variation(KeyingMaterial.RsaSecurityKey_2048, SecurityAlgorithms.RsaSha256Signature, rawBytes, signature, ExpectedException.NoExceptionExpected, errors, true);
            SignatureProviders_Verify_Variation(KeyingMaterial.RsaSecurityKey_2048_Public, SecurityAlgorithms.RsaSha256Signature, rawBytes, signature, ExpectedException.NoExceptionExpected, errors, true);
            // wrong hash
            SignatureProviders_Verify_Variation(KeyingMaterial.RsaSecurityKey_2048_Public, SecurityAlgorithms.RsaSha1Signature, rawBytes, signature, ExpectedException.NoExceptionExpected, errors, false);
            SignatureProviders_Verify_Variation(KeyingMaterial.RsaSecurityKey_2048_Public, SecurityAlgorithms.RsaSha384Signature, rawBytes, signature, ExpectedException.NoExceptionExpected, errors, false);
            SignatureProviders_Verify_Variation(KeyingMaterial.RsaSecurityKey_2048_Public, SecurityAlgorithms.RsaSha512Signature, rawBytes, signature, ExpectedException.NoExceptionExpected, errors, false);
            // wrong key
            SignatureProviders_Verify_Variation(KeyingMaterial.RsaSecurityKey_4096_Public, SecurityAlgorithms.RsaSha256Signature, rawBytes, signature, ExpectedException.NoExceptionExpected, errors, false);

            signature = GetSignature(KeyingMaterial.RsaSecurityKey_4096, SecurityAlgorithms.RsaSha256Signature, rawBytes);
            SignatureProviders_Verify_Variation(KeyingMaterial.RsaSecurityKey_4096, SecurityAlgorithms.RsaSha256Signature, rawBytes, signature, ExpectedException.NoExceptionExpected, errors, true);
            SignatureProviders_Verify_Variation(KeyingMaterial.RsaSecurityKey_4096_Public, SecurityAlgorithms.RsaSha256Signature, rawBytes, signature, ExpectedException.NoExceptionExpected, errors, true);
            // wrong hash
            SignatureProviders_Verify_Variation(KeyingMaterial.RsaSecurityKey_4096_Public, SecurityAlgorithms.RsaSha1Signature, rawBytes, signature, ExpectedException.NoExceptionExpected, errors, false);
            SignatureProviders_Verify_Variation(KeyingMaterial.RsaSecurityKey_4096_Public, SecurityAlgorithms.RsaSha384Signature, rawBytes, signature, ExpectedException.NoExceptionExpected, errors, false);
            SignatureProviders_Verify_Variation(KeyingMaterial.RsaSecurityKey_4096_Public, SecurityAlgorithms.RsaSha512Signature, rawBytes, signature, ExpectedException.NoExceptionExpected, errors, false);
            // wrong key
            SignatureProviders_Verify_Variation(KeyingMaterial.RsaSecurityKey_2048_Public, SecurityAlgorithms.RsaSha256Signature, rawBytes, signature, ExpectedException.NoExceptionExpected, errors, false);

            // sha384, 512
            signature = GetSignature(KeyingMaterial.RsaSecurityKey_2048, SecurityAlgorithms.RsaSha384Signature, rawBytes);
            SignatureProviders_Verify_Variation(KeyingMaterial.RsaSecurityKey_2048_Public, SecurityAlgorithms.RsaSha384Signature, rawBytes, signature, ExpectedException.NoExceptionExpected, errors, true);

            signature = GetSignature(KeyingMaterial.RsaSecurityKey_2048, SecurityAlgorithms.RsaSha512Signature, rawBytes);
            SignatureProviders_Verify_Variation(KeyingMaterial.RsaSecurityKey_2048_Public, SecurityAlgorithms.RsaSha512Signature, rawBytes, signature, ExpectedException.NoExceptionExpected, errors, true);

            TestUtilities.AssertFailIfErrors("SignatureProviders_Verify", errors);
        }

        private byte[] GetSignature(AsymmetricSecurityKey key, string algorithm, byte[] rawBytes)
        {
            AsymmetricSignatureProvider provider = new AsymmetricSignatureProvider(key, algorithm, true);
            return provider.Sign(rawBytes);
        }

        private void SignatureProviders_Verify_Variation(AsymmetricSecurityKey key, string algorithm, byte[] rawBytes, byte[] signature, ExpectedException ee, List<string> errors, bool shouldSignatureSucceed)
        {
            try
            {
                AsymmetricSignatureProvider provider = new AsymmetricSignatureProvider(key, algorithm);
                if (provider.Verify(rawBytes, signature) != shouldSignatureSucceed)
                    errors.Add("SignatureProvider.Verify did note return expected: " + shouldSignatureSucceed + " , algorithm: " + algorithm);

                ee.ProcessNoException(errors);
            }
            catch (Exception ex)
            {
                ee.ProcessException(ex, errors);
            }
        }

        [Fact(DisplayName = "SignatureProviderTests: Asymmetric and Symmetric Sign")]
        public void SignatureProviders_Sign()
        {
            List<string> errors = new List<string>();

            // Asymmetric
            SignatureProviders_Sign_Variation(KeyingMaterial.RsaSecurityKey_1024, SecurityAlgorithms.RsaSha256Signature, ExpectedException.ArgumentOutOfRangeException(substringExpected: "IDX10631:"), errors);
            SignatureProviders_Sign_Variation(KeyingMaterial.RsaSecurityKey_2048, SecurityAlgorithms.RsaSha256Signature, ExpectedException.NoExceptionExpected, errors);
            SignatureProviders_Sign_Variation(KeyingMaterial.RsaSecurityKey_2048_Public, SecurityAlgorithms.RsaSha256Signature, ExpectedException.InvalidOperationException(substringExpected: "IDX10638:"), errors);
            SignatureProviders_Sign_Variation(KeyingMaterial.RsaSecurityKey_2048, "NOT_SUPPORTED", ExpectedException.ArgumentException(substringExpected: "IDX10640:"), errors);
#if SymmetricKeySuport
            // Symmetric
            SignatureProviders_Sign_Variation(KeyingMaterial.DefaultSymmetricSecurityKey_256, SecurityAlgorithms.HmacSha256Signature, ExpectedException.InvalidOperationException(substringExpected: "IDX10640:"), errors);
            SignatureProviders_Sign_Variation(KeyingMaterial.SymmetricSecurityKey_56, SecurityAlgorithms.HmacSha256Signature, ExpectedException.InvalidOperationException(substringExpected: "IDX10640:"), errors);
            try
            {
                Random r = new Random();
                SymmetricSignatureProvider provider = new SymmetricSignatureProvider(KeyingMaterial.DefaultSymmetricSecurityKey_256, SecurityAlgorithms.HmacSha256Signature);
                byte[] bytesin = new byte[1024];
                r.NextBytes(bytesin);
                byte[] signature = provider.Sign(bytesin);
                Assert.True(provider.Verify(bytesin, signature), string.Format("Signature did not verify"));
            }
            catch (Exception ex)
            {
                Assert.True(false, string.Format("Unexpected exception received: '{0}'", ex));
            }

            // symmetric different byte[] sizes
            try
            {
                SymmetricSignatureProvider provider = new SymmetricSignatureProvider(KeyingMaterial.DefaultSymmetricSecurityKey_256, SecurityAlgorithms.HmacSha256Signature);
                byte[] bytesin = new byte[1024];
                byte[] signature = new byte[1024];
                Assert.False(provider.Verify(bytesin, signature), string.Format("Signature did not verify"));
            }
            catch (Exception ex)
            {
                Assert.True(false, string.Format("Unexpected exception received: '{0}'", ex));
            }

            // unknown algorithm
            try
            {
                Random r = new Random();
                SymmetricSignatureProvider provider = new SymmetricSignatureProvider(KeyingMaterial.DefaultSymmetricSecurityKey_256, "SecurityAlgorithms.HmacSha256Signature");
                Assert.True(false, string.Format("Should have thrown, it is possible that crypto config mapped this."));
            }
            catch (Exception ex)
            {
                Assert.False(ex.GetType() != typeof(InvalidOperationException), "ex.GetType() != typeof( InvalidOperationException )");
            }
#endif

            TestUtilities.AssertFailIfErrors("SignatureProviders_Sign", errors);
        }

        private void SignatureProviders_Sign_Variation(AsymmetricSecurityKey key, string algorithm, ExpectedException ee, List<string> errors)
        {
            try
            {
                Random r = new Random();
                AsymmetricSignatureProvider provider = new AsymmetricSignatureProvider(key, algorithm, true);
                byte[] bytesin = new byte[1024];
                r.NextBytes(bytesin);
                byte[] signature = provider.Sign(bytesin);
                ee.ProcessNoException(errors);
            }
            catch (Exception ex)
            {
                ee.ProcessException(ex, errors);
            }
        }

        private void SignatureProviders_Sign_Variation(SymmetricSecurityKey key, string algorithm, ExpectedException ee, List<string> errors)
        {
            try
            {
                Random r = new Random();
                SymmetricSignatureProvider provider = new SymmetricSignatureProvider(key, algorithm);
                byte[] bytesin = new byte[1024];
                r.NextBytes(bytesin);
                byte[] signature = provider.Sign(bytesin);
                ee.ProcessNoException(errors);
            }
            catch (Exception ex)
            {
                ee.ProcessException(ex, errors);
            }
        }

        [Fact(DisplayName = "AsymmetricSignatureProvider: Publics")]
        public void AsymmetricSignatureProvider_Publics()
        {
            AsymmetricSignatureProvider_Variations(KeyingMaterial.RsaSecurityKey_2048, SecurityAlgorithms.RsaSha256Signature);
        }

        private void AsymmetricSignatureProvider_Variations(AsymmetricSecurityKey key, string algorithm)
        {
            AsymmetricSignatureProvider provider = new AsymmetricSignatureProvider(key, algorithm);
            SignatureProvider_SignVariation(provider, null, null, ExpectedException.ArgumentNullException());
            SignatureProvider_SignVariation(provider, new byte[0], null, ExpectedException.ArgumentException("IDX10624:"));
            SignatureProvider_SignVariation(provider, new byte[1], null, ExpectedException.NoExceptionExpected);

            SignatureProvider_VerifyVariation(provider, null, null, ExpectedException.ArgumentNullException());
            SignatureProvider_VerifyVariation(provider, new byte[1], null, ExpectedException.ArgumentNullException());
            SignatureProvider_VerifyVariation(provider, new byte[0], new byte[1], ExpectedException.ArgumentException("IDX10625:"));
            SignatureProvider_VerifyVariation(provider, new byte[1], new byte[0], ExpectedException.ArgumentException("IDX10626:"));
        }

#if SymmetricKeySuport
        [Fact(DisplayName = "SymmetricSignatureProvider: Constructor")]
        public void SymmetricSignatureProvider_ConstructorTests()
        {

            // no errors
            SymmetricSignatureProvider_ConstructorVariation("Creates with no errors", KeyingMaterial.DefaultSymmetricSecurityKey_256, SecurityAlgorithms.HmacSha256Signature, ExpectedException.NoExceptionExpected);

            // null, empty algorithm digest
            SymmetricSignatureProvider_ConstructorVariation("Constructor:   - NUll key", null, SecurityAlgorithms.HmacSha256Signature, ExpectedException.ArgumentNullException());
            SymmetricSignatureProvider_ConstructorVariation("Constructor:   - algorithm == string.Empty", KeyingMaterial.DefaultSymmetricSecurityKey_256, string.Empty, ExpectedException.ArgumentException());

            // GetKeyedHashAlgorithm throws
            SymmetricSecurityKey key = new FaultingSymmetricSecurityKey(KeyingMaterial.DefaultSymmetricSecurityKey_256, new CryptographicException("hi from inner"));
            SymmetricSignatureProvider_ConstructorVariation("Constructor:   - SecurityKey.GetKeyedHashAlgorithm throws", key, SecurityAlgorithms.HmacSha256Signature, ExpectedException.InvalidOperationException("IDX10632:", typeof(CryptographicException)));

            // Key returns null KeyedHash
            key = new FaultingSymmetricSecurityKey(KeyingMaterial.DefaultSymmetricSecurityKey_256, null);
            SymmetricSignatureProvider_ConstructorVariation("Constructor:   - SecurityKey returns null KeyedHashAlgorithm", key, SecurityAlgorithms.HmacSha256Signature, ExpectedException.InvalidOperationException("IDX10633:"));

            //_keyedHash.Key = _key.GetSymmetricKey() is null;            
            KeyedHashAlgorithm keyedHashAlgorithm = KeyingMaterial.DefaultSymmetricSecurityKey_256.GetKeyedHashAlgorithm(SecurityAlgorithms.HmacSha256Signature);
            key = new FaultingSymmetricSecurityKey(KeyingMaterial.DefaultSymmetricSecurityKey_256, null, null, keyedHashAlgorithm, null);
            SymmetricSignatureProvider_ConstructorVariation("Constructor:   - key returns null bytes to pass to _keyedHashKey", key, SecurityAlgorithms.HmacSha256Signature, ExpectedException.InvalidOperationException("IDX10634:", typeof(NullReferenceException)));
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
#endif

#if SymmetricKeySuport
        [Fact(DisplayName = "SymmetricSignatureProvider: Publics")]
        public void SymmetricSignatureProvider_Publics()
        {
            SymmetricSignatureProvider provider = new SymmetricSignatureProvider(KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2.SigningKey as SymmetricSecurityKey, KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2.SignatureAlgorithm);

            SignatureProvider_SignVariation(provider, null, null, ExpectedException.ArgumentNullException());
            SignatureProvider_SignVariation(provider, new byte[0], null, ExpectedException.ArgumentException("IDX10624:"));
            SignatureProvider_SignVariation(provider, new byte[1], null, ExpectedException.NoExceptionExpected);

            SignatureProvider_VerifyVariation(provider, null, null, ExpectedException.ArgumentNullException());
            SignatureProvider_VerifyVariation(provider, new byte[0], null, ExpectedException.ArgumentNullException());
            SignatureProvider_VerifyVariation(provider, new byte[0], new byte[0], ExpectedException.ArgumentException("IDX10625:"));
            SignatureProvider_VerifyVariation(provider, new byte[1], new byte[0], ExpectedException.ArgumentException("IDX10626:"));
            SignatureProvider_VerifyVariation(provider, new byte[1], new byte[1], ExpectedException.NoExceptionExpected);

            provider.Dispose();
            SignatureProvider_SignVariation(provider, new byte[1], new byte[1], ExpectedException.ObjectDisposedException);
            SignatureProvider_VerifyVariation(provider, new byte[1], new byte[1], ExpectedException.ObjectDisposedException);
        }
#endif
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
