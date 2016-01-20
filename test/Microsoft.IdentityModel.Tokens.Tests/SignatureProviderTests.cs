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
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using Xunit;

namespace Microsoft.IdentityModel.Tokens.Tests
{
    /// <summary>
    /// This class tests:
    /// CryptoProviderFactory
    /// SignatureProvider
    /// SymmetricSignatureProvider
    /// AsymmetricSignatureProvider
    /// </summary>
    public class SignatureProviderTests
    {
        [Fact(DisplayName = "CryptoProviderTests: CryptoProviderFactory")]
        public void CryptoProviderFactory_Tests()
        {
            CryptoProviderFactory factory = new CryptoProviderFactory();

            // Asymmetric / Symmetric both need signature alg specified
            FactoryCreateFor("Siging:    - algorithm string.Empty", KeyingMaterial.X509SecurityKey_1024, string.Empty, factory, ExpectedException.ArgumentException());
            FactoryCreateFor("Verifying: - algorithm string.Empty", KeyingMaterial.X509SecurityKey_1024, string.Empty, factory, ExpectedException.ArgumentException());

            // Keytype not supported
            FactoryCreateFor("Siging:    - SecurityKey type not Asymmetric or Symmetric", NotAsymmetricOrSymmetricSecurityKey.New, SecurityAlgorithms.HmacSha256Signature, factory, ExpectedException.ArgumentException("IDX10600:"));
            FactoryCreateFor("Verifying: - SecurityKey type not Asymmetric or Symmetric", NotAsymmetricOrSymmetricSecurityKey.New, SecurityAlgorithms.RsaSha256Signature, factory, ExpectedException.ArgumentException("IDX10600:"));

            // Private keys missing
            FactoryCreateFor("Siging:    - SecurityKey without private key", KeyingMaterial.RsaSecurityKey_2048_Public, SecurityAlgorithms.RsaSha256Signature, factory, ExpectedException.InvalidOperationException(substringExpected: "IDX10638:"));
            FactoryCreateFor("Verifying: - SecurityKey without private key", KeyingMaterial.RsaSecurityKey_2048_Public, SecurityAlgorithms.RsaSha256Signature, factory, ExpectedException.NoExceptionExpected);
            FactoryCreateFor("Siging:    - SecurityKey without private key", KeyingMaterial.ECDsa256Key_Public, SecurityAlgorithms.ECDSA_SHA256, factory, ExpectedException.InvalidOperationException(substringExpected: "IDX10638:"));

            // Key size checks
            FactoryCreateFor("Siging:    - AsymmetricKeySize Key to small", KeyingMaterial.X509SecurityKey_1024, SecurityAlgorithms.RsaSha256Signature, factory, ExpectedException.ArgumentOutOfRangeException("IDX10630:"));

            FactoryCreateFor("Siging:    - SymmetricKeySize Key", KeyingMaterial.DefaultSymmetricSecurityKey_256, SecurityAlgorithms.HmacSha256Signature, factory, ExpectedException.NoExceptionExpected);
            FactoryCreateFor("Verifying: - SymmetricKeySize Key", KeyingMaterial.DefaultSymmetricSecurityKey_256, SecurityAlgorithms.HmacSha256Signature, factory, ExpectedException.NoExceptionExpected);
        }

        private void FactoryCreateFor(string testcase, SecurityKey key, string algorithm, CryptoProviderFactory factory, ExpectedException expectedException)
        {
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

        #region Common Signature Provider Tests
        [Fact(DisplayName = "SignatureProviderTests: SignatureProvider.Dispose")]
        public void SignatureProvider_Dispose()
        {
            AsymmetricSignatureProvider asymmetricSignatureProvider = new AsymmetricSignatureProvider(KeyingMaterial.DefaultX509Key_Public_2048, SecurityAlgorithms.RsaSha256Signature);
            asymmetricSignatureProvider.Dispose();

            ExpectedException expectedException = ExpectedException.ObjectDisposedException;
            SignatureProvider_DisposeVariation("Sign", asymmetricSignatureProvider, expectedException);
            SignatureProvider_DisposeVariation("Verify", asymmetricSignatureProvider, expectedException);
            SignatureProvider_DisposeVariation("Dispose", asymmetricSignatureProvider, ExpectedException.NoExceptionExpected);

            SymmetricSignatureProvider symmetricProvider = new SymmetricSignatureProvider(KeyingMaterial.DefaultSymmetricSecurityKey_256, KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2.Algorithm);
            symmetricProvider.Dispose();
            SignatureProvider_DisposeVariation("Sign", symmetricProvider, expectedException);
            SignatureProvider_DisposeVariation("Verify", symmetricProvider, expectedException);
            SignatureProvider_DisposeVariation("Dispose", symmetricProvider, ExpectedException.NoExceptionExpected);
        }

        private void SignatureProvider_DisposeVariation(string testCase, SignatureProvider provider, ExpectedException expectedException)
        {
            try
            {
                if (testCase.StartsWith("Sign"))
                    provider.Sign(new byte[256]);
                else if (testCase.StartsWith("Verify"))
                    provider.Verify(new byte[256], new byte[256]);
                else if (testCase.StartsWith("Dispose"))
                    provider.Dispose();
                else
                    Assert.True(false, "Test case does not match any scenario");

                expectedException.ProcessNoException();
            }
            catch(Exception ex)
            {
                expectedException.ProcessException(ex);
            }
        }


        [Fact(DisplayName = "SignatureProviderTests: Asymmetric and Symmetric Sign")]
        public void SignatureProviders_Sign()
        {
            List<string> errors = new List<string>();
            byte[] rawBytes = new byte[8192];
            (new Random()).NextBytes(rawBytes);

            // Asymmetric
            SignatureProviders_Sign_Variation(KeyingMaterial.RsaSecurityKey_2048, SecurityAlgorithms.RsaSha256Signature, null, ExpectedException.ArgumentNullException(), errors);
            SignatureProviders_Sign_Variation(KeyingMaterial.RsaSecurityKey_2048, SecurityAlgorithms.RsaSha256Signature, new byte[0], ExpectedException.ArgumentException("IDX10624:"), errors);
            SignatureProviders_Sign_Variation(KeyingMaterial.RsaSecurityKey_1024, SecurityAlgorithms.RsaSha256Signature, rawBytes, ExpectedException.ArgumentOutOfRangeException("IDX10630:"), errors);
            SignatureProviders_Sign_Variation(KeyingMaterial.RsaSecurityKey_2048, SecurityAlgorithms.RsaSha256Signature, rawBytes, ExpectedException.NoExceptionExpected, errors);
            SignatureProviders_Sign_Variation(KeyingMaterial.RsaSecurityKeyWithCspProvider_2048, SecurityAlgorithms.RsaSha256Signature, rawBytes, ExpectedException.NoExceptionExpected, errors);
#if DNXCORE50
            SignatureProviders_Sign_Variation(KeyingMaterial.RsaSecurityKeyWithCngProvider_2048, SecurityAlgorithms.RsaSha256Signature, rawBytes, ExpectedException.NoExceptionExpected, errors);
            Assert.ThrowsAny<CryptographicException>(() =>
            {
                AsymmetricSignatureProvider provider = new AsymmetricSignatureProvider(KeyingMaterial.RsaSecurityKeyWithCngProvider_2048_Public, SecurityAlgorithms.RsaSha256Signature);
                provider.Sign(rawBytes);
            });
#endif
            // since the actual exception thrown is private - WindowsCryptographicException, using this pattern to match the derived exception
            Assert.ThrowsAny<CryptographicException>(() =>
            {
                AsymmetricSignatureProvider provider = new AsymmetricSignatureProvider(KeyingMaterial.RsaSecurityKeyWithCspProvider_2048_Public, SecurityAlgorithms.RsaSha256Signature);
                provider.Sign(rawBytes);
            });

            SignatureProviders_Sign_Variation(KeyingMaterial.RsaSecurityKey_2048_Public, SecurityAlgorithms.RsaSha256Signature, rawBytes, ExpectedException.InvalidOperationException("IDX10638:"), errors);
            SignatureProviders_Sign_Variation(KeyingMaterial.RsaSecurityKey_2048, "NOT_SUPPORTED", rawBytes, ExpectedException.ArgumentException("IDX10640:"), errors);
            SignatureProviders_Sign_Variation(KeyingMaterial.ECDsa256Key, SecurityAlgorithms.ECDSA_SHA256, rawBytes, ExpectedException.NoExceptionExpected, errors);
            SignatureProviders_Sign_Variation(KeyingMaterial.ECDsa256Key_Public, SecurityAlgorithms.ECDSA_SHA256, rawBytes, ExpectedException.InvalidOperationException("IDX10638:"), errors);

            // Symmetric
            SignatureProviders_Sign_Variation(KeyingMaterial.DefaultSymmetricSecurityKey_256, SecurityAlgorithms.HmacSha256Signature, null, ExpectedException.ArgumentNullException(), errors);
            SignatureProviders_Sign_Variation(KeyingMaterial.DefaultSymmetricSecurityKey_256, SecurityAlgorithms.HmacSha256Signature, new byte[0], ExpectedException.ArgumentException("IDX10624:"), errors);
            SignatureProviders_Sign_Variation(KeyingMaterial.DefaultSymmetricSecurityKey_256, SecurityAlgorithms.HmacSha256Signature, rawBytes, ExpectedException.NoExceptionExpected, errors);
            SignatureProviders_Sign_Variation(KeyingMaterial.SymmetricSecurityKey_56, SecurityAlgorithms.HmacSha256Signature, rawBytes, ExpectedException.ArgumentOutOfRangeException("IDX10603:"), errors);
            TestUtilities.AssertFailIfErrors("SignatureProviders_Sign", errors);
        }

        private void SignatureProviders_Sign_Variation(AsymmetricSecurityKey key, string algorithm, byte[] input, ExpectedException ee, List<string> errors)
        {
            try
            {
                AsymmetricSignatureProvider provider = new AsymmetricSignatureProvider(key, algorithm, true);
                byte[] signature = provider.Sign(input);
                ee.ProcessNoException(errors);
            }
            catch (Exception ex)
            {
                ee.ProcessException(ex, errors);
            }
        }

        private void SignatureProviders_Sign_Variation(SymmetricSecurityKey key, string algorithm, byte[] input, ExpectedException ee, List<string> errors)
        {
            try
            {
                SymmetricSignatureProvider provider = new SymmetricSignatureProvider(key, algorithm);
                byte[] signature = provider.Sign(input);
                ee.ProcessNoException(errors);
            }
            catch (Exception ex)
            {
                ee.ProcessException(ex, errors);
            }
        }
#endregion

#region Asymmetric Signature Provider Tests
        [Fact(DisplayName = "SignatureProviderTests: AsymmetricSignatureProvider Constructor")]
        public void AsymmetricSignatureProvider_Constructor()
        {
            AsymmetricSecurityKey privateKey = KeyingMaterial.DefaultX509SigningCreds_2048_RsaSha2_Sha2.Key as AsymmetricSecurityKey;
            AsymmetricSecurityKey publicKey = KeyingMaterial.DefaultX509SigningCreds_Public_2048_RsaSha2_Sha2.Key as AsymmetricSecurityKey;
            string sha2SignatureAlgorithm = KeyingMaterial.DefaultX509SigningCreds_2048_RsaSha2_Sha2.Algorithm;

            // no errors
            AsymmetricConstructorVariation("Signing:  - Creates with no errors", privateKey, sha2SignatureAlgorithm, expectedException: ExpectedException.NoExceptionExpected);
            AsymmetricConstructorVariation("Verifying: - Creates with no errors (Private Key)", privateKey, sha2SignatureAlgorithm, expectedException: ExpectedException.NoExceptionExpected);
            AsymmetricConstructorVariation("Verifying: - Creates with no errors (Public Key)", publicKey, sha2SignatureAlgorithm, expectedException: ExpectedException.NoExceptionExpected);
            AsymmetricConstructorVariation("Signing:  - Creates with no errors", KeyingMaterial.ECDsa256Key, SecurityAlgorithms.ECDSA_SHA256, expectedException: ExpectedException.NoExceptionExpected);
            AsymmetricConstructorVariation("Verifying: - Creates with no errors (Public Key)", KeyingMaterial.ECDsa256Key_Public, SecurityAlgorithms.ECDSA_SHA256, expectedException: ExpectedException.NoExceptionExpected);
            AsymmetricConstructorVariation("Verifying: - Creates with no errors (Private Key)", KeyingMaterial.ECDsa256Key, SecurityAlgorithms.ECDSA_SHA256, expectedException: ExpectedException.NoExceptionExpected);
            AsymmetricConstructorVariation("Verifying: - Creates with no errors (Public Key)", KeyingMaterial.ECDsa384Key_Public, SecurityAlgorithms.ECDSA_SHA384, expectedException: ExpectedException.NoExceptionExpected);

            // null, empty algorithm digest
            AsymmetricConstructorVariation("Signing:   - NUll key", null, sha2SignatureAlgorithm, expectedException: ExpectedException.ArgumentNullException());
            AsymmetricConstructorVariation("Signing:   - SignatureAlorithm == null", privateKey, null, expectedException: ExpectedException.ArgumentException("IDX10640:"));
            AsymmetricConstructorVariation("Signing:   - SignatureAlorithm == whitespace", privateKey, "    ", expectedException: ExpectedException.ArgumentException("IDX10640:"));

            // No Private keys
            AsymmetricConstructorVariation("Signing:   - SecurityKey without private key", publicKey, sha2SignatureAlgorithm, expectedException: ExpectedException.InvalidOperationException("IDX10638:"));
            AsymmetricConstructorVariation("Verifying: - SecurityKey without private key", publicKey, sha2SignatureAlgorithm, expectedException: ExpectedException.NoExceptionExpected);
            AsymmetricConstructorVariation("Signing: - no private key", KeyingMaterial.ECDsa521Key_Public, SecurityAlgorithms.ECDSA_SHA512, expectedException: ExpectedException.InvalidOperationException("IDX10638:"));

            // Signature algorithm not supported
            AsymmetricConstructorVariation("Signing:   - SignatureAlgorithm not supported", KeyingMaterial.X509SecurityKey_1024, "SecurityAlgorithms.RsaSha256Signature", expectedException: ExpectedException.ArgumentException(substringExpected: "IDX10640"));
            AsymmetricConstructorVariation("Verifying: - SignatureAlgorithm not supported", KeyingMaterial.DefaultX509Key_Public_2048, "SecurityAlgorithms.RsaSha256Signature", expectedException: ExpectedException.ArgumentException(substringExpected: "IDX10640"));
        }

        private void AsymmetricConstructorVariation(string testcase, AsymmetricSecurityKey key, string algorithm, ExpectedException expectedException)
        {

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


        [Fact(DisplayName = "SignatureProviderTests: AsymmetricSignatureProvider - SupportedAlgorithms")]
        public void AsymmetricSignatureProvider_SupportedAlgorithms()
        {
            var errors = new List<string>();

            foreach (var algorithm in
                new string[] {
                    JwtAlgorithms.ECDSA_SHA256,
                    JwtAlgorithms.ECDSA_SHA384,
                    JwtAlgorithms.ECDSA_SHA512,
                    JwtAlgorithms.RSA_SHA256,
                    JwtAlgorithms.RSA_SHA384,
                    JwtAlgorithms.RSA_SHA512,
                    SecurityAlgorithms.RsaSha256Signature,
                    SecurityAlgorithms.RsaSha384Signature,
                    SecurityAlgorithms.RsaSha512Signature })
            {
                try
                {
                    var provider = new AsymmetricSignatureProvider(KeyingMaterial.DefaultX509Key_2048, algorithm);
                }
                catch (Exception ex)
                {
                    errors.Add("Creation of AsymmetricSignatureProvider with algorithm: " + algorithm + ", threw: " + ex.Message);
                }

                TestUtilities.AssertFailIfErrors("AsymmetricSignatureProvider_SupportedAlgorithms", errors);
            }
        }

        [Fact(DisplayName = "SignatureProviderTests: Verify Asymmetric Signature Providers")]
        public void AsymmetricSignatureProviders_Verify()
        {
            List<string> errors = new List<string>();
            byte[] rawBytes = new byte[8192];
            (new Random()).NextBytes(rawBytes);

            AsymmetricSignatureProviders_Verify_Variation(KeyingMaterial.RsaSecurityKey_2048, SecurityAlgorithms.RsaSha256Signature, null, null, ExpectedException.ArgumentNullException(), errors, false);
            AsymmetricSignatureProviders_Verify_Variation(KeyingMaterial.RsaSecurityKey_2048, SecurityAlgorithms.RsaSha256Signature, new byte[1], null, ExpectedException.ArgumentNullException(), errors, false);
            AsymmetricSignatureProviders_Verify_Variation(KeyingMaterial.RsaSecurityKey_2048, SecurityAlgorithms.RsaSha256Signature, new byte[0], new byte[1], ExpectedException.ArgumentException("IDX10625:"), errors, false);
            AsymmetricSignatureProviders_Verify_Variation(KeyingMaterial.RsaSecurityKey_2048, SecurityAlgorithms.RsaSha256Signature, new byte[1], new byte[0], ExpectedException.ArgumentException("IDX10626:"), errors, false);

            var signature = GetSignature(KeyingMaterial.RsaSecurityKey_2048, SecurityAlgorithms.RsaSha256Signature, rawBytes);
            AsymmetricSignatureProviders_Verify_Variation(KeyingMaterial.RsaSecurityKey_2048, SecurityAlgorithms.RsaSha256Signature, rawBytes, signature, ExpectedException.NoExceptionExpected, errors, true);
            AsymmetricSignatureProviders_Verify_Variation(KeyingMaterial.RsaSecurityKey_2048_Public, SecurityAlgorithms.RsaSha256Signature, rawBytes, signature, ExpectedException.NoExceptionExpected, errors, true);
            AsymmetricSignatureProviders_Verify_Variation(KeyingMaterial.RsaSecurityKeyWithCspProvider_2048_Public, SecurityAlgorithms.RsaSha256Signature, rawBytes, signature, ExpectedException.NoExceptionExpected, errors, true);
#if DNXCORE50
            AsymmetricSignatureProviders_Verify_Variation(KeyingMaterial.RsaSecurityKeyWithCngProvider_2048_Public, SecurityAlgorithms.RsaSha256Signature, rawBytes, signature, ExpectedException.NoExceptionExpected, errors, true);
#endif
            // wrong hash
            AsymmetricSignatureProviders_Verify_Variation(KeyingMaterial.RsaSecurityKey_2048_Public, SecurityAlgorithms.RsaSha384Signature, rawBytes, signature, ExpectedException.NoExceptionExpected, errors, false);
            AsymmetricSignatureProviders_Verify_Variation(KeyingMaterial.RsaSecurityKey_2048_Public, SecurityAlgorithms.RsaSha512Signature, rawBytes, signature, ExpectedException.NoExceptionExpected, errors, false);
            // wrong key
            AsymmetricSignatureProviders_Verify_Variation(KeyingMaterial.RsaSecurityKey_4096_Public, SecurityAlgorithms.RsaSha256Signature, rawBytes, signature, ExpectedException.NoExceptionExpected, errors, false);

            signature = GetSignature(KeyingMaterial.RsaSecurityKey_4096, SecurityAlgorithms.RsaSha256Signature, rawBytes);
            AsymmetricSignatureProviders_Verify_Variation(KeyingMaterial.RsaSecurityKey_4096, SecurityAlgorithms.RsaSha256Signature, rawBytes, signature, ExpectedException.NoExceptionExpected, errors, true);
            AsymmetricSignatureProviders_Verify_Variation(KeyingMaterial.RsaSecurityKey_4096_Public, SecurityAlgorithms.RsaSha256Signature, rawBytes, signature, ExpectedException.NoExceptionExpected, errors, true);
            // wrong hash
            AsymmetricSignatureProviders_Verify_Variation(KeyingMaterial.RsaSecurityKey_4096_Public, SecurityAlgorithms.RsaSha384Signature, rawBytes, signature, ExpectedException.NoExceptionExpected, errors, false);
            AsymmetricSignatureProviders_Verify_Variation(KeyingMaterial.RsaSecurityKey_4096_Public, SecurityAlgorithms.RsaSha512Signature, rawBytes, signature, ExpectedException.NoExceptionExpected, errors, false);
            // wrong key
            AsymmetricSignatureProviders_Verify_Variation(KeyingMaterial.RsaSecurityKey_2048_Public, SecurityAlgorithms.RsaSha256Signature, rawBytes, signature, ExpectedException.NoExceptionExpected, errors, false);

            // sha384, 512
            signature = GetSignature(KeyingMaterial.RsaSecurityKeyWithCspProvider_2048, SecurityAlgorithms.RsaSha384Signature, rawBytes);
            AsymmetricSignatureProviders_Verify_Variation(KeyingMaterial.RsaSecurityKey_2048_Public, SecurityAlgorithms.RsaSha384Signature, rawBytes, signature, ExpectedException.NoExceptionExpected, errors, true);

            signature = GetSignature(KeyingMaterial.RsaSecurityKey_2048, SecurityAlgorithms.RsaSha512Signature, rawBytes);
            AsymmetricSignatureProviders_Verify_Variation(KeyingMaterial.RsaSecurityKey_2048_Public, SecurityAlgorithms.RsaSha512Signature, rawBytes, signature, ExpectedException.NoExceptionExpected, errors, true);

            //ecdsa
            signature = GetSignature(KeyingMaterial.ECDsa256Key, SecurityAlgorithms.ECDSA_SHA256, rawBytes);
            AsymmetricSignatureProviders_Verify_Variation(KeyingMaterial.ECDsa256Key, SecurityAlgorithms.ECDSA_SHA256, rawBytes, signature, ExpectedException.NoExceptionExpected, errors, true);
            AsymmetricSignatureProviders_Verify_Variation(KeyingMaterial.ECDsa256Key_Public, SecurityAlgorithms.ECDSA_SHA256, rawBytes, signature, ExpectedException.NoExceptionExpected, errors, true);

            // wrong key
            AsymmetricSignatureProviders_Verify_Variation(KeyingMaterial.ECDsa256Key, SecurityAlgorithms.ECDSA_SHA384, rawBytes, signature, ExpectedException.NoExceptionExpected, errors, false);
#if DNXCORE50
            AsymmetricSignatureProviders_Verify_Variation(KeyingMaterial.ECDsa384Key, SecurityAlgorithms.ECDSA_SHA384, rawBytes, signature, ExpectedException.NoExceptionExpected, errors, false);
#else
            AsymmetricSignatureProviders_Verify_Variation(KeyingMaterial.ECDsa384Key, SecurityAlgorithms.ECDSA_SHA384, rawBytes, signature, new ExpectedException(typeof(CryptographicException)), errors, false);
#endif

            signature = GetSignature(KeyingMaterial.ECDsa384Key, SecurityAlgorithms.ECDSA_SHA384, rawBytes);
            AsymmetricSignatureProviders_Verify_Variation(KeyingMaterial.ECDsa384Key, SecurityAlgorithms.ECDSA_SHA384, rawBytes, signature, ExpectedException.NoExceptionExpected, errors, true);

            TestUtilities.AssertFailIfErrors("AsymmetricSignatureProviders_Verify", errors);
        }

        private byte[] GetSignature(AsymmetricSecurityKey key, string algorithm, byte[] rawBytes)
        {
            AsymmetricSignatureProvider provider = new AsymmetricSignatureProvider(key, algorithm, true);
            return provider.Sign(rawBytes);
        }

        private void AsymmetricSignatureProviders_Verify_Variation(AsymmetricSecurityKey key, string algorithm, byte[] rawBytes, byte[] signature, ExpectedException ee, List<string> errors, bool shouldSignatureSucceed)
        {
            try
            {
                AsymmetricSignatureProvider provider = new AsymmetricSignatureProvider(key, algorithm);
                if (provider.Verify(rawBytes, signature) != shouldSignatureSucceed)
                    errors.Add("SignatureProvider.Verify did not return expected: " + shouldSignatureSucceed + " , algorithm: " + algorithm);

                ee.ProcessNoException(errors);
            }
            catch (Exception ex)
            {
                ee.ProcessException(ex, errors);
            }
        }
#endregion

#region Symmetric Signature Provider Tests
        [Fact(DisplayName = "SymmetricSignatureProvider: Constructor")]
        public void SymmetricSignatureProvider_ConstructorTests()
        {
            // no errors
            SymmetricSignatureProvider_ConstructorVariation(KeyingMaterial.DefaultSymmetricSecurityKey_256, SecurityAlgorithms.HmacSha256Signature, ExpectedException.NoExceptionExpected);
            // null key
            SymmetricSignatureProvider_ConstructorVariation(null, SecurityAlgorithms.HmacSha256Signature, ExpectedException.ArgumentNullException());
            // empty algorithm
            SymmetricSignatureProvider_ConstructorVariation(KeyingMaterial.DefaultSymmetricSecurityKey_256, string.Empty, ExpectedException.ArgumentException());
            // unsupported algorithm
            SymmetricSignatureProvider_ConstructorVariation(KeyingMaterial.DefaultSymmetricSecurityKey_256, "unknown algorithm", ExpectedException.ArgumentException("IDX10640:"));
            // smaller key < 256 bytes
            SymmetricSignatureProvider_ConstructorVariation(KeyingMaterial.SymmetricSecurityKey_56, SecurityAlgorithms.HmacSha256Signature, ExpectedException.ArgumentOutOfRangeException("IDX10603"));
            // GetKeyedHashAlgorithm throws
            SymmetricSecurityKey key = new FaultingSymmetricSecurityKey(KeyingMaterial.DefaultSymmetricSecurityKey_256, new CryptographicException("hi from inner"), null, null, KeyingMaterial.DefaultSymmetricKeyBytes_256);
            SymmetricSignatureProvider_ConstructorVariation(key, SecurityAlgorithms.HmacSha256Signature, ExpectedException.InvalidOperationException("IDX10634:", typeof(CryptographicException)));
        }

        private void SymmetricSignatureProvider_ConstructorVariation(SymmetricSecurityKey key, string algorithm, ExpectedException expectedException)
        {
            try
            {
                SymmetricSignatureProvider provider = new SymmetricSignatureProvider(key, algorithm);
                expectedException.ProcessNoException();
            }
            catch (Exception ex)
            {
                expectedException.ProcessException(ex);
            }
        }

        [Fact(DisplayName = "SignatureProviderTests: SymmetricSignatureProvider - SupportedAlgorithms")]
        public void SymmetricSignatureProvider_SupportedAlgorithms()
        {
            var errors = new List<string>();

            foreach (var algorithm in
                new string[] {
                    SecurityAlgorithms.HmacSha256Signature,
                    SecurityAlgorithms.HmacSha384Signature,
                    SecurityAlgorithms.HmacSha512Signature,
                    SecurityAlgorithms.HMAC_SHA256,
                    SecurityAlgorithms.HMAC_SHA384,
                    SecurityAlgorithms.HMAC_SHA512 })
            {
                try
                {
                    var provider = new SymmetricSignatureProvider(KeyingMaterial.DefaultSymmetricSecurityKey_256, algorithm);
                }
                catch (Exception ex)
                {
                    errors.Add("Creation of AsymmetricSignatureProvider with algorithm: " + algorithm + ", threw: " + ex.Message);
                }

                TestUtilities.AssertFailIfErrors("AsymmetricSignatureProvider_SupportedAlgorithms", errors);
            }
        }

        [Fact(DisplayName = "SymmetricSignatureProvider: Publics")]
        public void SymmetricSignatureProvider_Publics()
        {
            SymmetricSignatureProvider provider = new SymmetricSignatureProvider(KeyingMaterial.DefaultSymmetricSecurityKey_256, KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2.Algorithm);

            ExpectedException expectedException = ExpectedException.ArgumentOutOfRangeException("IDX10628:");
            try
            {
                provider.MinimumSymmetricKeySizeInBits = SymmetricSignatureProvider.DefaultMinimumSymmetricKeySizeInBits - 10;
                expectedException.ProcessNoException();
            }
            catch (Exception ex)
            {
                expectedException.ProcessException(ex);
            }
        }

        [Fact(DisplayName = "SymmetricSignatureProvider: Symmetric Signature Provider Verify")]
        public void SymmetricSignatureProvider_Verify()
        {
            List<string> errors = new List<string>();
            byte[] rawBytes = new byte[8192];
            (new Random()).NextBytes(rawBytes);

            SymmetricSignatureProviders_Verify_Variation(KeyingMaterial.DefaultSymmetricSecurityKey_256, SecurityAlgorithms.HmacSha256Signature, null, null, ExpectedException.ArgumentNullException(), errors, false);
            SymmetricSignatureProviders_Verify_Variation(KeyingMaterial.DefaultSymmetricSecurityKey_256, SecurityAlgorithms.HmacSha256Signature, new byte[0], null, ExpectedException.ArgumentNullException(), errors, false);
            SymmetricSignatureProviders_Verify_Variation(KeyingMaterial.DefaultSymmetricSecurityKey_256, SecurityAlgorithms.HmacSha256Signature, new byte[0], new byte[0], ExpectedException.ArgumentException("IDX10625:"), errors, false);
            SymmetricSignatureProviders_Verify_Variation(KeyingMaterial.DefaultSymmetricSecurityKey_256, SecurityAlgorithms.HmacSha256Signature, new byte[1], new byte[0], ExpectedException.ArgumentException("IDX10626:"), errors, false);
            SymmetricSignatureProviders_Verify_Variation(KeyingMaterial.DefaultSymmetricSecurityKey_256, SecurityAlgorithms.HmacSha256Signature, new byte[1], new byte[1], ExpectedException.NoExceptionExpected, errors, false);

            var signature = GetSignature(KeyingMaterial.DefaultSymmetricSecurityKey_256, SecurityAlgorithms.HmacSha256Signature, rawBytes);
            SymmetricSignatureProviders_Verify_Variation(KeyingMaterial.DefaultSymmetricSecurityKey_256, SecurityAlgorithms.HmacSha256Signature, rawBytes, signature, ExpectedException.NoExceptionExpected, errors, true);
            // wrong algorithm
            SymmetricSignatureProviders_Verify_Variation(KeyingMaterial.DefaultSymmetricSecurityKey_256, SecurityAlgorithms.HmacSha384Signature, rawBytes, signature, ExpectedException.NoExceptionExpected, errors, false);
            // wrong key
            SymmetricSignatureProviders_Verify_Variation(KeyingMaterial.SymmetricSecurityKey2_256, SecurityAlgorithms.HmacSha256Signature, rawBytes, signature, ExpectedException.NoExceptionExpected, errors, false);

            signature = GetSignature(KeyingMaterial.DefaultSymmetricSecurityKey_256, SecurityAlgorithms.HmacSha512Signature, rawBytes);
            SymmetricSignatureProviders_Verify_Variation(KeyingMaterial.DefaultSymmetricSecurityKey_256, SecurityAlgorithms.HmacSha512Signature, rawBytes, signature, ExpectedException.NoExceptionExpected, errors, true);

            TestUtilities.AssertFailIfErrors("SymmetricSignatureProvider_Verify", errors);
        }
        private byte[] GetSignature(SymmetricSecurityKey key, string algorithm, byte[] rawBytes)
        {
            SymmetricSignatureProvider provider = new SymmetricSignatureProvider(key, algorithm);
            return provider.Sign(rawBytes);
        }

        private void SymmetricSignatureProviders_Verify_Variation(SymmetricSecurityKey key, string algorithm, byte[] rawBytes, byte[] signature, ExpectedException ee, List<string> errors, bool shouldSignatureSucceed)
        {
            try
            {
                SymmetricSignatureProvider provider = new SymmetricSignatureProvider(key, algorithm);
                if (provider.Verify(rawBytes, signature) != shouldSignatureSucceed)
                    errors.Add("SignatureProvider.Verify did not return expected: " + shouldSignatureSucceed + " , algorithm: " + algorithm);

                ee.ProcessNoException(errors);
            }
            catch (Exception ex)
            {
                ee.ProcessException(ex, errors);
            }
        }
#endregion
    }
}
