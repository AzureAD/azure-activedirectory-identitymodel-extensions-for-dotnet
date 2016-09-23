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
        [Fact]
        public void CryptoProviderFactory_Tests()
        {
            CryptoProviderFactory factory = new CryptoProviderFactory();

            // Asymmetric / Symmetric both need signature alg specified
            FactoryCreateFor("Signing: algorithm string.Empty", KeyingMaterial.X509SecurityKey_1024, string.Empty, factory, ExpectedException.ArgumentNullException());
            FactoryCreateFor("Verifying: algorithm string.Empty", KeyingMaterial.X509SecurityKey_1024, string.Empty, factory, ExpectedException.ArgumentNullException());

            // Json Web Keys
            FactoryCreateFor("Signing: No exception", KeyingMaterial.JsonWebKeyRsa256, SecurityAlgorithms.RsaSha256, factory, ExpectedException.NoExceptionExpected);
            FactoryCreateFor("Signing: security key without private key", KeyingMaterial.JsonWebKeyRsa256Public, SecurityAlgorithms.RsaSha256, factory, ExpectedException.InvalidOperationException("IDX10638:"));
            FactoryCreateFor("Verifying: No exception", KeyingMaterial.JsonWebKeyRsa256Public, SecurityAlgorithms.RsaSha256, factory, ExpectedException.NoExceptionExpected);
            FactoryCreateFor("Signing: No exception", KeyingMaterial.JsonWebKeySymmetric256, SecurityAlgorithms.HmacSha256, factory, ExpectedException.NoExceptionExpected);
            FactoryCreateFor("Verifying: No exception", KeyingMaterial.JsonWebKeySymmetric256, SecurityAlgorithms.HmacSha256, factory, ExpectedException.NoExceptionExpected);

            // Keytype not supported
            FactoryCreateFor("Signing: SecurityKey type not Asymmetric or Symmetric", NotAsymmetricOrSymmetricSecurityKey.New, SecurityAlgorithms.HmacSha256Signature, factory, ExpectedException.ArgumentException("IDX10634:"));
            FactoryCreateFor("Verifying: SecurityKey type not Asymmetric or Symmetric", NotAsymmetricOrSymmetricSecurityKey.New, SecurityAlgorithms.RsaSha256Signature, factory, ExpectedException.ArgumentException("IDX10634:"));

            // Private keys missing
            FactoryCreateFor("Signing RsaSecurityKey_2048_Public: SecurityKey without private key", KeyingMaterial.RsaSecurityKey_2048_Public, SecurityAlgorithms.RsaSha256Signature, factory, ExpectedException.InvalidOperationException(substringExpected: "IDX10638:"));
            FactoryCreateFor("Verifying RsaSecurityKey_2048_Public: SecurityKey without private key", KeyingMaterial.RsaSecurityKey_2048_Public, SecurityAlgorithms.RsaSha256Signature, factory, ExpectedException.NoExceptionExpected);
            FactoryCreateFor("Signing ECDsa256Key_Public: SecurityKey without private key", KeyingMaterial.ECDsa256Key_Public, SecurityAlgorithms.EcdsaSha256, factory, ExpectedException.InvalidOperationException(substringExpected: "IDX10638:"));

            // Key size checks
            FactoryCreateFor("Signing: AsymmetricKeySize Key to small", KeyingMaterial.X509SecurityKey_1024, SecurityAlgorithms.RsaSha256Signature, factory, ExpectedException.ArgumentOutOfRangeException("IDX10630:"));
            FactoryCreateFor("Signing: SymmetricKeySize Key to small", KeyingMaterial.SymmetricSecurityKey_56, SecurityAlgorithms.HmacSha256Signature, factory, ExpectedException.ArgumentOutOfRangeException("IDX10603:"));

            FactoryCreateFor("Signing: SymmetricKeySize Key", KeyingMaterial.DefaultSymmetricSecurityKey_256, SecurityAlgorithms.HmacSha256Signature, factory, ExpectedException.NoExceptionExpected);
            FactoryCreateFor("Verifying: SymmetricKeySize Key", KeyingMaterial.DefaultSymmetricSecurityKey_256, SecurityAlgorithms.HmacSha256Signature, factory, ExpectedException.NoExceptionExpected);

            // extensibility tests
            // smaller key sizes but no exceptions using custom crypto factory
            FactoryCreateFor("Signing: AsymmetricKeySize Key to small", KeyingMaterial.X509SecurityKey_1024, SecurityAlgorithms.RsaSha256Signature, new CustomCryptoProviderFactory(new string[] { SecurityAlgorithms.RsaSha256Signature }), ExpectedException.NoExceptionExpected);
            FactoryCreateFor("Signing: SymmetricKeySize Key to small", KeyingMaterial.SymmetricSecurityKey_56, SecurityAlgorithms.HmacSha256Signature, new CustomCryptoProviderFactory(new string[] { SecurityAlgorithms.HmacSha256Signature }), ExpectedException.NoExceptionExpected);
        }

        private void FactoryCreateFor(string testcase, SecurityKey key, string algorithm, CryptoProviderFactory factory, ExpectedException expectedException)
        {
            Console.WriteLine(testcase);
            try
            {
                if (testcase.StartsWith("Signing"))
                    factory.CreateForSigning(key, algorithm);
                else
                    factory.CreateForVerifying(key, algorithm);

                expectedException.ProcessNoException();
            }
            catch (Exception ex)
            {
                expectedException.ProcessException(ex);
            }
        }

        #region Common Signature Provider Tests
        [Fact]
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

        [Fact]
        public void SignatureProviders_Sign()
        {
            List<string> errors = new List<string>();
            byte[] rawBytes = new byte[8192];
            (new Random()).NextBytes(rawBytes);

            // Asymmetric
            AsymmetricSignatureProvidersSignVariation(KeyingMaterial.RsaSecurityKey_2048, SecurityAlgorithms.RsaSha256Signature, null, ExpectedException.ArgumentNullException(), errors);
            AsymmetricSignatureProvidersSignVariation(KeyingMaterial.RsaSecurityKey_2048, SecurityAlgorithms.RsaSha256Signature, new byte[0], ExpectedException.ArgumentException("IDX10624:"), errors);
            AsymmetricSignatureProvidersSignVariation(KeyingMaterial.RsaSecurityKey_1024, SecurityAlgorithms.RsaSha256Signature, rawBytes, ExpectedException.ArgumentOutOfRangeException("IDX10630:"), errors);
            AsymmetricSignatureProvidersSignVariation(KeyingMaterial.RsaSecurityKey_2048, SecurityAlgorithms.RsaSha256Signature, rawBytes, ExpectedException.NoExceptionExpected, errors);
            AsymmetricSignatureProvidersSignVariation(KeyingMaterial.RsaSecurityKeyWithCspProvider_2048, SecurityAlgorithms.RsaSha256Signature, rawBytes, ExpectedException.NoExceptionExpected, errors);
#if NETCOREAPP1_0
            AsymmetricSignatureProvidersSignVariation(KeyingMaterial.RsaSecurityKeyWithCngProvider_2048, SecurityAlgorithms.RsaSha256Signature, rawBytes, ExpectedException.NoExceptionExpected, errors);
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

            AsymmetricSignatureProvidersSignVariation(KeyingMaterial.RsaSecurityKey_2048_Public, SecurityAlgorithms.RsaSha256Signature, rawBytes, ExpectedException.InvalidOperationException("IDX10638:"), errors);
            AsymmetricSignatureProvidersSignVariation(KeyingMaterial.RsaSecurityKey_2048, "NOT_SUPPORTED", rawBytes, ExpectedException.ArgumentException("IDX10634:"), errors);
            AsymmetricSignatureProvidersSignVariation(KeyingMaterial.ECDsa256Key, SecurityAlgorithms.EcdsaSha256, rawBytes, ExpectedException.NoExceptionExpected, errors);
            AsymmetricSignatureProvidersSignVariation(KeyingMaterial.ECDsa256Key_Public, SecurityAlgorithms.EcdsaSha256, rawBytes, ExpectedException.InvalidOperationException("IDX10638:"), errors);

            AsymmetricSignatureProvidersSignVariation(KeyingMaterial.JsonWebKeyRsa256, SecurityAlgorithms.RsaSha256Signature, rawBytes, ExpectedException.NoExceptionExpected, errors);
            AsymmetricSignatureProvidersSignVariation(KeyingMaterial.JsonWebKeyRsa256Public, SecurityAlgorithms.RsaSha256Signature, rawBytes, ExpectedException.InvalidOperationException("IDX10638:"), errors);
            AsymmetricSignatureProvidersSignVariation(KeyingMaterial.JsonWebKeyEcdsa256, SecurityAlgorithms.EcdsaSha256, rawBytes, ExpectedException.NoExceptionExpected, errors);
            AsymmetricSignatureProvidersSignVariation(KeyingMaterial.JsonWebKeyEcdsa256Public, SecurityAlgorithms.EcdsaSha256, rawBytes, ExpectedException.InvalidOperationException("IDX10638:"), errors);

            // Symmetric
            SymmetricSignatureProvidersSignVariation(KeyingMaterial.DefaultSymmetricSecurityKey_256, SecurityAlgorithms.HmacSha256Signature, null, ExpectedException.ArgumentNullException(), errors);
            SymmetricSignatureProvidersSignVariation(KeyingMaterial.DefaultSymmetricSecurityKey_256, SecurityAlgorithms.HmacSha256Signature, new byte[0], ExpectedException.ArgumentException("IDX10624:"), errors);
            SymmetricSignatureProvidersSignVariation(KeyingMaterial.DefaultSymmetricSecurityKey_256, SecurityAlgorithms.HmacSha256Signature, rawBytes, ExpectedException.NoExceptionExpected, errors);
            SymmetricSignatureProvidersSignVariation(KeyingMaterial.SymmetricSecurityKey_56, SecurityAlgorithms.HmacSha256Signature, rawBytes, ExpectedException.ArgumentOutOfRangeException("IDX10603:"), errors);
            SymmetricSignatureProvidersSignVariation(KeyingMaterial.JsonWebKeySymmetric256, SecurityAlgorithms.HmacSha256Signature, rawBytes, ExpectedException.NoExceptionExpected, errors);
            TestUtilities.AssertFailIfErrors("SignatureProviders_Sign", errors);
        }

        private void AsymmetricSignatureProvidersSignVariation(SecurityKey key, string algorithm, byte[] input, ExpectedException ee, List<string> errors)
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

        private void SymmetricSignatureProvidersSignVariation(SecurityKey key, string algorithm, byte[] input, ExpectedException ee, List<string> errors)
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
        [Fact]
        public void AsymmetricSignatureProvider_Constructor()
        {
            AsymmetricSecurityKey privateKey = KeyingMaterial.DefaultX509SigningCreds_2048_RsaSha2_Sha2.Key as AsymmetricSecurityKey;
            AsymmetricSecurityKey publicKey = KeyingMaterial.DefaultX509SigningCreds_Public_2048_RsaSha2_Sha2.Key as AsymmetricSecurityKey;
            string sha2SignatureAlgorithm = KeyingMaterial.DefaultX509SigningCreds_2048_RsaSha2_Sha2.Algorithm;

            // no errors
            AsymmetricConstructorVariation("Signing:  - Creates with no errors", privateKey, sha2SignatureAlgorithm, ExpectedException.NoExceptionExpected);
            AsymmetricConstructorVariation("Verifying: - Creates with no errors (Private Key)", privateKey, sha2SignatureAlgorithm, ExpectedException.NoExceptionExpected);
            AsymmetricConstructorVariation("Verifying: - Creates with no errors (Public Key)", publicKey, sha2SignatureAlgorithm, ExpectedException.NoExceptionExpected);
            AsymmetricConstructorVariation("Signing:  - Creates with no errors", KeyingMaterial.ECDsa256Key, SecurityAlgorithms.EcdsaSha256, ExpectedException.NoExceptionExpected);
            AsymmetricConstructorVariation("Verifying: - Creates with no errors (Public Key)", KeyingMaterial.ECDsa256Key_Public, SecurityAlgorithms.EcdsaSha256, ExpectedException.NoExceptionExpected);
            AsymmetricConstructorVariation("Verifying: - Creates with no errors (Private Key)", KeyingMaterial.ECDsa256Key, SecurityAlgorithms.EcdsaSha256, ExpectedException.NoExceptionExpected);
            AsymmetricConstructorVariation("Verifying: - Creates with no errors (Public Key)", KeyingMaterial.ECDsa384Key_Public, SecurityAlgorithms.EcdsaSha384, ExpectedException.NoExceptionExpected);

            // null, empty algorithm digest
            AsymmetricConstructorVariation("Signing:   - NUll key", null, sha2SignatureAlgorithm, ExpectedException.ArgumentNullException());
            AsymmetricConstructorVariation("Signing:   - SignatureAlorithm == null", privateKey, null, ExpectedException.ArgumentException("IDX10634:"));
            AsymmetricConstructorVariation("Signing:   - SignatureAlorithm == whitespace", privateKey, "    ", ExpectedException.ArgumentException("IDX10634:"));

            // No Private keys
            AsymmetricConstructorVariation("Signing:   - SecurityKey without private key", publicKey, sha2SignatureAlgorithm, ExpectedException.InvalidOperationException("IDX10638:"));
            AsymmetricConstructorVariation("Verifying: - SecurityKey without private key", publicKey, sha2SignatureAlgorithm, ExpectedException.NoExceptionExpected);
            AsymmetricConstructorVariation("Signing: - no private key", KeyingMaterial.ECDsa521Key_Public, SecurityAlgorithms.EcdsaSha512, ExpectedException.InvalidOperationException("IDX10638:"));

            // Signature algorithm not supported
            AsymmetricConstructorVariation("Signing:   - SignatureAlgorithm not supported", KeyingMaterial.X509SecurityKey_1024, "SecurityAlgorithms.RsaSha256Signature", ExpectedException.ArgumentException(substringExpected: "IDX10634:"));
            AsymmetricConstructorVariation("Verifying: - SignatureAlgorithm not supported", KeyingMaterial.DefaultX509Key_Public_2048, "SecurityAlgorithms.RsaSha256Signature", ExpectedException.ArgumentException(substringExpected: "IDX10634:"));

            // constructing using jsonweb keys
            AsymmetricConstructorVariation("Signing:  - Creates with no errors", KeyingMaterial.JsonWebKeyRsa256, SecurityAlgorithms.RsaSha256, ExpectedException.NoExceptionExpected);
            AsymmetricConstructorVariation("Verifying:  - Creates with no errors", KeyingMaterial.JsonWebKeyRsa256Public, SecurityAlgorithms.RsaSha256, ExpectedException.NoExceptionExpected);
            AsymmetricConstructorVariation("Signing:  - Creates with no errors", KeyingMaterial.JsonWebKeyEcdsa256, SecurityAlgorithms.EcdsaSha256, ExpectedException.NoExceptionExpected);
            AsymmetricConstructorVariation("Verifying:  - Creates with no errors", KeyingMaterial.JsonWebKeyEcdsa256Public, SecurityAlgorithms.EcdsaSha256, ExpectedException.NoExceptionExpected);
        }

        private void AsymmetricConstructorVariation(string testcase, SecurityKey key, string algorithm, ExpectedException expectedException)
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

        [Fact]
        public void AsymmetricSignatureProvider_SupportedAlgorithms()
        {
            var errors = new List<string>();

            foreach (var algorithm in
                new string[] {
                    SecurityAlgorithms.RsaSha256,
                    SecurityAlgorithms.RsaSha384,
                    SecurityAlgorithms.RsaSha512,
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

            }

            foreach (var algorithm in
                new string[] {
                    SecurityAlgorithms.EcdsaSha256,
                    SecurityAlgorithms.EcdsaSha384,
                    SecurityAlgorithms.EcdsaSha512 })
            {
                try
                {
                    var provider = new AsymmetricSignatureProvider(KeyingMaterial.ECDsa256Key, algorithm);
                }
                catch (Exception ex)
                {
                    errors.Add("Creation of AsymmetricSignatureProvider with algorithm: " + algorithm + ", threw: " + ex.Message);
                }

            }
            TestUtilities.AssertFailIfErrors("AsymmetricSignatureProvider_SupportedAlgorithms", errors);

        }

        [Fact]
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
#if NETCOREAPP1_0
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
            signature = GetSignature(KeyingMaterial.ECDsa256Key, SecurityAlgorithms.EcdsaSha256, rawBytes);
            AsymmetricSignatureProviders_Verify_Variation(KeyingMaterial.ECDsa256Key, SecurityAlgorithms.EcdsaSha256, rawBytes, signature, ExpectedException.NoExceptionExpected, errors, true);
            AsymmetricSignatureProviders_Verify_Variation(KeyingMaterial.ECDsa256Key_Public, SecurityAlgorithms.EcdsaSha256, rawBytes, signature, ExpectedException.NoExceptionExpected, errors, true);

            // wrong key
            AsymmetricSignatureProviders_Verify_Variation(KeyingMaterial.ECDsa256Key, SecurityAlgorithms.EcdsaSha384, rawBytes, signature, ExpectedException.NoExceptionExpected, errors, false);
#if NETCOREAPP1_0
            AsymmetricSignatureProviders_Verify_Variation(KeyingMaterial.ECDsa384Key, SecurityAlgorithms.EcdsaSha384, rawBytes, signature, ExpectedException.NoExceptionExpected, errors, false);
#else
            //AsymmetricSignatureProviders_Verify_Variation(KeyingMaterial.ECDsa384Key, SecurityAlgorithms.EcdsaSha384, rawBytes, signature, new ExpectedException(typeof(CryptographicException)), errors, false);
#endif

            signature = GetSignature(KeyingMaterial.ECDsa384Key, SecurityAlgorithms.EcdsaSha384, rawBytes);
            AsymmetricSignatureProviders_Verify_Variation(KeyingMaterial.ECDsa384Key, SecurityAlgorithms.EcdsaSha384, rawBytes, signature, ExpectedException.NoExceptionExpected, errors, true);

            signature = GetSignature(KeyingMaterial.JsonWebKeyEcdsa256, SecurityAlgorithms.EcdsaSha256, rawBytes);
            AsymmetricSignatureProviders_Verify_Variation(KeyingMaterial.JsonWebKeyEcdsa256, SecurityAlgorithms.EcdsaSha256, rawBytes, signature, ExpectedException.NoExceptionExpected, errors, true);
            AsymmetricSignatureProviders_Verify_Variation(KeyingMaterial.JsonWebKeyEcdsa256Public, SecurityAlgorithms.EcdsaSha256, rawBytes, signature, ExpectedException.NoExceptionExpected, errors, true);

            signature = GetSignature(KeyingMaterial.JsonWebKeyRsa256, SecurityAlgorithms.RsaSha256, rawBytes);
            AsymmetricSignatureProviders_Verify_Variation(KeyingMaterial.JsonWebKeyRsa256, SecurityAlgorithms.RsaSha256, rawBytes, signature, ExpectedException.NoExceptionExpected, errors, true);
            AsymmetricSignatureProviders_Verify_Variation(KeyingMaterial.JsonWebKeyRsa256Public, SecurityAlgorithms.RsaSha256, rawBytes, signature, ExpectedException.NoExceptionExpected, errors, true);

            TestUtilities.AssertFailIfErrors("AsymmetricSignatureProviders_Verify", errors);
        }

        private byte[] GetSignature(SecurityKey key, string algorithm, byte[] rawBytes)
        {
            var provider = new AsymmetricSignatureProvider(key, algorithm, true);
            var bytes = provider.Sign(rawBytes);
            provider.Dispose();

            return bytes;
        }

        private void AsymmetricSignatureProviders_Verify_Variation(SecurityKey key, string algorithm, byte[] rawBytes, byte[] signature, ExpectedException ee, List<string> errors, bool shouldSignatureSucceed)
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
        [Fact]
        public void SymmetricSignatureProvider_ConstructorTests()
        {
            // no errors
            SymmetricSignatureProvider_ConstructorVariation(KeyingMaterial.DefaultSymmetricSecurityKey_256, SecurityAlgorithms.HmacSha256Signature, ExpectedException.NoExceptionExpected);
            SymmetricSignatureProvider_ConstructorVariation(KeyingMaterial.JsonWebKeySymmetric256, SecurityAlgorithms.HmacSha256, ExpectedException.NoExceptionExpected);
            // null key
            SymmetricSignatureProvider_ConstructorVariation(null, SecurityAlgorithms.HmacSha256Signature, ExpectedException.ArgumentNullException());
            // empty algorithm
            SymmetricSignatureProvider_ConstructorVariation(KeyingMaterial.DefaultSymmetricSecurityKey_256, string.Empty, ExpectedException.ArgumentException());
            // unsupported algorithm
            SymmetricSignatureProvider_ConstructorVariation(KeyingMaterial.DefaultSymmetricSecurityKey_256, "unknown algorithm", ExpectedException.ArgumentException("IDX10634:"));
            // smaller key < 256 bytes
            SymmetricSignatureProvider_ConstructorVariation(KeyingMaterial.SymmetricSecurityKey_56, SecurityAlgorithms.HmacSha256Signature, ExpectedException.ArgumentOutOfRangeException("IDX10603"));
            // GetKeyedHashAlgorithm throws
            SymmetricSecurityKey key = new FaultingSymmetricSecurityKey(KeyingMaterial.DefaultSymmetricSecurityKey_256, new CryptographicException("hi from inner"), null, null, KeyingMaterial.DefaultSymmetricKeyBytes_256);
            SymmetricSignatureProvider_ConstructorVariation(key, SecurityAlgorithms.HmacSha256Signature, ExpectedException.InvalidOperationException("IDX10634:", typeof(CryptographicException)));
        }

        private void SymmetricSignatureProvider_ConstructorVariation(SecurityKey key, string algorithm, ExpectedException expectedException)
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

        [Fact]
        public void SymmetricSignatureProvider_SupportedAlgorithms()
        {
            var errors = new List<string>();

            foreach (var algorithm in
                new string[] {
                    SecurityAlgorithms.HmacSha256Signature,
                    SecurityAlgorithms.HmacSha384Signature,
                    SecurityAlgorithms.HmacSha512Signature,
                    SecurityAlgorithms.HmacSha256,
                    SecurityAlgorithms.HmacSha384,
                    SecurityAlgorithms.HmacSha512 })
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

        [Fact]
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

        [Fact]
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

            var signature = GetSignatureFromSymmetricKey(KeyingMaterial.DefaultSymmetricSecurityKey_256, SecurityAlgorithms.HmacSha256Signature, rawBytes);
            SymmetricSignatureProviders_Verify_Variation(KeyingMaterial.DefaultSymmetricSecurityKey_256, SecurityAlgorithms.HmacSha256Signature, rawBytes, signature, ExpectedException.NoExceptionExpected, errors, true);
            // wrong algorithm
            SymmetricSignatureProviders_Verify_Variation(KeyingMaterial.DefaultSymmetricSecurityKey_256, SecurityAlgorithms.HmacSha384Signature, rawBytes, signature, ExpectedException.NoExceptionExpected, errors, false);
            // wrong key
            SymmetricSignatureProviders_Verify_Variation(KeyingMaterial.SymmetricSecurityKey2_256, SecurityAlgorithms.HmacSha256Signature, rawBytes, signature, ExpectedException.NoExceptionExpected, errors, false);

            signature = GetSignatureFromSymmetricKey(KeyingMaterial.DefaultSymmetricSecurityKey_256, SecurityAlgorithms.HmacSha512Signature, rawBytes);
            SymmetricSignatureProviders_Verify_Variation(KeyingMaterial.DefaultSymmetricSecurityKey_256, SecurityAlgorithms.HmacSha512Signature, rawBytes, signature, ExpectedException.NoExceptionExpected, errors, true);

            signature = GetSignatureFromSymmetricKey(KeyingMaterial.JsonWebKeySymmetric256, SecurityAlgorithms.HmacSha256Signature, rawBytes);
            SymmetricSignatureProviders_Verify_Variation(KeyingMaterial.JsonWebKeySymmetric256, SecurityAlgorithms.HmacSha256Signature, rawBytes, signature, ExpectedException.NoExceptionExpected, errors, true);
            SymmetricSignatureProviders_Verify_Variation(KeyingMaterial.DefaultSymmetricSecurityKey_256, SecurityAlgorithms.HmacSha256Signature, rawBytes, signature, ExpectedException.NoExceptionExpected, errors, true);

            TestUtilities.AssertFailIfErrors("SymmetricSignatureProvider_Verify", errors);
        }
        private byte[] GetSignatureFromSymmetricKey(SecurityKey key, string algorithm, byte[] rawBytes)
        {
            SymmetricSignatureProvider provider = new SymmetricSignatureProvider(key, algorithm);
            return provider.Sign(rawBytes);
        }

        private void SymmetricSignatureProviders_Verify_Variation(SecurityKey key, string algorithm, byte[] rawBytes, byte[] signature, ExpectedException ee, List<string> errors, bool shouldSignatureSucceed)
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

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData(nameof(KeyDisposeData))]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void SignatureProviderDispose_Test(string testId, SecurityKey securityKey, string algorithm, ExpectedException ee)
        {
            try
            {
                var jsonWebKey = securityKey as JsonWebKey;
                var symmetricSecurityKey = securityKey as SymmetricSecurityKey;

                if (symmetricSecurityKey != null || jsonWebKey?.Kty == JsonWebAlgorithmsKeyTypes.Octet)
                    SymmetricProviderDispose(testId, securityKey, algorithm, ee);
                else
                    AsymmetricProviderDispose(testId, securityKey, algorithm, ee);

                var bytes = new byte[1024];
                var provider = securityKey.CryptoProviderFactory.CreateForSigning(securityKey, algorithm);
                var signature = provider.Sign(bytes);
                securityKey.CryptoProviderFactory.ReleaseSignatureProvider(provider);

                provider = securityKey.CryptoProviderFactory.CreateForSigning(securityKey, algorithm);
                signature = provider.Sign(bytes);
                securityKey.CryptoProviderFactory.ReleaseSignatureProvider(provider);

                provider = securityKey.CryptoProviderFactory.CreateForVerifying(securityKey, algorithm);
                provider.Verify(bytes, signature);

                ee.ProcessNoException();
            }
            catch (Exception ex)
            {
                ee.ProcessException(ex);
            }
        }

        public void AsymmetricProviderDispose(string testId, SecurityKey securityKey, string algorithm, ExpectedException ee)
        {
            try
            {
                var bytes = new byte[256];
                var asymmetricProvider = new AsymmetricSignatureProvider(securityKey, algorithm, true);
                var signature = asymmetricProvider.Sign(bytes);
                asymmetricProvider.Dispose();

                asymmetricProvider = new AsymmetricSignatureProvider(securityKey, algorithm, true);
                signature = asymmetricProvider.Sign(bytes);
                asymmetricProvider.Dispose();

                asymmetricProvider = new AsymmetricSignatureProvider(securityKey, algorithm, false);
                asymmetricProvider.Verify(bytes, signature);

                ee.ProcessNoException();
            }
            catch(Exception ex)
            {
                ee.ProcessException(ex);
            }
        }

        public void SymmetricProviderDispose(string testId, SecurityKey securityKey, string algorithm, ExpectedException ee)
        {
            try
            {
                var bytes = new byte[256];
                var symmetricProvider = new SymmetricSignatureProvider(securityKey, algorithm);
                var signature = symmetricProvider.Sign(bytes);
                symmetricProvider.Dispose();

                symmetricProvider = new SymmetricSignatureProvider(securityKey, algorithm);
                signature = symmetricProvider.Sign(bytes);
                symmetricProvider.Dispose();

                symmetricProvider = new SymmetricSignatureProvider(securityKey, algorithm);
                symmetricProvider.Verify(bytes, signature);

                ee.ProcessNoException();
            }
            catch (Exception ex)
            {
                ee.ProcessException(ex);
            }
        }

        public static TheoryData<string, SecurityKey, string, ExpectedException> KeyDisposeData()
        {
            var dataSet = new TheoryData<string, SecurityKey, string, ExpectedException>();

            dataSet.Add(
                "Test1",
                new RsaSecurityKey(new RSACryptoServiceProvider(2048)),
                SecurityAlgorithms.RsaSha256,
                ExpectedException.NoExceptionExpected
            );

            dataSet.Add(
                "Test2",
                new RsaSecurityKey(KeyingMaterial.RsaParameters_2048),
                SecurityAlgorithms.RsaSha256,
                ExpectedException.NoExceptionExpected
            );

            dataSet.Add(
                "Test3",
                KeyingMaterial.JsonWebKeyRsa256,
                SecurityAlgorithms.RsaSha256,
                ExpectedException.NoExceptionExpected
            );

            dataSet.Add(
                "Test4",
                KeyingMaterial.JsonWebKeyEcdsa256,
                SecurityAlgorithms.EcdsaSha256,
                ExpectedException.NoExceptionExpected
            );

            dataSet.Add(
                "Test5",
                KeyingMaterial.ECDsa256Key,
                SecurityAlgorithms.EcdsaSha256,
                ExpectedException.NoExceptionExpected
            );

            dataSet.Add(
                "Test6",
                KeyingMaterial.SymmetricSecurityKey2_256,
                SecurityAlgorithms.HmacSha256,
                ExpectedException.NoExceptionExpected
            );

            return dataSet;
        }
    }
}
