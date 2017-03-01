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
using System.Reflection;
using System.Security.Cryptography;
using Xunit;

namespace Microsoft.IdentityModel.Tokens.Tests
{
    public class SignatureProviderTestParams
    {
        public string Algorithm { get; set; }
        public ExpectedException EE { get; set; }
        public SecurityKey Key { get; set; }
        public SignatureProvider ProviderForSigning { get; set; }
        public SignatureProvider ProviderForVerifying { get; set; }
        public byte[] RawBytes { get; set; }
        public bool ShouldVerify { get; set; }
        public byte[] Signature { get; set; }
        public string TestId { get; set; }
        public override string ToString()
        {
            return TestId + ", " + Algorithm + ", " + Key;
        }
    }

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
            FactoryCreateFor("Signing: AsymmetricKeySize Key too small", KeyingMaterial.X509SecurityKey_1024, SecurityAlgorithms.RsaSha256Signature, factory, ExpectedException.ArgumentOutOfRangeException("IDX10630:"));
            FactoryCreateFor("Signing: SymmetricKeySize Key too small", KeyingMaterial.DefaultSymmetricSecurityKey_56, SecurityAlgorithms.HmacSha256Signature, factory, ExpectedException.ArgumentOutOfRangeException("IDX10603:"));

            FactoryCreateFor("Signing: SymmetricKeySize Key", KeyingMaterial.DefaultSymmetricSecurityKey_256, SecurityAlgorithms.HmacSha256Signature, factory, ExpectedException.NoExceptionExpected);
            FactoryCreateFor("Verifying: SymmetricKeySize Key", KeyingMaterial.DefaultSymmetricSecurityKey_256, SecurityAlgorithms.HmacSha256Signature, factory, ExpectedException.NoExceptionExpected);

            // extensibility tests
            // smaller key sizes but no exceptions using custom crypto factory
            FactoryCreateFor("Signing: AsymmetricKeySize Key too small", KeyingMaterial.X509SecurityKey_1024, SecurityAlgorithms.RsaSha256Signature, new CustomCryptoProviderFactory(new string[] { SecurityAlgorithms.RsaSha256Signature }), ExpectedException.NoExceptionExpected);
            FactoryCreateFor("Signing: SymmetricKeySize Key too small", KeyingMaterial.DefaultSymmetricSecurityKey_56, SecurityAlgorithms.HmacSha256Signature, new CustomCryptoProviderFactory(new string[] { SecurityAlgorithms.HmacSha256Signature }), ExpectedException.NoExceptionExpected);
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
            AsymmetricSignatureProvidersSignVariation(KeyingMaterial.RsaSecurityKey_2048, SecurityAlgorithms.RsaSha256Signature, new byte[0], ExpectedException.ArgumentNullException(), errors);
            AsymmetricSignatureProvidersSignVariation(KeyingMaterial.RsaSecurityKey_1024, SecurityAlgorithms.RsaSha256Signature, rawBytes, ExpectedException.ArgumentOutOfRangeException("IDX10630:"), errors);
            AsymmetricSignatureProvidersSignVariation(KeyingMaterial.RsaSecurityKey_2048, SecurityAlgorithms.RsaSha256Signature, rawBytes, ExpectedException.NoExceptionExpected, errors);
#if NET451
            AsymmetricSignatureProvidersSignVariation(KeyingMaterial.RsaSecurityKeyWithCspProvider_2048, SecurityAlgorithms.RsaSha256Signature, rawBytes, ExpectedException.NoExceptionExpected, errors);
#endif

#if NETCOREAPP1_0
            AsymmetricSignatureProvidersSignVariation(KeyingMaterial.RsaSecurityKeyWithCngProvider_2048, SecurityAlgorithms.RsaSha256Signature, rawBytes, ExpectedException.NoExceptionExpected, errors);
            Assert.ThrowsAny<CryptographicException>(() =>
            {
                AsymmetricSignatureProvider provider = new AsymmetricSignatureProvider(KeyingMaterial.RsaSecurityKeyWithCngProvider_2048_Public, SecurityAlgorithms.RsaSha256Signature);
                provider.Sign(rawBytes);
            });
#endif

#if NET451
            // since the actual exception thrown is private - WindowsCryptographicException, using this pattern to match the derived exception
            Assert.ThrowsAny<CryptographicException>(() =>
            {
                AsymmetricSignatureProvider provider = new AsymmetricSignatureProvider(KeyingMaterial.RsaSecurityKeyWithCspProvider_2048_Public, SecurityAlgorithms.RsaSha256Signature);
                provider.Sign(rawBytes);
            });
#endif
            AsymmetricSignatureProvidersSignVariation(KeyingMaterial.RsaSecurityKey_2048_Public, SecurityAlgorithms.RsaSha256Signature, rawBytes, ExpectedException.InvalidOperationException("IDX10638:"), errors);
            AsymmetricSignatureProvidersSignVariation(KeyingMaterial.RsaSecurityKey_2048, "NOT_SUPPORTED", rawBytes, ExpectedException.ArgumentException("IDX10634:"), errors);
            AsymmetricSignatureProvidersSignVariation(KeyingMaterial.ECDsa256Key, SecurityAlgorithms.EcdsaSha256, rawBytes, ExpectedException.NoExceptionExpected, errors);
            AsymmetricSignatureProvidersSignVariation(KeyingMaterial.ECDsa256Key_Public, SecurityAlgorithms.EcdsaSha256, rawBytes, ExpectedException.InvalidOperationException("IDX10638:"), errors);

            AsymmetricSignatureProvidersSignVariation(KeyingMaterial.JsonWebKeyRsa256, SecurityAlgorithms.RsaSha256Signature, rawBytes, ExpectedException.NoExceptionExpected, errors);
            AsymmetricSignatureProvidersSignVariation(KeyingMaterial.JsonWebKeyRsa256Public, SecurityAlgorithms.RsaSha256Signature, rawBytes, ExpectedException.InvalidOperationException("IDX10638:"), errors);
            AsymmetricSignatureProvidersSignVariation(KeyingMaterial.JsonWebKeyEcdsa256, SecurityAlgorithms.EcdsaSha256, rawBytes, ExpectedException.NoExceptionExpected, errors);
            AsymmetricSignatureProvidersSignVariation(KeyingMaterial.JsonWebKeyEcdsa256Public, SecurityAlgorithms.EcdsaSha256, rawBytes, ExpectedException.InvalidOperationException("IDX10638:"), errors);

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

            // constructing using a key with wrong key size:
            AsymmetricConstructorVariation("Verifying:    - ECDSA with unmatched keysize", KeyingMaterial.ECDsa256Key, SecurityAlgorithms.EcdsaSha512, ExpectedException.ArgumentOutOfRangeException("IDX10641:"));
            AsymmetricConstructorVariation("Verifying:    - JsonWebKey for ECDSA with unmatched keysize", KeyingMaterial.JsonWebKeyEcdsa256, SecurityAlgorithms.EcdsaSha512, ExpectedException.ArgumentOutOfRangeException("IDX10671:"));
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
                    SecurityKey key = null;
                    if (algorithm.Equals(SecurityAlgorithms.EcdsaSha256, StringComparison.Ordinal))
                    {
                        key = KeyingMaterial.ECDsa256Key;
                    }
                    else if (algorithm.Equals(SecurityAlgorithms.EcdsaSha384, StringComparison.Ordinal))
                    {
                        key = KeyingMaterial.ECDsa384Key;
                    }
                    else
                    {
                        key = KeyingMaterial.ECDsa521Key;
                    }

                    var provider = new AsymmetricSignatureProvider(key, algorithm);
                }
                catch (Exception ex)
                {
                    errors.Add("Creation of AsymmetricSignatureProvider with algorithm: " + algorithm + ", threw: " + ex.Message);
                }

            }
            TestUtilities.AssertFailIfErrors("AsymmetricSignatureProvider_SupportedAlgorithms", errors);

        }

        private static bool IsRunningOn462OrGreaterOrCore()
        {
#if NETCOREAPP1_0
            // test for Core
            return true;
#else
            // test for >=4.6.2
            // AesCng was added to System.Core in 4.6.2. It doesn't exist in .NET Core.
            Module systemCoreModule = typeof(System.Security.Cryptography.AesCryptoServiceProvider).GetTypeInfo().Assembly.GetModules()[0];
            if (systemCoreModule != null && systemCoreModule.GetType("System.Security.Cryptography.AesCng") != null)
                return true;
            return false;
#endif
        }

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData(nameof(AsymmetricSignatureProviderVerifyTheoryData))]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void AsymmetricSignatureProvidersVerify(SignatureProviderTestParams testParams)
        {
            try
            {
                AsymmetricSignatureProvider provider = new AsymmetricSignatureProvider(testParams.Key, testParams.Algorithm);
                if (provider.Verify(testParams.RawBytes, testParams.Signature) != testParams.ShouldVerify)
                    Assert.True(false, testParams.TestId + " - SignatureProvider.Verify did not return expected: " + testParams.ShouldVerify + " , algorithm: " + testParams.Algorithm);

                testParams.EE.ProcessNoException();
            }
            catch (Exception ex)
            {
                testParams.EE.ProcessException(ex);
            }
        }

        public static TheoryData<SignatureProviderTestParams> AsymmetricSignatureProviderVerifyTheoryData()
        {
            var theoryData = new TheoryData<SignatureProviderTestParams>();

            byte[] rawBytes = new byte[8192];
            (new Random()).NextBytes(rawBytes);

            theoryData.Add(new SignatureProviderTestParams
            {
                Algorithm = SecurityAlgorithms.EcdsaSha256,
                EE = ExpectedException.NoExceptionExpected,
                RawBytes = rawBytes,
                Key = KeyingMaterial.ECDsa256Key,
                ShouldVerify = true,
                Signature = GetSignature(KeyingMaterial.ECDsa256Key, SecurityAlgorithms.EcdsaSha256, rawBytes),
                TestId = "Test1"
            });

            theoryData.Add(new SignatureProviderTestParams
            {
                Algorithm = SecurityAlgorithms.EcdsaSha256,
                EE = ExpectedException.NoExceptionExpected,
                RawBytes = rawBytes,
                Key = KeyingMaterial.ECDsa256Key_Public,
                ShouldVerify = true,
                Signature = GetSignature(KeyingMaterial.ECDsa256Key, SecurityAlgorithms.EcdsaSha256, rawBytes),
                TestId = "Test2"
            });

            theoryData.Add(new SignatureProviderTestParams
            {
                Algorithm = SecurityAlgorithms.EcdsaSha384,
                EE = ExpectedException.ArgumentOutOfRangeException("IDX10641:"),
                RawBytes = rawBytes,
                Key = KeyingMaterial.ECDsa256Key,
                ShouldVerify = false,
                Signature = GetSignature(KeyingMaterial.ECDsa256Key, SecurityAlgorithms.EcdsaSha256, rawBytes),
                TestId = "Test3"
            });

            if (IsRunningOn462OrGreaterOrCore())
            {
                theoryData.Add(new SignatureProviderTestParams
                {
                    Algorithm = SecurityAlgorithms.EcdsaSha384,
                    EE = ExpectedException.NoExceptionExpected,
                    RawBytes = rawBytes,
                    Key = KeyingMaterial.ECDsa384Key,
                    ShouldVerify = false,
                    Signature = GetSignature(KeyingMaterial.ECDsa256Key, SecurityAlgorithms.EcdsaSha256, rawBytes),
                    TestId = "Test4 (for >= 4.6.2 and Core)"
                });
            }
            else //running on 461 or below
             {
                theoryData.Add(new SignatureProviderTestParams
                {
                    Algorithm = SecurityAlgorithms.EcdsaSha384,
                    EE = new ExpectedException(typeof(System.Security.Cryptography.CryptographicException), "The parameter is incorrect."),
                    RawBytes = rawBytes,
                    Key = KeyingMaterial.ECDsa384Key,
                    ShouldVerify = false,
                    Signature = GetSignature(KeyingMaterial.ECDsa256Key, SecurityAlgorithms.EcdsaSha256, rawBytes),
                    TestId = "Test4 (for < 4.6.2)"
                });
            }

        //theoryData.Add(new SignatureProviderTestParams
        //    {
        //        Algorithm = SecurityAlgorithms.EcdsaSha384,
        //        EE = ExpectedException.NoExceptionExpected,
        //        RawBytes = rawBytes,
        //        Key = KeyingMaterial.ECDsa384Key,
        //        ShouldVerify = false,
        //        Signature = GetSignature(KeyingMaterial.ECDsa256Key, SecurityAlgorithms.EcdsaSha256, rawBytes),
        //        TestId = "Test4"
        //    });

            theoryData.Add(new SignatureProviderTestParams
            {
                Algorithm = SecurityAlgorithms.EcdsaSha384,
                EE = ExpectedException.NoExceptionExpected,
                RawBytes = rawBytes,
                Key = KeyingMaterial.ECDsa384Key,
                ShouldVerify = true,
                Signature = GetSignature(KeyingMaterial.ECDsa384Key, SecurityAlgorithms.EcdsaSha384, rawBytes),
                TestId = "Test5"
            });

            theoryData.Add(new SignatureProviderTestParams
            {
                Algorithm = SecurityAlgorithms.EcdsaSha256,
                EE = ExpectedException.NoExceptionExpected,
                RawBytes = rawBytes,
                Key = KeyingMaterial.JsonWebKeyEcdsa256,
                ShouldVerify = true,
                Signature = GetSignature(KeyingMaterial.JsonWebKeyEcdsa256, SecurityAlgorithms.EcdsaSha256, rawBytes),
                TestId = "Test6"
            });

            theoryData.Add(new SignatureProviderTestParams
            {
                Algorithm = SecurityAlgorithms.EcdsaSha256,
                EE = ExpectedException.NoExceptionExpected,
                RawBytes = rawBytes,
                Key = KeyingMaterial.JsonWebKeyEcdsa256Public,
                ShouldVerify = true,
                Signature = GetSignature(KeyingMaterial.JsonWebKeyEcdsa256, SecurityAlgorithms.EcdsaSha256, rawBytes),
                TestId = "Test7"
            });

            theoryData.Add(new SignatureProviderTestParams
            {
                Algorithm = SecurityAlgorithms.RsaSha256Signature,
                EE = ExpectedException.ArgumentNullException(),
                Key = KeyingMaterial.RsaSecurityKey_2048,
                RawBytes = null,
                Signature = null,
                ShouldVerify = false,
                TestId = "Test8"
            });

            theoryData.Add(new SignatureProviderTestParams
            {
                Algorithm = SecurityAlgorithms.RsaSha256Signature,
                EE = ExpectedException.ArgumentNullException(),
                Key = KeyingMaterial.RsaSecurityKey_2048,
                RawBytes = new byte[1],
                Signature = null,
                ShouldVerify = false,
                TestId = "Test9"
            });

            theoryData.Add(new SignatureProviderTestParams
            {
                Algorithm = SecurityAlgorithms.RsaSha256Signature,
                EE = ExpectedException.ArgumentNullException(),
                Key = KeyingMaterial.RsaSecurityKey_2048,
                RawBytes = new byte[0],
                Signature = new byte[1],
                ShouldVerify = false,
                TestId = "Test10"
            });

            theoryData.Add(new SignatureProviderTestParams
            {
                Algorithm = SecurityAlgorithms.RsaSha256Signature,
                EE = ExpectedException.ArgumentNullException(),
                Key = KeyingMaterial.RsaSecurityKey_2048,
                RawBytes = new byte[1],
                Signature = new byte[0],
                ShouldVerify = false,
                TestId = "Test11"
            });

            theoryData.Add(new SignatureProviderTestParams
            {
                Algorithm = SecurityAlgorithms.RsaSha256Signature,
                EE = ExpectedException.ArgumentNullException(),
                Key = KeyingMaterial.RsaSecurityKey_2048,
                RawBytes = new byte[0],
                Signature = new byte[1],
                ShouldVerify = false,
                TestId = "Test12"
            });

            var signature = GetSignature(KeyingMaterial.RsaSecurityKey_2048, SecurityAlgorithms.RsaSha256Signature, rawBytes);
            theoryData.Add(new SignatureProviderTestParams
            {
                Algorithm = SecurityAlgorithms.RsaSha256Signature,
                EE = ExpectedException.NoExceptionExpected,
                Key = KeyingMaterial.RsaSecurityKey_2048,
                RawBytes = rawBytes,
                Signature = signature,
                ShouldVerify = true,
                TestId = "Test13"
            });

#if NET451
            theoryData.Add(new SignatureProviderTestParams
            {
                Algorithm = SecurityAlgorithms.RsaSha256Signature,
                EE = ExpectedException.NoExceptionExpected,
                Key = KeyingMaterial.RsaSecurityKeyWithCspProvider_2048_Public,
                RawBytes = rawBytes,
                Signature = signature,
                ShouldVerify = true,
                TestId = "Test14"
            });
#endif
            // wrong hash
            theoryData.Add(new SignatureProviderTestParams
            {
                Algorithm = SecurityAlgorithms.RsaSha384Signature,
                EE = ExpectedException.NoExceptionExpected,
                Key = KeyingMaterial.RsaSecurityKey_2048_Public,
                RawBytes = rawBytes,
                Signature = signature,
                ShouldVerify = false,
                TestId = "Test15"
            });

            theoryData.Add(new SignatureProviderTestParams
            {
                Algorithm = SecurityAlgorithms.RsaSha512Signature,
                EE = ExpectedException.NoExceptionExpected,
                Key = KeyingMaterial.RsaSecurityKey_2048_Public,
                RawBytes = rawBytes,
                Signature = signature,
                ShouldVerify = false,
                TestId = "Test16"
            });

            // wrong key
            theoryData.Add(new SignatureProviderTestParams
            {
                Algorithm = SecurityAlgorithms.RsaSha256Signature,
                EE = ExpectedException.NoExceptionExpected,
                Key = KeyingMaterial.RsaSecurityKey_4096_Public,
                RawBytes = rawBytes,
                Signature = signature,
                ShouldVerify = false,
                TestId = "Test17"
            });

            signature = GetSignature(KeyingMaterial.RsaSecurityKey_4096, SecurityAlgorithms.RsaSha256Signature, rawBytes);
            theoryData.Add(new SignatureProviderTestParams
            {
                Algorithm = SecurityAlgorithms.RsaSha256Signature,
                EE = ExpectedException.NoExceptionExpected,
                Key = KeyingMaterial.RsaSecurityKey_4096,
                RawBytes = rawBytes,
                Signature = signature,
                ShouldVerify = true,
                TestId = "Test18"
            });

            theoryData.Add(new SignatureProviderTestParams
            {
                Algorithm = SecurityAlgorithms.RsaSha256Signature,
                EE = ExpectedException.NoExceptionExpected,
                Key = KeyingMaterial.RsaSecurityKey_4096_Public,
                RawBytes = rawBytes,
                Signature = signature,
                ShouldVerify = true,
                TestId = "Test19"
            });

            // wrong hash
            theoryData.Add(new SignatureProviderTestParams
            {
                Algorithm = SecurityAlgorithms.RsaSha384Signature,
                EE = ExpectedException.NoExceptionExpected,
                Key = KeyingMaterial.RsaSecurityKey_4096_Public,
                RawBytes = rawBytes,
                Signature = signature,
                ShouldVerify = false,
                TestId = "Test20"
            });

            theoryData.Add(new SignatureProviderTestParams
            {
                Algorithm = SecurityAlgorithms.RsaSha512Signature,
                EE = ExpectedException.NoExceptionExpected,
                Key = KeyingMaterial.RsaSecurityKey_4096_Public,
                RawBytes = rawBytes,
                Signature = signature,
                ShouldVerify = false,
                TestId = "Test21"
            });

            // wrong key
            theoryData.Add(new SignatureProviderTestParams
            {
                Algorithm = SecurityAlgorithms.RsaSha256Signature,
                EE = ExpectedException.NoExceptionExpected,
                Key = KeyingMaterial.RsaSecurityKey_2048_Public,
                RawBytes = rawBytes,
                Signature = signature,
                ShouldVerify = false,
                TestId = "Test22"
            });

#if NET451
            // sha384, 512
            signature = GetSignature(KeyingMaterial.RsaSecurityKeyWithCspProvider_2048, SecurityAlgorithms.RsaSha384Signature, rawBytes);
            theoryData.Add(new SignatureProviderTestParams
            {
                Algorithm = SecurityAlgorithms.RsaSha384Signature,
                EE = ExpectedException.NoExceptionExpected,
                Key = KeyingMaterial.RsaSecurityKey_2048_Public,
                RawBytes = rawBytes,
                Signature = signature,
                ShouldVerify = true,
                TestId = "Test23"
            });

#endif
            signature = GetSignature(KeyingMaterial.RsaSecurityKey_2048, SecurityAlgorithms.RsaSha512Signature, rawBytes);
            theoryData.Add(new SignatureProviderTestParams
            {
                Algorithm = SecurityAlgorithms.RsaSha512Signature,
                EE = ExpectedException.NoExceptionExpected,
                Key = KeyingMaterial.RsaSecurityKey_2048_Public,
                RawBytes = rawBytes,
                Signature = signature,
                ShouldVerify = true,
                TestId = "Test24"
            });

            signature = GetSignature(KeyingMaterial.JsonWebKeyRsa256, SecurityAlgorithms.RsaSha256, rawBytes);
            theoryData.Add(new SignatureProviderTestParams
            {
                Algorithm = SecurityAlgorithms.RsaSha256,
                EE = ExpectedException.NoExceptionExpected,
                Key = KeyingMaterial.JsonWebKeyRsa256,
                RawBytes = rawBytes,
                Signature = signature,
                ShouldVerify = true,
                TestId = "Test25"
            });

            theoryData.Add(new SignatureProviderTestParams
            {
                Algorithm = SecurityAlgorithms.RsaSha256,
                EE = ExpectedException.NoExceptionExpected,
                Key = KeyingMaterial.JsonWebKeyRsa256Public,
                RawBytes = rawBytes,
                Signature = signature,
                ShouldVerify = true,
                TestId = "Test26"
            });

            return theoryData;
        }

        private static byte[] GetSignature(SecurityKey key, string algorithm, byte[] rawBytes)
        {
            var provider = new AsymmetricSignatureProvider(key, algorithm, true);
            var bytes = provider.Sign(rawBytes);
            provider.Dispose();

            return bytes;
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
            SymmetricSignatureProvider_ConstructorVariation(Default.SymmetricSigningKey56, SecurityAlgorithms.HmacSha256Signature, ExpectedException.ArgumentOutOfRangeException("IDX10603"));
            SymmetricSignatureProvider_ConstructorVariation(Default.SymmetricSigningKey64, SecurityAlgorithms.HmacSha256Signature, ExpectedException.ArgumentOutOfRangeException("IDX10603"));

            // GetKeyedHashAlgorithm throws
            SymmetricSecurityKey key = new FaultingSymmetricSecurityKey(Default.SymmetricSigningKey256, new CryptographicException("Inner CryptographicException"), null, null, Default.SymmetricSigningKey256.Key);
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

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData(nameof(SymmetricSignatureProviderVerifyTheoryData))]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void SymmetricSignatureProvidersVerify(SignatureProviderTestParams testParams)
        {
            try
            {
                SymmetricSignatureProvider provider = new SymmetricSignatureProvider(testParams.Key, testParams.Algorithm);
                if (provider.Verify(testParams.RawBytes, testParams.Signature) != testParams.ShouldVerify)
                    Assert.True(false, testParams.TestId + " - SignatureProvider.Verify did not return expected: " + testParams.ShouldVerify + " , algorithm: " + testParams.Algorithm);

                testParams.EE.ProcessNoException();
            }
            catch (Exception ex)
            {
                testParams.EE.ProcessException(ex);
            }
        }
#endregion

        public static TheoryData <SignatureProviderTestParams> SymmetricSignatureProviderVerifyTheoryData()
        {
            var theoryData = new TheoryData<SignatureProviderTestParams>();

            byte[] rawBytes = new byte[8192];
            (new Random()).NextBytes(rawBytes);

#region Parameter Validation

            theoryData.Add(new SignatureProviderTestParams
            {
                Algorithm = SecurityAlgorithms.HmacSha256,
                EE = ExpectedException.ArgumentNullException(),
                Key = Default.SymmetricSigningKey256,
                RawBytes = null,
                ShouldVerify = false,
                Signature = new byte[1],
                TestId = "Test1"
            });

            theoryData.Add(new SignatureProviderTestParams
            {
                Algorithm = SecurityAlgorithms.HmacSha256,
                EE = ExpectedException.ArgumentNullException(),
                Key = Default.SymmetricSigningKey256,
                RawBytes = new byte[0],
                ShouldVerify = false,
                Signature = new byte[1],
                TestId = "Test2"
            });

            theoryData.Add(new SignatureProviderTestParams
            {
                Algorithm = SecurityAlgorithms.HmacSha256,
                EE = ExpectedException.ArgumentNullException(),
                Key = Default.SymmetricSigningKey256,
                RawBytes = new byte[1],
                ShouldVerify = false,
                Signature = null,
                TestId = "Test3"
            });

            theoryData.Add(new SignatureProviderTestParams
            {
                Algorithm = SecurityAlgorithms.HmacSha256,
                EE = ExpectedException.ArgumentNullException(),
                RawBytes = new byte[1],
                Key = Default.SymmetricSigningKey256,
                ShouldVerify = false,
                Signature = new byte[0],
                TestId = "Test4"
            });

            theoryData.Add(new SignatureProviderTestParams
            {
                Algorithm = SecurityAlgorithms.HmacSha256,
                EE = ExpectedException.NoExceptionExpected,
                Key = Default.SymmetricSigningKey256,
                RawBytes = new byte[1],
                ShouldVerify = false,
                Signature = new byte[1],
                TestId = "Test5"
            });

#endregion Parameter Validation

#region positive tests

            // HmacSha256 <-> HmacSha256Signature
            theoryData.Add(new SignatureProviderTestParams
            {
                Algorithm = SecurityAlgorithms.HmacSha256,
                EE = ExpectedException.NoExceptionExpected,
                RawBytes = rawBytes,
                Key = Default.SymmetricSigningKey256,
                ShouldVerify = true,
                Signature = GetSignatureFromSymmetricKey(Default.SymmetricSigningKey256, SecurityAlgorithms.HmacSha256Signature, rawBytes),
                TestId = "Test6"
            });

            theoryData.Add(new SignatureProviderTestParams
            {
                Algorithm = SecurityAlgorithms.HmacSha256Signature,
                EE = ExpectedException.NoExceptionExpected,
                Key = Default.SymmetricSigningKey256,
                RawBytes = rawBytes,
                ShouldVerify = true,
                Signature = GetSignatureFromSymmetricKey(Default.SymmetricSigningKey256, SecurityAlgorithms.HmacSha256, rawBytes),
                TestId = "Test7"
            });

            // HmacSha384 <-> HmacSha384Signature
            theoryData.Add(new SignatureProviderTestParams
            {
                Algorithm = SecurityAlgorithms.HmacSha384,
                EE = ExpectedException.NoExceptionExpected,
                Key = Default.SymmetricSigningKey256,
                RawBytes = rawBytes,
                ShouldVerify = true,
                Signature = GetSignatureFromSymmetricKey(Default.SymmetricSigningKey256, SecurityAlgorithms.HmacSha384Signature, rawBytes),
                TestId = "Test8"
            });

            theoryData.Add(new SignatureProviderTestParams
            {
                Algorithm = SecurityAlgorithms.HmacSha384Signature,
                EE = ExpectedException.NoExceptionExpected,
                Key = Default.SymmetricSigningKey256,
                RawBytes = rawBytes,
                ShouldVerify = true,
                Signature = GetSignatureFromSymmetricKey(Default.SymmetricSigningKey256, SecurityAlgorithms.HmacSha384, rawBytes),
                TestId = "Test9"
            });

            // HmacSha512 <-> HmacSha512Signature
            theoryData.Add(new SignatureProviderTestParams
            {
                Algorithm = SecurityAlgorithms.HmacSha512,
                EE = ExpectedException.NoExceptionExpected,
                Key = Default.SymmetricSigningKey256,
                RawBytes = rawBytes,
                ShouldVerify = true,
                Signature = GetSignatureFromSymmetricKey(Default.SymmetricSigningKey256, SecurityAlgorithms.HmacSha512Signature, rawBytes),
                TestId = "Test10"
            });

            theoryData.Add(new SignatureProviderTestParams
            {
                Algorithm = SecurityAlgorithms.HmacSha512Signature,
                EE = ExpectedException.NoExceptionExpected,
                Key = Default.SymmetricSigningKey256,
                RawBytes = rawBytes,
                ShouldVerify = true,
                Signature = GetSignatureFromSymmetricKey(Default.SymmetricSigningKey256, SecurityAlgorithms.HmacSha512, rawBytes),
                TestId = "Test11"
            });

            // JsonWebKey
            theoryData.Add(new SignatureProviderTestParams
            {
                Algorithm = SecurityAlgorithms.HmacSha256,
                EE = ExpectedException.NoExceptionExpected,
                Key = KeyingMaterial.JsonWebKeySymmetric256,
                RawBytes = rawBytes,
                ShouldVerify = true,
                Signature = GetSignatureFromSymmetricKey(KeyingMaterial.JsonWebKeySymmetric256, SecurityAlgorithms.HmacSha256Signature, rawBytes),
                TestId = "Test11",
            });

#endregion positive tests

#region negative tests

            // different algorithm
            // HmacSha256 -> HmacSha384
            theoryData.Add(new SignatureProviderTestParams
            {
                Algorithm = SecurityAlgorithms.HmacSha256,
                EE = ExpectedException.NoExceptionExpected,
                Key = Default.SymmetricSigningKey256,
                RawBytes = rawBytes,
                ShouldVerify = false,
                Signature = GetSignatureFromSymmetricKey(Default.SymmetricSigningKey256, SecurityAlgorithms.HmacSha384, rawBytes),
                TestId = "Test12",
            });

            // HmacSha256 -> HmacSha512
            theoryData.Add(new SignatureProviderTestParams
            {
                Algorithm = SecurityAlgorithms.HmacSha256,
                EE = ExpectedException.NoExceptionExpected,
                Key = Default.SymmetricSigningKey256,
                RawBytes = rawBytes,
                ShouldVerify = false,
                Signature = GetSignatureFromSymmetricKey(Default.SymmetricSigningKey256, SecurityAlgorithms.HmacSha512, rawBytes),
                TestId = "Test13",
            });

            // HmacSha384 -> HmacSha512
            theoryData.Add(new SignatureProviderTestParams
            {
                Algorithm = SecurityAlgorithms.HmacSha384,
                EE = ExpectedException.NoExceptionExpected,
                Key = Default.SymmetricSigningKey256,
                RawBytes = rawBytes,
                ShouldVerify = false,
                Signature = GetSignatureFromSymmetricKey(Default.SymmetricSigningKey256, SecurityAlgorithms.HmacSha512, rawBytes),
                TestId = "Test14",
            });

            // Default.SymmetricSigningKey256 -> NotDefault.SymmetricSigningKey256
            theoryData.Add(new SignatureProviderTestParams
            {
                Algorithm = SecurityAlgorithms.HmacSha256,
                EE = ExpectedException.NoExceptionExpected,
                Key = NotDefault.SymmetricSigningKey256,
                RawBytes = rawBytes,
                ShouldVerify = false,
                Signature = GetSignatureFromSymmetricKey(Default.SymmetricSigningKey256, SecurityAlgorithms.HmacSha256, rawBytes),
                TestId = "Test15"
            });

            // Default.SymmetricSigningKey256 -> Default.SymmetricSigningKey384
            theoryData.Add(new SignatureProviderTestParams
            {
                Algorithm = SecurityAlgorithms.HmacSha256,
                EE = ExpectedException.NoExceptionExpected,
                Key = Default.SymmetricSigningKey384,
                RawBytes = rawBytes,
                ShouldVerify = false,
                Signature = GetSignatureFromSymmetricKey(Default.SymmetricSigningKey256, SecurityAlgorithms.HmacSha384, rawBytes),
                TestId = "Test16",
            });

            // Default.SymmetricSigningKey384 -> NotDefault.SymmetricSigningKey384
            theoryData.Add(new SignatureProviderTestParams
            {
                Algorithm = SecurityAlgorithms.HmacSha384,
                EE = ExpectedException.NoExceptionExpected,
                Key = NotDefault.SymmetricSigningKey384,
                RawBytes = rawBytes,
                ShouldVerify = false,
                Signature = GetSignatureFromSymmetricKey(Default.SymmetricSigningKey384, SecurityAlgorithms.HmacSha384, rawBytes),
                TestId = "Test17"
            });

            // Default.SymmetricSigningKey384 -> Default.SymmetricSigningKey512
            theoryData.Add(new SignatureProviderTestParams
            {
                Algorithm = SecurityAlgorithms.HmacSha384,
                EE = ExpectedException.NoExceptionExpected,
                Key = NotDefault.SymmetricSigningKey384,
                RawBytes = rawBytes,
                ShouldVerify = false,
                Signature = GetSignatureFromSymmetricKey(Default.SymmetricSigningKey384, SecurityAlgorithms.HmacSha384, rawBytes),
                TestId = "Test18"
            });

            // Default.SymmetricSigningKey512 -> NoDefault.SymmetricSigningKey512
            theoryData.Add(new SignatureProviderTestParams
            {
                Algorithm = SecurityAlgorithms.HmacSha512,
                EE = ExpectedException.NoExceptionExpected,
                Key = NotDefault.SymmetricSigningKey512,
                RawBytes = rawBytes,
                ShouldVerify = false,
                Signature = GetSignatureFromSymmetricKey(Default.SymmetricSigningKey512, SecurityAlgorithms.HmacSha512, rawBytes),
                TestId = "Test19"
            });

            // Default.SymmetricSigningKey512 -> Default.SymmetricSigningKey1024
            theoryData.Add(new SignatureProviderTestParams
            {
                Algorithm = SecurityAlgorithms.HmacSha512,
                EE = ExpectedException.NoExceptionExpected,
                Key = NotDefault.SymmetricSigningKey1024,
                RawBytes = rawBytes,
                ShouldVerify = false,
                Signature = GetSignatureFromSymmetricKey(Default.SymmetricSigningKey1024, SecurityAlgorithms.HmacSha512, rawBytes),
                TestId = "Test20"
            });

            theoryData.Add(new SignatureProviderTestParams
            {
                Algorithm = SecurityAlgorithms.HmacSha256,
                EE = ExpectedException.NoExceptionExpected,
                Key = KeyingMaterial.JsonWebKeySymmetric256,
                RawBytes = rawBytes,
                ShouldVerify = false,
                Signature = GetSignatureFromSymmetricKey(KeyingMaterial.JsonWebKeySymmetric256_2, SecurityAlgorithms.HmacSha256, rawBytes),
                TestId = "Test21",
            });

#endregion  negative tests

            return theoryData;
        }

        private static byte[] GetSignatureFromSymmetricKey(SecurityKey key, string algorithm, byte[] rawBytes)
        {
            SymmetricSignatureProvider provider = new SymmetricSignatureProvider(key, algorithm);
            return provider.Sign(rawBytes);
        }

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

#if NET451
            dataSet.Add(
                "Test1",
                new RsaSecurityKey(new RSACryptoServiceProvider(2048)),
                SecurityAlgorithms.RsaSha256,
                ExpectedException.NoExceptionExpected
            );
#endif
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

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData(nameof(SignatureTheoryData))]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void SignatureTampering(SignatureProviderTestParams testParams)
        {
            Console.WriteLine($"SignatureTampering : {testParams} : {testParams.Signature.Length}");

            //var copiedSignature = testParams.Signature.CloneByteArray();
            //for (int i = 0; i<testParams.Signature.Length; i++)
            //{
            //    var originalB = testParams.Signature[i];
            //    for (byte b = 0; b<byte.MaxValue; b++)
            //    {
            //        // skip here as this will succeed
            //        if (b == testParams.Signature[i])
            //            continue;

            //        copiedSignature[i] = b;
            //        Assert.False(testParams.ProviderForVerifying.Verify(testParams.RawBytes, copiedSignature), $"signature should not have verified: {testParams.TestId} : {i} : {b} : {copiedSignature[i]}");

            //        // reset so we move to next byte
            //        copiedSignature[i] = originalB;
            //    }
            //}

            //Assert.True(testParams.ProviderForVerifying.Verify(testParams.RawBytes, copiedSignature), "Final check should have verified");
        }

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData(nameof(SignatureTheoryData))]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void SignatureTruncation(SignatureProviderTestParams testParams)
        {
            Console.WriteLine($"SignatureTruncation : {testParams} : {testParams.Signature.Length}");
            
            //for (int i = 0; i<testParams.Signature.Length-1; i++)
            //{
            //    var truncatedSignature = new byte[i + 1];
            //    Array.Copy(testParams.Signature, truncatedSignature, i+1);
            //    Assert.False(testParams.ProviderForVerifying.Verify(testParams.RawBytes, truncatedSignature), $"signature should not have verified: {testParams.TestId} : {i}");
            //}

            //Assert.True(testParams.ProviderForVerifying.Verify(testParams.RawBytes, testParams.Signature), "Final check should have verified");
        }

        public static TheoryData<SignatureProviderTestParams> SignatureTheoryData()
        {
            var theoryData = new TheoryData<SignatureProviderTestParams>();

            var rawBytes = Guid.NewGuid().ToByteArray();
            var asymmetricProvider = new AsymmetricSignatureProvider(KeyingMaterial.DefaultX509Key_2048, SecurityAlgorithms.RsaSha256, true);
            theoryData.Add(
                new SignatureProviderTestParams
                {
                    Algorithm = SecurityAlgorithms.RsaSha256,
                    Key = KeyingMaterial.DefaultX509Key_2048,
                    ProviderForVerifying = asymmetricProvider,
                    RawBytes = rawBytes,
                    Signature = asymmetricProvider.Sign(rawBytes),
                    TestId = "RS256"
                }
            );

            var asymmetricProvider2 = new AsymmetricSignatureProvider(KeyingMaterial.ECDsa256Key, SecurityAlgorithms.EcdsaSha256, true);
            theoryData.Add(
                new SignatureProviderTestParams
                {
                    Algorithm = SecurityAlgorithms.EcdsaSha256,
                    Key = KeyingMaterial.ECDsa256Key,
                    ProviderForVerifying = asymmetricProvider,
                    RawBytes = rawBytes,
                    Signature = asymmetricProvider.Sign(rawBytes),
                    TestId = "ES256"
                }
            );

            var symmetricProvider = new SymmetricSignatureProvider(KeyingMaterial.SymmetricSecurityKey2_256, SecurityAlgorithms.HmacSha256);
            theoryData.Add(
                new SignatureProviderTestParams
                {
                    Algorithm = SecurityAlgorithms.HmacSha256,
                    Key = KeyingMaterial.SymmetricSecurityKey2_256,
                    ProviderForVerifying = symmetricProvider,
                    RawBytes = rawBytes,
                    Signature = symmetricProvider.Sign(rawBytes),
                    TestId = "HS256"
                }
            );

            var symmetricProvider2 = new SymmetricSignatureProvider(KeyingMaterial.SymmetricSecurityKey2_512, SecurityAlgorithms.HmacSha512);
            theoryData.Add(
                new SignatureProviderTestParams
                {
                    Algorithm = SecurityAlgorithms.HmacSha512,
                    Key = KeyingMaterial.SymmetricSecurityKey2_512,
                    ProviderForVerifying = symmetricProvider2,
                    RawBytes = rawBytes,
                    Signature = symmetricProvider2.Sign(rawBytes),
                    TestId = "HS512"
                }
            );

            return theoryData;
        }
    }
}
