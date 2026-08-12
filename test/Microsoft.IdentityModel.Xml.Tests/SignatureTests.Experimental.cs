// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Security.Cryptography;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Experimental;
using Xunit;

namespace Microsoft.IdentityModel.Xml.Tests;

public class SignatureExperimentalTests
{
    [Theory, MemberData(nameof(VerifyTheoryData), DisableDiscoveryEnumeration = true)]
    public void VerifyTest(SignatureExperimentalTheoryData theoryData)
    {
        CompareContext context = TestUtilities.WriteHeader($"{this}.Verify", theoryData);

        ValidationResult<SecurityKey, ValidationError> validationResult =
            theoryData.Signature.Verify(theoryData.SecurityKey, theoryData.CryptoProviderFactory, theoryData.CallContext);

        if (validationResult.Succeeded)
        {
            if (!theoryData.ExpectedResult)
            {
                context.AddDiff($"Expected validation to fail for '{theoryData.TestId}', but it succeeded.");
            }
            else
            {
                Assert.Same(theoryData.SecurityKey, validationResult.Result);
            }
        }
        else
        {
            if (theoryData.ExpectedResult)
            {
                context.AddDiff($"Expected validation to succeed for '{theoryData.TestId}', but it failed with error: {validationResult.Error.Message}.");
            }
            else
            {
                IdentityComparer.AreStringsEqual(validationResult.Error.FailureType.Name, theoryData.ExpectedFailureType.Name, context);

                theoryData.ExpectedException.ProcessException(validationResult.Error.GetException(), context);
            }
        }

        TestUtilities.AssertFailIfErrors(context);
    }

    public static TheoryData<SignatureExperimentalTheoryData> VerifyTheoryData
    {
        get
        {
            var signatureUnknownReferenceDigestAlg = Default.Signature;
            signatureUnknownReferenceDigestAlg.SignedInfo.References[0].DigestMethod = $"_{SecurityAlgorithms.Sha256Digest}";

            return new TheoryData<SignatureExperimentalTheoryData>
            {
                new SignatureExperimentalTheoryData()
                {
                    TestId = "NullSignedInfo",
                    ExpectedException = new ExpectedException(typeof(SecurityTokenValidationException), "IDX30212:"),
                    ExpectedFailureType = ValidationFailureType.SignedInfoNull,
                    CryptoProviderFactory = CryptoProviderFactory.Default,
                    Signature = new Signature(),
                    SecurityKey = Default.AsymmetricSigningKey,
                },
                new SignatureExperimentalTheoryData()
                {
                    TestId = "NullSecurityKey",
                    ExpectedException = ExpectedException.ArgumentNullException("key"),
                    ExpectedFailureType = ValidationFailureType.NullArgument,
                    CryptoProviderFactory = CryptoProviderFactory.Default,
                    Signature = new Signature(),
                    SecurityKey = null,
                },
                new SignatureExperimentalTheoryData()
                {
                    TestId = "NullCryptoProviderFactory",
                    ExpectedException = ExpectedException.ArgumentNullException("cryptoProviderFactory"),
                    ExpectedFailureType = ValidationFailureType.NullArgument,
                    CryptoProviderFactory = null,
                    Signature = new Signature(),
                    SecurityKey = Default.AsymmetricSigningKey,
                },
                new SignatureExperimentalTheoryData()
                {
                    TestId = "SignatureMethodNotSupported",
                    ExpectedException = new ExpectedException(typeof(SecurityTokenValidationException), "IDX30207:"),
                    ExpectedFailureType = ValidationFailureType.CryptoProviderAlgorithmNotSupported,
                    CryptoProviderFactory = CryptoProviderFactory.Default,
                    Signature = new Signature(new SignedInfo { SignatureMethod = SecurityAlgorithms.Aes128CbcHmacSha256 }),
                    SecurityKey = Default.AsymmetricSigningKey,
                },
                new SignatureExperimentalTheoryData()
                {
                    TestId = "SignatureProvider.CreateForVerifying-ReturnsNull",
                    ExpectedException = new ExpectedException(typeof(SecurityTokenValidationException), "IDX30203:"),
                    ExpectedFailureType = ValidationFailureType.CryptoProviderReturnedNull,
                    CryptoProviderFactory = new CustomCryptoProviderFactory([ SecurityAlgorithms.RsaSha256Signature ]),
                    Signature = new Signature(new SignedInfo { SignatureMethod = SecurityAlgorithms.RsaSha256Signature }),
                    SecurityKey = Default.AsymmetricSigningKey,
                },
                new SignatureExperimentalTheoryData()
                {
                    TestId = "ReferenceUnknownDigestAlg",
                    ExpectedException = new ExpectedException(typeof(SecurityTokenInvalidSignatureException), "IDX30201:", typeof(XmlValidationException)),
                    ExpectedFailureType = SignatureValidationFailure.ReferenceDigestValidationFailed,
                    CryptoProviderFactory = new CustomCryptoProviderFactory([ SecurityAlgorithms.RsaSha256Signature ])
                    {
                        SigningSignatureProvider = new CustomSignatureProvider(Default.AsymmetricSigningKey, SecurityAlgorithms.RsaSha256Signature),
                        VerifyingSignatureProvider = new CustomSignatureProvider(Default.AsymmetricSigningKey, SecurityAlgorithms.RsaSha256Signature)
                    },
                    Signature = signatureUnknownReferenceDigestAlg,
                    SecurityKey = Default.AsymmetricSigningKey,
                },
                new SignatureExperimentalTheoryData()
                {
                    TestId = "SignatureValidationFailed",
                    ExpectedException = new ExpectedException(typeof(SecurityTokenInvalidSignatureException), "IDX10511:"),
                    ExpectedFailureType = SignatureValidationFailure.ValidationFailed,
                    CryptoProviderFactory = new CustomCryptoProviderFactory([ SecurityAlgorithms.RsaSha256Signature ])
                    {
                        VerifyingSignatureProvider = new CustomSignatureProvider(Default.AsymmetricSigningKey, SecurityAlgorithms.RsaSha256Signature) { VerifyResult = false }
                    },
                    Signature = Default.Signature,
                    SecurityKey = Default.AsymmetricSigningKey,
                },
                new SignatureExperimentalTheoryData()
                {
                    // Success: signature verification and every reference digest verification succeed.
                    TestId = "Valid",
                    ExpectedResult = true,
                    CryptoProviderFactory = new CustomCryptoProviderFactory([ SecurityAlgorithms.RsaSha256Signature, SecurityAlgorithms.Sha256Digest ])
                    {
                        VerifyingSignatureProvider = new CustomSignatureProvider(Default.AsymmetricSigningKey, SecurityAlgorithms.RsaSha256Signature) { VerifyResult = true },
                        HashAlgorithm = SHA256.Create()
                    },
                    Signature = Default.Signature,
                    SecurityKey = Default.AsymmetricSigningKey,
                },
            };
        }
    }
}

public class SignatureExperimentalTheoryData : TheoryDataBase
{
    public CryptoProviderFactory CryptoProviderFactory { get; set; }
    public bool ExpectedResult { get; set; }
    public ValidationFailureType ExpectedFailureType { get; set; }
    public Signature Signature { get; set; } = new Signature();
    public SecurityKey SecurityKey { get; set; }
}
