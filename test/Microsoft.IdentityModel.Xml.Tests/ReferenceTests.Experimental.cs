// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Text;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Experimental;
using Xunit;

namespace Microsoft.IdentityModel.Xml.Tests;

public class ReferenceExperimentalTests
{
    [Theory, MemberData(nameof(VerifyTheoryData), DisableDiscoveryEnumeration = true)]
    public void VerifyTest(ReferenceExperimentalTheoryData theoryData)
    {
        CompareContext context = TestUtilities.WriteHeader($"{this}.Verify", theoryData);

        ValidationResult<SecurityKey, ValidationError> validationResult =
            theoryData.Reference.Verify(theoryData.SecurityKey, theoryData.CryptoProviderFactory, theoryData.CallContext);

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

    public static TheoryData<ReferenceExperimentalTheoryData> VerifyTheoryData
    {
        get
        {
            var referenceWithTamperedDigest = Default.Reference;
            referenceWithTamperedDigest.DigestValue = Convert.ToBase64String(Encoding.UTF8.GetBytes("tampered-digest-value"));

            return new TheoryData<ReferenceExperimentalTheoryData>
            {
                new ReferenceExperimentalTheoryData()
                {
                    TestId = "ValidDigest",
                    ExpectedResult = true,
                    CryptoProviderFactory = CryptoProviderFactory.Default,
                    Reference = Default.Reference,
                    SecurityKey = Default.AsymmetricSigningKey,
                },
                new ReferenceExperimentalTheoryData()
                {
                    TestId = "ValidDigestOnlyCanonicalizingTransform",
                    ExpectedResult = true,
                    CryptoProviderFactory = CryptoProviderFactory.Default,
                    Reference = Default.ReferenceWithOnlyCanonicalizingTransform,
                    SecurityKey = Default.AsymmetricSigningKey,
                },
                new ReferenceExperimentalTheoryData()
                {
                    TestId = "ValidDigestWithoutTransform",
                    ExpectedResult = true,
                    CryptoProviderFactory = CryptoProviderFactory.Default,
                    Reference = Default.ReferenceWithoutTransform,
                    SecurityKey = Default.AsymmetricSigningKey,
                },
                new ReferenceExperimentalTheoryData()
                {
                    TestId = "NullSecurityKey",
                    ExpectedException = ExpectedException.ArgumentNullException("key"),
                    ExpectedFailureType = ValidationFailureType.NullArgument,
                    CryptoProviderFactory = CryptoProviderFactory.Default,
                    Reference = Default.Reference,
                    SecurityKey = null,
                },
                new ReferenceExperimentalTheoryData()
                {
                    TestId = "NullCryptoProviderFactory",
                    ExpectedException = ExpectedException.ArgumentNullException("cryptoProviderFactory"),
                    ExpectedFailureType = ValidationFailureType.NullArgument,
                    CryptoProviderFactory = null,
                    Reference = Default.Reference,
                    SecurityKey = Default.AsymmetricSigningKey,
                },
                new ReferenceExperimentalTheoryData()
                {
                    TestId = "DigestMismatch",
                    ExpectedException = new ExpectedException(typeof(SecurityTokenInvalidSignatureException), "IDX30201:"),
                    ExpectedFailureType = SignatureValidationFailure.ReferenceDigestValidationFailed,
                    CryptoProviderFactory = CryptoProviderFactory.Default,
                    Reference = referenceWithTamperedDigest,
                    SecurityKey = Default.AsymmetricSigningKey,
                },
                new ReferenceExperimentalTheoryData()
                {
                    TestId = "NullTokenStream",
                    ExpectedResult = false,
                    ExpectedException = new ExpectedException(typeof(SecurityTokenInvalidSignatureException), "IDX30201:", typeof(XmlValidationException)),
                    ExpectedFailureType = SignatureValidationFailure.ReferenceDigestValidationFailed,
                    CryptoProviderFactory = CryptoProviderFactory.Default,
                    Reference = Default.ReferenceWithNullTokenStreamNS,
                    SecurityKey = Default.AsymmetricSigningKey,
                },
                new ReferenceExperimentalTheoryData()
                {
                    TestId = "DigestMethodNotSupported",
                    ExpectedResult = false,
                    ExpectedException = new ExpectedException(typeof(SecurityTokenInvalidSignatureException), "IDX30201:", typeof(XmlValidationException)),
                    ExpectedFailureType = SignatureValidationFailure.ReferenceDigestValidationFailed,
                    CryptoProviderFactory = new CustomCryptoProviderFactory(),
                    Reference = Default.ReferenceNS,
                    SecurityKey = Default.AsymmetricSigningKey,
                },
            };
        }
    }
}

public class ReferenceExperimentalTheoryData : TheoryDataBase
{
    public CryptoProviderFactory CryptoProviderFactory { get; set; }
    public bool ExpectedResult { get; set; }
    public ValidationFailureType ExpectedFailureType { get; set; }
    public Reference Reference { get; set; } = new Reference();
    public SecurityKey SecurityKey { get; set; }
}
