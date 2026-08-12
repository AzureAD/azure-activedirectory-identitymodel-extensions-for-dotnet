// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Experimental;
using Xunit;

namespace Microsoft.IdentityModel.Xml.Tests;

public class SignedInfoExperimentalTests
{
    [Theory, MemberData(nameof(VerifyTheoryData), DisableDiscoveryEnumeration = true)]
    public void VerifyTest(SignedInfoExperimentalTheoryData theoryData)
    {
        CompareContext context = TestUtilities.WriteHeader($"{this}.Verify", theoryData);

        ValidationResult<SecurityKey, ValidationError> validationResult =
            theoryData.SignedInfo.Verify(theoryData.SecurityKey, theoryData.CryptoProviderFactory, theoryData.CallContext);

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

    public static TheoryData<SignedInfoExperimentalTheoryData> VerifyTheoryData
    {
        get
        {
            var signedInfoFirstReferenceFails = new SignedInfo(Default.ReferenceWithoutTransform)
            {
                CanonicalizationMethod = SecurityAlgorithms.ExclusiveC14n,
                SignatureMethod = SecurityAlgorithms.RsaSha256Signature,
            };
            signedInfoFirstReferenceFails.References[0].DigestValue = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("tampered-digest-value"));

            return new TheoryData<SignedInfoExperimentalTheoryData>
            {
                new SignedInfoExperimentalTheoryData()
                {
                    TestId = "NoReferences",
                    ExpectedResult = true,
                    CryptoProviderFactory = CryptoProviderFactory.Default,
                    SignedInfo = new SignedInfo(),
                    SecurityKey = Default.AsymmetricSigningKey,
                },
                new SignedInfoExperimentalTheoryData()
                {
                    TestId = "SingleReference:Valid",
                    ExpectedResult = true,
                    CryptoProviderFactory = CryptoProviderFactory.Default,
                    SignedInfo = Default.SignedInfo,
                    SecurityKey = Default.AsymmetricSigningKey,
                },
                new SignedInfoExperimentalTheoryData()
                {
                    TestId = "SecurityKey:Null",
                    ExpectedException = ExpectedException.ArgumentNullException("key"),
                    ExpectedFailureType = ValidationFailureType.NullArgument,
                    CryptoProviderFactory = CryptoProviderFactory.Default,
                    SignedInfo = Default.SignedInfo,
                    SecurityKey = null,
                },
                new SignedInfoExperimentalTheoryData()
                {
                    TestId = "CryptoProviderFactory:Null",
                    ExpectedException = ExpectedException.ArgumentNullException("cryptoProviderFactory"),
                    ExpectedFailureType = ValidationFailureType.NullArgument,
                    CryptoProviderFactory = null,
                    SignedInfo = Default.SignedInfo,
                    SecurityKey = Default.AsymmetricSigningKey,
                },
                new SignedInfoExperimentalTheoryData()
                {
                    TestId = "FirstReference:DigestMismatch",
                    ExpectedException = new ExpectedException(typeof(SecurityTokenInvalidSignatureException), "IDX30201:"),
                    ExpectedFailureType = SignatureValidationFailure.ReferenceDigestValidationFailed,
                    CryptoProviderFactory = CryptoProviderFactory.Default,
                    SignedInfo = signedInfoFirstReferenceFails,
                    SecurityKey = Default.AsymmetricSigningKey,
                },
            };
        }
    }
}

public class SignedInfoExperimentalTheoryData : TheoryDataBase
{
    public CryptoProviderFactory CryptoProviderFactory { get; set; }
    public bool ExpectedResult { get; set; }
    public ValidationFailureType ExpectedFailureType { get; set; }
    public SignedInfo SignedInfo { get; set; } = new SignedInfo();
    public SecurityKey SecurityKey { get; set; }
}
