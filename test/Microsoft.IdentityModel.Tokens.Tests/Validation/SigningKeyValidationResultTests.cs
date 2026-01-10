// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens.Experimental;
using Xunit;

namespace Microsoft.IdentityModel.Tokens.Validation.Tests
{
    public class SigningKeyTests
    {
        [Theory, MemberData(nameof(InvalidTestCases), DisableDiscoveryEnumeration = true)]
        public void InvalidSigningKeys(ValidateSigningKeyTheoryData theoryData)
        {
            CompareContext context = TestUtilities.WriteHeader($"{this}.InvalidSigningKeys", theoryData);

            try
            {
                ValidationResult<ValidatedSignatureKey, ValidationError> validationResult =
                    Validators.ValidateSignatureKey(
                        theoryData.SecurityKey,
                        theoryData.SecurityToken,
                        theoryData.ValidationParameters,
                        theoryData.CallContext);

                if (validationResult.Succeeded)
                {
                    context.AddDiff($"Expected validation to fail, but it succeeded with result: {validationResult.Result}.");
                }
                else
                {
                    ValidationError validationError = validationResult.Error;
                    IdentityComparer.AreStringsEqual(
                        validationError.FailureType.Name,
                        theoryData.ValidationResult.Error.FailureType.Name,
                        context);

                    theoryData.ExpectedException.ProcessException(validationError.GetException(), context);
                }
            }
            catch (Exception ex)
            {
                TestUtilities.RecordUnexpectedException(context, theoryData, ex);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<ValidateSigningKeyTheoryData> InvalidTestCases
        {
            get
            {
                MockTimeProvider timeProvider = new MockTimeProvider();
                DateTime utcNow = timeProvider.GetUtcNow().UtcDateTime;
                DateTime utcExpired = KeyingMaterial.ExpiredX509SecurityKey_Public.Certificate.NotAfter.ToUniversalTime();
                DateTime utcNotYetValid = KeyingMaterial.NotYetValidX509SecurityKey_Public.Certificate.NotBefore.ToUniversalTime();

                return new TheoryData<ValidateSigningKeyTheoryData>
                {
                    // TODO Error message IDX10253 message is not accurate.
                    new ValidateSigningKeyTheoryData("SecurityKeyIsNull")
                    {
                        ExpectedException = ExpectedException.SecurityTokenInvalidSigningKeyException(substringExpected: "IDX10253:"),
                        SecurityKey = null,
                        SecurityToken = new JwtSecurityToken(),
                        ValidationParameters = new ValidationParameters(){ TimeProvider = timeProvider },
                        ValidationResult = new SignatureKeyValidationError(
                            new MessageDetail(LogMessages.IDX10253),
                            SignatureKeyValidationFailure.KeyIsNull,
                            null,
                            null)
                    },
                    new ValidateSigningKeyTheoryData("SecurityTokenIsNull")
                    {
                        ExpectedException = ExpectedException.ArgumentNullException(substringExpected: "IDX10000:"),
                        SecurityKey = KeyingMaterial.SymmetricSecurityKey2_256,
                        SecurityToken = null,
                        ValidationParameters = new ValidationParameters() { TimeProvider = timeProvider },
                        ValidationResult = new SignatureKeyValidationError(
                            new MessageDetail(
                                LogMessages.IDX10000,
                                LogHelper.MarkAsNonPII("securityToken")),
                            ValidationFailureType.NullArgument,
                            null,
                            null)
                    },
                    new ValidateSigningKeyTheoryData("ValidationParametersIsNull")
                    {
                        ExpectedException = ExpectedException.ArgumentNullException(substringExpected: "IDX10000:"),
                        SecurityKey = KeyingMaterial.SymmetricSecurityKey2_256,
                        SecurityToken = new JwtSecurityToken(),
                        ValidationParameters = null,
                        ValidationResult = new SignatureKeyValidationError(
                            new MessageDetail(
                                LogMessages.IDX10000,
                                LogHelper.MarkAsNonPII("validationParameters")),
                            ValidationFailureType.NullArgument,
                            null,
                            null), // InvalidSigningKey
                    },
                    new ValidateSigningKeyTheoryData("SecurityKeyIsExpired")
                    {
                        ExpectedException = ExpectedException.SecurityTokenInvalidSigningKeyException(substringExpected: "IDX10249:"),
                        SecurityKey = KeyingMaterial.ExpiredX509SecurityKey_Public,
                        SecurityToken = new JwtSecurityToken(),
                        ValidationParameters = new ValidationParameters() { TimeProvider = timeProvider },
                        ValidationResult = new SignatureKeyValidationError(
                            new MessageDetail(
                                LogMessages.IDX10249,
                                LogHelper.MarkAsNonPII(utcExpired),
                                LogHelper.MarkAsNonPII(utcNow)),
                            SignatureKeyValidationFailure.KeyExpired,
                            null,
                            null), // InvalidSigningKey
                    },
                    new ValidateSigningKeyTheoryData("SecurityKeyIsNotYetValid")
                    {
                        ExpectedException = ExpectedException.SecurityTokenInvalidSigningKeyException(substringExpected: "IDX10248:"),
                        SecurityKey = KeyingMaterial.NotYetValidX509SecurityKey_Public,
                        SecurityToken = new JwtSecurityToken(),
                        ValidationParameters = new ValidationParameters() { TimeProvider = timeProvider },
                        ValidationResult = new SignatureKeyValidationError(
                            new MessageDetail(
                                LogMessages.IDX10248,
                                LogHelper.MarkAsNonPII(utcNotYetValid),
                                LogHelper.MarkAsNonPII(utcNow)),
                            SignatureKeyValidationFailure.NotYetValid,
                            null,
                            null), // InvalidSigningKey
                    }
                };
            }
        }

        [Theory, MemberData(nameof(ValidTestCases), DisableDiscoveryEnumeration = true)]
        public void ValidSigningKeys(ValidateSigningKeyTheoryData theoryData)
        {
            CompareContext context = TestUtilities.WriteHeader($"{this}.ValidSigningKeys", theoryData);

            try
            {
                ValidationResult<ValidatedSignatureKey, ValidationError> validationResult =
                    Validators.ValidateSignatureKey(
                        theoryData.SecurityKey,
                        theoryData.SecurityToken,
                        theoryData.ValidationParameters,
                        theoryData.CallContext);

                if (validationResult.Succeeded)
                {
                    IdentityComparer.AreValidatedSigningKeyLifetimesEqual(
                        theoryData.ValidationResult.Result,
                        validationResult.Result,
                        context);
                }
                else
                {
                    context.AddDiff($"Expected validation to succeed, but it failed with error: {validationResult.Error}.");
                }
            }
            catch (Exception ex)
            {
                TestUtilities.RecordUnexpectedException(context, theoryData, ex);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<ValidateSigningKeyTheoryData> ValidTestCases
        {
            get
            {
                MockTimeProvider timeProvider = new MockTimeProvider();
                DateTime utcNow = timeProvider.GetUtcNow().UtcDateTime;

                return new TheoryData<ValidateSigningKeyTheoryData>
                {
                    new ValidateSigningKeyTheoryData("SecurityTokenIsPresent")
                    {
                        SecurityKey = KeyingMaterial.SymmetricSecurityKey2_256,
                        SecurityToken = new JwtSecurityToken(),
                        ValidationParameters = new ValidationParameters(){ TimeProvider = timeProvider },
                        ValidationResult = new ValidatedSignatureKey(null, null, utcNow)
                    }
                };
            }
        }
    }
}
