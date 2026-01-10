// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Diagnostics;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens.Experimental;
using Xunit;

namespace Microsoft.IdentityModel.Tokens.Validation.Tests
{
    public class AlgorithmValidationTests
    {
        [Theory, MemberData(nameof(InvalidTestCases), DisableDiscoveryEnumeration = true)]
        public void InvalidAlgorithms(ValidateAlgorithmTheoryData theoryData)
        {
            CompareContext context = TestUtilities.WriteHeader($"{this}.InvalidAlgorithms", theoryData);

            try
            {
                ValidationResult<string, ValidationError> validationResult =
                    Validators.ValidateAlgorithm(
                        theoryData.Algorithm,
                        theoryData.SecurityToken,
                        theoryData.ValidationParameters,
                        theoryData.CallContext);

                if (validationResult.Succeeded)
                {
                    context.AddDiff($"Expected validationResult to succeed, but it failed with: {validationResult.Error}.");
                }
                else
                {

                    ValidationError validationError = validationResult.Error;
                    TestUtilities.RecordIfMoveNextFound(context, validationError);
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

        public static TheoryData<ValidateAlgorithmTheoryData> InvalidTestCases
        {
            get
            {
                SecurityKey securityKey = new SymmetricSecurityKey(new byte[256]);

                return new TheoryData<ValidateAlgorithmTheoryData>
                {
                    new ValidateAlgorithmTheoryData("ValidationParametersNull")
                    {
                        Algorithm = null,
                        ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                        SecurityKey = null,
                        SecurityToken = null,
                        ValidationParameters = null,
                        ValidationResult = new AlgorithmValidationError(
                            new MessageDetail(
                                LogMessages.IDX10000,
                                LogHelper.MarkAsNonPII("validationParameters")),
                            ValidationFailureType.NullArgument,
                            null, // StackFrame
                            null,
                            null) // InvalidAlgorithm
                    },
                    new ValidateAlgorithmTheoryData("InvalidAlgorithm")
                    {
                        Algorithm = SecurityAlgorithms.Sha256,
                        ExpectedException = ExpectedException.SecurityTokenInvalidAlgorithmException("IDX10696:"),
                        SecurityKey = securityKey,
                        SecurityToken = null,
                        ValidationParameters = ValidationUtils.CreateValidationParameters(
                            algorithms: [SecurityAlgorithms.HmacSha256]),
                        ValidationResult = new AlgorithmValidationError(
                            new MessageDetail(
                                LogMessages.IDX10696,
                                LogHelper.MarkAsNonPII(SecurityAlgorithms.Sha256)),
                            AlgorithmValidationFailure.NotSupported,
                            null, // StackFrame
                            SecurityAlgorithms.Sha256,
                            null) // InvalidAlgorithm
                    },
                };
            }
        }

        [Theory, MemberData(nameof(ValidTestCases), DisableDiscoveryEnumeration = true)]
        public void ValidAlgorithms(ValidateAlgorithmTheoryData theoryData)
        {
            CompareContext context = TestUtilities.WriteHeader($"{this}.ValidAlgorithms", theoryData);

            try
            {
                ValidationResult<string, ValidationError> validationResult =
                    Validators.ValidateAlgorithm(
                        theoryData.Algorithm,
                        theoryData.SecurityToken,
                        theoryData.ValidationParameters,
                        theoryData.CallContext);

                if (validationResult.Succeeded)
                {
                    IdentityComparer.AreStringsEqual(
                        validationResult.Result,
                        theoryData.ValidationResult.Result,
                        context);
                }
                else
                {
                    context.AddDiff($"Expected validationResult to succeed, but it failed with: {validationResult.Error}.");
                }
            }
            catch (Exception ex)
            {
                TestUtilities.RecordUnexpectedException(context, theoryData, ex);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<ValidateAlgorithmTheoryData> ValidTestCases
        {
            get
            {
                SecurityKey securityKey = new SymmetricSecurityKey(new byte[256]);

                return new TheoryData<ValidateAlgorithmTheoryData>
                {
                    new ValidateAlgorithmTheoryData("ValidateAlgorithmWhenValidAlgorithmsIsEmpty")
                    {
                        Algorithm = SecurityAlgorithms.Sha256,
                        SecurityKey = securityKey,
                        SecurityToken = null,
                        ValidationParameters = ValidationUtils.CreateValidationParameters(
                            algorithms: []),
                        ValidationResult = SecurityAlgorithms.Sha256
                    },
                    new ValidateAlgorithmTheoryData("ValidateAlgorithmDefaultAlgorithmValidation")
                    {
                        Algorithm = SecurityAlgorithms.Sha256,
                        SecurityKey = securityKey,
                        SecurityToken = null,
                        ValidationParameters = ValidationUtils.CreateValidationParameters(
                            algorithms: [SecurityAlgorithms.HmacSha256, SecurityAlgorithms.Sha256]),
                        ValidationResult = SecurityAlgorithms.Sha256
                    }
                };
            }
        }
    }
}
