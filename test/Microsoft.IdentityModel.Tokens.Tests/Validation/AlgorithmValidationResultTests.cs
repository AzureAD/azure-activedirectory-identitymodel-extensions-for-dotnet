// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Logging;
using Xunit;
using System;
using Microsoft.IdentityModel.Tokens.Experimental;
using Microsoft.Identity.Abstractions;

namespace Microsoft.IdentityModel.Tokens.Validation.Tests
{
    public class AlgorithmValidationTests
    {
        [Theory, MemberData(nameof(InvalidTestCases), DisableDiscoveryEnumeration = true)]
        public void InvalidAlgorithms(AlgorithmTheoryData theoryData)
        {
            CompareContext context = TestUtilities.WriteHeader($"{this}.InvalidAlgorithms", theoryData);

            try
            {
                OperationResult<string, ValidationError> operationResult =
                    Validators.ValidateAlgorithm(
                        theoryData.Algorithm,
                        theoryData.SecurityToken,
                        theoryData.ValidationParameters,
                        theoryData.CallContext);

                if (operationResult.Succeeded)
                {
                    context.AddDiff($"Expected operationResult to succeed, but it failed with: {operationResult.Error}.");
                }
                else
                {
                    ValidationError validationError = operationResult.Error;
                    IdentityComparer.AreStringsEqual(
                        validationError.FailureType.Name,
                        theoryData.OperationResult.Error.FailureType.Name,
                        context);

                    theoryData.ExpectedException.ProcessException(validationError.GetException(), context);
                }
            }
            catch (Exception ex)
            {
                context.AddDiff($"Did not expect an exception: {ex}.");
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<AlgorithmTheoryData> InvalidTestCases
        {
            get
            {
                SecurityKey securityKey = new SymmetricSecurityKey(new byte[256]);

                return new TheoryData<AlgorithmTheoryData>
                {
                    new AlgorithmTheoryData("ValidationParametersNull")
                    {
                        Algorithm = null,
                        ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                        SecurityKey = null,
                        SecurityToken = null,
                        ValidationParameters = null,
                        OperationResult = new AlgorithmValidationError(
                            new MessageDetail(
                                LogMessages.IDX10000,
                                LogHelper.MarkAsNonPII("validationParameters")),
                            ValidationFailureType.NullArgument,
                            null, // StackFrame
                            null,
                            null) // InvalidAlgorithm
                    },
                    new AlgorithmTheoryData("InvalidAlgorithm")
                    {
                        Algorithm = SecurityAlgorithms.Sha256,
                        ExpectedException = ExpectedException.SecurityTokenInvalidAlgorithmException("IDX10696:"),
                        SecurityKey = securityKey,
                        SecurityToken = null,
                        ValidationParameters = ValidationUtils.CreateValidationParameters(
                            algorithms: [SecurityAlgorithms.HmacSha256]),
                        OperationResult = new AlgorithmValidationError(
                            new MessageDetail(
                                LogMessages.IDX10696,
                                LogHelper.MarkAsNonPII(SecurityAlgorithms.Sha256)),
                            AlgorithmValidationFailure.ValidationFailed,
                            null, // StackFrame
                            SecurityAlgorithms.Sha256,
                            null) // InvalidAlgorithm
                    },
                };
            }
        }

        [Theory, MemberData(nameof(ValidTestCases), DisableDiscoveryEnumeration = true)]
        public void ValidAlgorithms(AlgorithmTheoryData theoryData)
        {
            CompareContext context = TestUtilities.WriteHeader($"{this}.ValidAlgorithms", theoryData);

            try
            {
                OperationResult<string, ValidationError> operationResult =
                    Validators.ValidateAlgorithm(
                        theoryData.Algorithm,
                        theoryData.SecurityToken,
                        theoryData.ValidationParameters,
                        theoryData.CallContext);

                if (operationResult.Succeeded)
                {
                    IdentityComparer.AreStringsEqual(
                        operationResult.Result,
                        theoryData.OperationResult.Result,
                        context);
                }
                else
                {
                    context.AddDiff($"Expected operationResult to succeed, but it failed with: {operationResult.Error}.");
                }
            }
            catch (Exception ex)
            {
                context.AddDiff($"Did not expect an exception: {ex}");
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<AlgorithmTheoryData> ValidTestCases
        {
            get
            {
                SecurityKey securityKey = new SymmetricSecurityKey(new byte[256]);

                return new TheoryData<AlgorithmTheoryData>
                {
                    new AlgorithmTheoryData("ValidateAlgorithmWhenValidAlgorithmsIsEmpty")
                    {
                        Algorithm = SecurityAlgorithms.Sha256,
                        SecurityKey = securityKey,
                        SecurityToken = null,
                        ValidationParameters = ValidationUtils.CreateValidationParameters(
                            algorithms: []),
                        OperationResult = SecurityAlgorithms.Sha256
                    },
                    new AlgorithmTheoryData("ValidateAlgorithmDefaultAlgorithmValidation")
                    {
                        Algorithm = SecurityAlgorithms.Sha256,
                        SecurityKey = securityKey,
                        SecurityToken = null,
                        ValidationParameters = ValidationUtils.CreateValidationParameters(
                            algorithms: [SecurityAlgorithms.HmacSha256, SecurityAlgorithms.Sha256]),
                        OperationResult = SecurityAlgorithms.Sha256
                    }
                };
            }
        }
        public class AlgorithmTheoryData : TheoryDataBase
        {
            public AlgorithmTheoryData(string testId) : base(testId) { }

            public string Algorithm { get; set; }

            public SecurityKey SecurityKey { get; set; }

            public SecurityToken SecurityToken { get; set; }

            internal ValidationParameters ValidationParameters { get; set; }

            internal OperationResult<string, AlgorithmValidationError> OperationResult { get; set; }
        }
    }
}
