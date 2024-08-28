// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Logging;
using Xunit;
using System;

namespace Microsoft.IdentityModel.Tokens.Validation.Tests
{
    public class AlgorithmValidationResultTests
    {
        [Theory, MemberData(nameof(AlgorithmValidationTestCases), DisableDiscoveryEnumeration = true)]
        public void ValidateAlgorithm(AlgorithmTheoryData theoryData)
        {
            CompareContext context = TestUtilities.WriteHeader($"{this}.AlgorithmValidationResultTests", theoryData);

            Result<string, ExceptionDetail> result = Validators.ValidateAlgorithm(
                theoryData.Algorithm,
                theoryData.SecurityKey,
                theoryData.SecurityToken,
                theoryData.ValidationParameters,
                new CallContext());

            if (result.IsSuccess)
            {
                IdentityComparer.AreStringsEqual(
                    result.UnwrapResult(),
                    theoryData.Result.UnwrapResult(),
                    context);

                theoryData.ExpectedException.ProcessNoException();
            }
            else
            {
                ExceptionDetail exceptionDetail = result.UnwrapError();
                IdentityComparer.AreStringsEqual(
                    exceptionDetail.FailureType.Name,
                    theoryData.Result.UnwrapError().FailureType.Name,
                    context);

                Exception exception = exceptionDetail.GetException();
                theoryData.ExpectedException.ProcessException(exception, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<AlgorithmTheoryData> AlgorithmValidationTestCases
        {
            get
            {
                SecurityKey securityKey = new SymmetricSecurityKey(new byte[256]);

                return new TheoryData<AlgorithmTheoryData>
                {
                    new AlgorithmTheoryData
                    {
                        TestId = "Invalid_ValidationParametersAreNull",
                        Algorithm = null,
                        ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                        SecurityKey = null,
                        SecurityToken = null,
                        ValidationParameters = null,
                        Result = new ExceptionDetail(
                            new MessageDetail(
                                LogMessages.IDX10000,
                                LogHelper.MarkAsNonPII("validationParameters")),
                            ValidationFailureType.NullArgument,
                            typeof(ArgumentNullException),
                            null, // StackFrame
                            null) // InnerException
                    },
                    new AlgorithmTheoryData
                    {
                        TestId = "Invalid_ValidateAlgorithmNotAValidAlgorithm",
                        Algorithm = SecurityAlgorithms.Sha256,
                        ExpectedException = ExpectedException.SecurityTokenInvalidAlgorithmException("IDX10696:"),
                        SecurityKey = securityKey,
                        SecurityToken = null,
                        ValidationParameters = new ValidationParameters
                        {
                            ValidAlgorithms = new[] { SecurityAlgorithms.HmacSha256 }
                        },
                        Result = new ExceptionDetail(
                            new MessageDetail(
                                LogMessages.IDX10696,
                                LogHelper.MarkAsNonPII(SecurityAlgorithms.Sha256)),
                            ValidationFailureType.AlgorithmValidationFailed,
                            typeof(SecurityTokenInvalidAlgorithmException),
                            null, // StackFrame
                            null),// InnerException
                    },
                    new AlgorithmTheoryData
                    {
                        TestId = "Valid_ValidateAlgorithmWhenValidAlgorithmsIsNull",
                        Algorithm = SecurityAlgorithms.Sha256,
                        SecurityKey = securityKey,
                        SecurityToken = null,
                        ValidationParameters = new ValidationParameters
                        {
                            ValidAlgorithms = null
                        },
                        Result = SecurityAlgorithms.Sha256
                    },
                    new AlgorithmTheoryData
                    {
                        TestId = "Valid_ValidateAlgorithmDefaultAlgorithmValidation",
                        Algorithm = SecurityAlgorithms.Sha256,
                        SecurityKey = securityKey,
                        SecurityToken = null,
                        ValidationParameters = new ValidationParameters
                        {
                            ValidAlgorithms = new[] { SecurityAlgorithms.HmacSha256, SecurityAlgorithms.Sha256 }
                        },
                        Result = SecurityAlgorithms.Sha256
                    }
                };
            }
        }

        public class AlgorithmTheoryData : TheoryDataBase
        {
            public string Algorithm { get; set; }

            public SecurityKey SecurityKey { get; set; }

            public SecurityToken SecurityToken { get; set; }

            internal ValidationParameters ValidationParameters { get; set; }

            internal Result<string, ExceptionDetail> Result { get; set; }
        }
    }
}
