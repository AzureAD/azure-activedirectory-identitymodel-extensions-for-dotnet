// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens.Experimental;
using Xunit;

namespace Microsoft.IdentityModel.Tokens.Validation.Tests
{
    public class ReplayValidationTests
    {
        [Theory, MemberData(nameof(InvalidTestCases), DisableDiscoveryEnumeration = true)]
        public void InvalidReplays(ValidateTokenReplayTheoryData theoryData)
        {
            CompareContext context = TestUtilities.WriteHeader($"{this}.InvalidReplays", theoryData);
            try
            {
                ValidationResult<DateTime?, ValidationError> validationResult = Validators.ValidateTokenReplay(
                    theoryData.ExpirationTime,
                    theoryData.Token,
                    theoryData.ValidationParameters,
                    theoryData.CallContext);

                if (validationResult.Succeeded)
                {
                    context.AddDiff($"Expected validationResult to fail, but it succeeded with: {validationResult.Result}.");
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

        public static TheoryData<ValidateTokenReplayTheoryData> InvalidTestCases
        {
            get
            {
                DateTime now = DateTime.UtcNow;
                DateTime oneHourAgo = now.AddHours(-1);
                DateTime oneHourFromNow = now.AddHours(1);

                return new TheoryData<ValidateTokenReplayTheoryData>
                {
                    new ValidateTokenReplayTheoryData("SecurityToken_Null")
                    {
                        ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                        ExpirationTime = now,
                        Token = null,
                        ValidationParameters = new ValidationParameters(),
                        ValidationResult = new TokenReplayValidationError(
                            new MessageDetail(
                                LogMessages.IDX10000,
                                LogHelper.MarkAsNonPII("securityToken")),
                            ValidationFailureType.NullArgument,
                            null,
                            null),
                    },
                    new ValidateTokenReplayTheoryData("SecurityToken_Empty")
                    {
                        ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                        ExpirationTime = now,
                        Token = string.Empty,
                        ValidationParameters = new ValidationParameters(),
                        ValidationResult = new TokenReplayValidationError(
                            new MessageDetail(
                                LogMessages.IDX10000,
                                LogHelper.MarkAsNonPII("securityToken")),
                            ValidationFailureType.NullArgument,
                            null,
                            null),
                    },
                    new ValidateTokenReplayTheoryData("ValidationParameters_Null")
                    {
                        ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                        ExpirationTime = now,
                        Token = "token",
                        ValidationParameters = null,
                        ValidationResult = new TokenReplayValidationError(
                            new MessageDetail(
                                LogMessages.IDX10000,
                                LogHelper.MarkAsNonPII("validationParameters")),
                            ValidationFailureType.NullArgument,
                            null,
                            null),
                    },
                    new ValidateTokenReplayTheoryData("Invalid_ReplayCacheIsPresent_ExpirationTimeIsNull")
                    {
                        ExpectedException = ExpectedException.SecurityTokenReplayDetected("IDX10227:"),
                        ExpirationTime = null,
                        Token = "token",
                        ValidationParameters = new ValidationParameters
                        {
                            TokenReplayCache = new TokenReplayCache
                            {
                                OnAddReturnValue = true,
                                OnFindReturnValue = false
                            }
                        },
                        ValidationResult = new TokenReplayValidationError(
                            new MessageDetail(
                                LogMessages.IDX10227,
                                LogHelper.MarkAsUnsafeSecurityArtifact("token", t => t.ToString())),
                            TokenReplayValidationFailure.NoExpiration,
                            null,
                            null),
                    },
                    new ValidateTokenReplayTheoryData("Invalid_ReplayCacheIsPresent_TokenIsAlreadyInCache")
                    {
                        ExpectedException = ExpectedException.SecurityTokenReplayDetected("IDX10228:"),
                        ExpirationTime = oneHourFromNow,
                        Token= "token",
                        ValidationParameters = new ValidationParameters
                        {
                            TokenReplayCache = new TokenReplayCache
                            {
                                OnAddReturnValue = true,
                                OnFindReturnValue = true
                            },
                        },
                        ValidationResult = new TokenReplayValidationError(
                            new MessageDetail(
                                LogMessages.IDX10228,
                                LogHelper.MarkAsUnsafeSecurityArtifact("token", t => t.ToString())),
                            TokenReplayValidationFailure.TokenFoundInCache,
                            null,
                            null),
                    },
                    new ValidateTokenReplayTheoryData("Invalid_ReplayCacheIsPresent_AddingTokenToCacheFails")
                    {
                        ExpirationTime = oneHourFromNow,
                        Token= "token",
                        ValidationParameters = new ValidationParameters
                        {
                            TokenReplayCache = new TokenReplayCache
                            {
                                OnAddReturnValue = false,
                                OnFindReturnValue = false
                            }
                        },
                        ExpectedException = ExpectedException.SecurityTokenReplayDetected("IDX10229:"),
                        ValidationResult = new TokenReplayValidationError(
                            new MessageDetail(
                                LogMessages.IDX10229,
                                LogHelper.MarkAsUnsafeSecurityArtifact("token", t => t.ToString())),
                            TokenReplayValidationFailure.AddToCacheFailed,
                            null,
                            null),
                    }
                };
            }
        }

        [Theory, MemberData(nameof(ValidTestCases), DisableDiscoveryEnumeration = true)]
        public void ValidReplays(ValidateTokenReplayTheoryData theoryData)
        {
            CompareContext context = TestUtilities.WriteHeader($"{this}.ValidReplays", theoryData);

            try
            {
                ValidationResult<DateTime?, ValidationError> validationResult = Validators.ValidateTokenReplay(
                    theoryData.ExpirationTime,
                    theoryData.Token,
                    theoryData.ValidationParameters,
                    theoryData.CallContext);

                if (validationResult.Succeeded)
                {
                    IdentityComparer.AreDateTimesEqualWithEpsilon(
                        validationResult.Result,
                        theoryData.ValidationResult.Result,
                        1,
                        context);
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

        public static TheoryData<ValidateTokenReplayTheoryData> ValidTestCases
        {
            get
            {
                DateTime now = DateTime.UtcNow;
                DateTime oneHourAgo = now.AddHours(-1);
                DateTime oneHourFromNow = now.AddHours(1);

                return new TheoryData<ValidateTokenReplayTheoryData>
                {
                    new ValidateTokenReplayTheoryData("Valid_ReplayCache_Null")
                    {
                        ExpirationTime = oneHourAgo,
                        Token = "token",
                        ValidationParameters = new ValidationParameters
                        {
                            TokenReplayCache = null
                        },
                        ValidationResult = oneHourAgo,
                    },
                    new ValidateTokenReplayTheoryData("Valid_ReplayCache_NotNull")
                    {
                        ExpirationTime = oneHourFromNow,
                        Token = "token",
                        ValidationParameters = new ValidationParameters
                        {
                            TokenReplayCache = new TokenReplayCache { OnAddReturnValue = true, OnFindReturnValue = false },
                        },
                        ValidationResult = oneHourFromNow,
                    },
                };
            }
        }
    }
}
