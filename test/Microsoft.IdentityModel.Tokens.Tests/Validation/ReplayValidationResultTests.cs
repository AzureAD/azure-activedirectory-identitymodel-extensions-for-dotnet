﻿// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.TestUtils;
using Xunit;

namespace Microsoft.IdentityModel.Tokens.Validation.Tests
{
    public class ReplayValidationResultTests
    {
        [Theory, MemberData(nameof(TokenReplayValidationTestCases), DisableDiscoveryEnumeration = true)]
        public void ValidateTokenReplay(TokenReplayTheoryData theoryData)
        {
            CompareContext context = TestUtilities.WriteHeader($"{this}.TokenReplayValidationResultTests", theoryData);

            ValidationResult<DateTime?> result = Validators.ValidateTokenReplay(
                theoryData.ExpirationTime,
                theoryData.SecurityToken,
                theoryData.ValidationParameters,
                new CallContext());

            if (result.IsValid)
            {
                IdentityComparer.AreDateTimesEqualWithEpsilon(
                    result.UnwrapResult(),
                    theoryData.Result.UnwrapResult(),
                    1,
                    context);

                theoryData.ExpectedException.ProcessNoException();
            }
            else
            {
                ValidationError validationError = result.UnwrapError();
                IdentityComparer.AreStringsEqual(
                    validationError.FailureType.Name,
                    theoryData.Result.UnwrapError().FailureType.Name,
                    context);

                Exception exception = validationError.GetException();
                theoryData.ExpectedException.ProcessException(exception, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<TokenReplayTheoryData> TokenReplayValidationTestCases
        {
            get
            {
                DateTime now = DateTime.UtcNow;
                DateTime oneHourAgo = now.AddHours(-1);
                DateTime oneHourFromNow = now.AddHours(1);

                return new TheoryData<TokenReplayTheoryData>
                {
                    new TokenReplayTheoryData
                    {
                        TestId = "Valid_ReplayCache_Null",
                        ExpirationTime = oneHourAgo,
                        SecurityToken = "token",
                        ValidationParameters = new ValidationParameters
                        {
                            TokenReplayCache = null
                        },
                        Result = oneHourAgo,
                    },
                    new TokenReplayTheoryData
                    {
                        TestId = "Valid_ReplayCache_NotNull",
                        ExpirationTime = oneHourFromNow,
                        SecurityToken = "token",
                        ValidationParameters = new ValidationParameters
                        {
                            TokenReplayCache = new TokenReplayCache { OnAddReturnValue = true, OnFindReturnValue = false },
                        },
                        Result = oneHourFromNow,
                    },
                    new TokenReplayTheoryData
                    {
                        TestId = "Invalid_SecurityToken_Null",
                        ExpectedException = ExpectedException.SecurityTokenArgumentNullException("IDX10000:"),
                        ExpirationTime = now,
                        SecurityToken = null,
                        ValidationParameters = new ValidationParameters(),
                        Result = new ValidationError(
                            new MessageDetail(
                                LogMessages.IDX10000,
                                LogHelper.MarkAsNonPII("securityToken")),
                            ValidationFailureType.NullArgument,
                            typeof(SecurityTokenArgumentNullException),
                            null),
                    },
                    new TokenReplayTheoryData
                    {
                        TestId = "Invalid_SecurityToken_Empty",
                        ExpectedException = ExpectedException.SecurityTokenArgumentNullException("IDX10000:"),
                        ExpirationTime = now,
                        SecurityToken = string.Empty,
                        ValidationParameters = new ValidationParameters(),
                        Result = new ValidationError(
                            new MessageDetail(
                                LogMessages.IDX10000,
                                LogHelper.MarkAsNonPII("securityToken")),
                            ValidationFailureType.NullArgument,
                            typeof(SecurityTokenArgumentNullException),
                            null),
                    },
                    new TokenReplayTheoryData
                    {
                        TestId = "Invalid_ValidationParameters_Null",
                        ExpectedException = ExpectedException.SecurityTokenArgumentNullException("IDX10000:"),
                        ExpirationTime = now,
                        SecurityToken = "token",
                        ValidationParameters = null,
                        Result = new ValidationError(
                            new MessageDetail(
                                LogMessages.IDX10000,
                                LogHelper.MarkAsNonPII("validationParameters")),
                            ValidationFailureType.NullArgument,
                            typeof(SecurityTokenArgumentNullException),
                            null),
                    },
                    new TokenReplayTheoryData
                    {
                        TestId = "Invalid_ReplayCacheIsPresent_ExpirationTimeIsNull",
                        ExpectedException = ExpectedException.SecurityTokenReplayDetected("IDX10227:"),
                        ExpirationTime = null,
                        SecurityToken = "token",
                        ValidationParameters = new ValidationParameters
                        {
                            TokenReplayCache = new TokenReplayCache
                            {
                                OnAddReturnValue = true,
                                OnFindReturnValue = false
                            }
                        },
                        Result = new ValidationError(
                            new MessageDetail(
                                LogMessages.IDX10227,
                                LogHelper.MarkAsUnsafeSecurityArtifact("token", t => t.ToString())),
                            ValidationFailureType.TokenReplayValidationFailed,
                            typeof(SecurityTokenReplayDetectedException),
                            null),
                    },
                    new TokenReplayTheoryData
                    {
                        TestId = "Invalid_ReplayCacheIsPresent_TokenIsAlreadyInCache",
                        ExpectedException = ExpectedException.SecurityTokenReplayDetected("IDX10228:"),
                        ExpirationTime = oneHourFromNow,
                        SecurityToken= "token",
                        ValidationParameters = new ValidationParameters
                        {
                            TokenReplayCache = new TokenReplayCache
                            {
                                OnAddReturnValue = true,
                                OnFindReturnValue = true
                            },
                        },
                        Result = new ValidationError(
                            new MessageDetail(
                                LogMessages.IDX10228,
                                LogHelper.MarkAsUnsafeSecurityArtifact("token", t => t.ToString())),
                            ValidationFailureType.TokenReplayValidationFailed,
                            typeof(SecurityTokenReplayDetectedException),
                            null),
                    },
                    new TokenReplayTheoryData
                    {
                        TestId = "Invalid_ReplayCacheIsPresent_AddingTokenToCacheFails",
                        ExpirationTime = oneHourFromNow,
                        SecurityToken= "token",
                        ValidationParameters = new ValidationParameters
                        {
                            TokenReplayCache = new TokenReplayCache
                            {
                                OnAddReturnValue = false,
                                OnFindReturnValue = false
                            }
                        },
                        ExpectedException = ExpectedException.SecurityTokenReplayAddFailed("IDX10229:"),
                        Result = new ValidationError(
                            new MessageDetail(
                                LogMessages.IDX10229,
                                LogHelper.MarkAsUnsafeSecurityArtifact("token", t => t.ToString())),
                            ValidationFailureType.TokenReplayValidationFailed,
                            typeof(SecurityTokenReplayDetectedException),
                            null),
                    }
                };
            }
        }
    }

    public class TokenReplayTheoryData : TheoryDataBase
    {
        public DateTime? ExpirationTime { get; set; }

        public string SecurityToken { get; set; }

        internal ValidationParameters ValidationParameters { get; set; }

        internal ValidationResult<DateTime?> Result { get; set; }
    }
}
