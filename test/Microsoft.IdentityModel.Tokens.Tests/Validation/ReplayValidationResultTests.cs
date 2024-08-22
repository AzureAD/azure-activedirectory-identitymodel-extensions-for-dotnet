﻿// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using Microsoft.IdentityModel.Abstractions;
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

            Result<DateTime?, TokenValidationError> result = Validators.ValidateTokenReplay(
                theoryData.ExpirationTime,
                theoryData.SecurityToken,
                theoryData.ValidationParameters,
                new CallContext());

            if (result.IsSuccess)
            {
                IdentityComparer.AreDateTimesEqualWithEpsilon(
                    result.UnwrapResult(),
                    theoryData.Result.UnwrapResult(),
                    1,
                    context);
            }
            else
            {
                IdentityComparer.AreTokenValidationErrorsEqual(
                    result.UnwrapError(),
                    theoryData.Result.UnwrapError(),
                    context);

                if (result.UnwrapError().InnerException is not null)
                    theoryData.ExpectedException.ProcessException(result.UnwrapError().InnerException);
                else
                    theoryData.ExpectedException.ProcessNoException();
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
                        ExpirationTime = now,
                        SecurityToken = null,
                        ValidationParameters = new ValidationParameters(),
                        Result = new TokenValidationError(
                            ValidationErrorType.ArgumentNull,
                            new MessageDetail(
                                LogMessages.IDX10000,
                                LogHelper.MarkAsNonPII("securityToken")),
                            null),
                    },
                    new TokenReplayTheoryData
                    {
                        TestId = "Invalid_SecurityToken_Empty",
                        ExpirationTime = now,
                        SecurityToken = string.Empty,
                        ValidationParameters = new ValidationParameters(),
                        Result = new TokenValidationError(
                            ValidationErrorType.ArgumentNull,
                            new MessageDetail(
                                LogMessages.IDX10000,
                                LogHelper.MarkAsNonPII("securityToken")),
                            null),
                    },
                    new TokenReplayTheoryData
                    {
                        TestId = "Invalid_ValidationParameters_Null",
                        ExpirationTime = now,
                        SecurityToken = "token",
                        ValidationParameters = null,
                        Result = new TokenValidationError(
                            ValidationErrorType.ArgumentNull,
                            new MessageDetail(
                                LogMessages.IDX10000,
                                LogHelper.MarkAsNonPII("validationParameters")),
                            null),
                    },
                    new TokenReplayTheoryData
                    {
                        TestId = "Invalid_ReplayCacheIsPresent_ExpirationTimeIsNull",
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
                        Result = new TokenValidationError(
                            ValidationErrorType.SecurityTokenReplayDetected,
                            new MessageDetail(
                                LogMessages.IDX10227,
                                LogHelper.MarkAsUnsafeSecurityArtifact("token", t => t.ToString())),
                            null),
                    },
                    new TokenReplayTheoryData
                    {
                        TestId = "Invalid_ReplayCacheIsPresent_TokenIsAlreadyInCache",
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
                        Result = new TokenValidationError(
                            ValidationErrorType.SecurityTokenReplayDetected,
                            new MessageDetail(
                                LogMessages.IDX10228,
                                LogHelper.MarkAsUnsafeSecurityArtifact("token", t => t.ToString())),
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
                        Result = new TokenValidationError(
                            ValidationErrorType.SecurityTokenReplayDetected,
                            new MessageDetail(
                                LogMessages.IDX10229,
                                LogHelper.MarkAsUnsafeSecurityArtifact("token", t => t.ToString())),
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

        internal Result<DateTime?, TokenValidationError> Result { get; set; }
    }
}
