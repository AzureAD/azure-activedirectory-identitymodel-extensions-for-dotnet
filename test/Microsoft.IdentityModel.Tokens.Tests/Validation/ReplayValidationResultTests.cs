// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Diagnostics;
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

            ReplayValidationResult replayValidationResult = Validators.ValidateTokenReplay(
                theoryData.ExpirationTime,
                theoryData.SecurityToken,
                theoryData.ValidationParameters,
                new CallContext());

            if (replayValidationResult.Exception != null)
                theoryData.ExpectedException.ProcessException(replayValidationResult.Exception);
            else
                theoryData.ExpectedException.ProcessNoException();

            IdentityComparer.AreTokenReplayValidationResultsEqual(
                replayValidationResult,
                theoryData.ReplayValidationResult,
                context);

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
                        ReplayValidationResult = new ReplayValidationResult(oneHourAgo)
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
                        ReplayValidationResult = new ReplayValidationResult(oneHourFromNow)
                    },
                    new TokenReplayTheoryData
                    {
                        TestId = "Invalid_SecurityToken_Null",
                        ExpirationTime = now,
                        SecurityToken = null,
                        ValidationParameters = new ValidationParameters(),
                        ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                        ReplayValidationResult = new ReplayValidationResult(
                            now,
                            ValidationFailureType.NullArgument,
                            new ExceptionDetail(
                                new MessageDetail(
                                    LogMessages.IDX10000,
                                    LogHelper.MarkAsNonPII("securityToken")),
                                ExceptionDetail.ExceptionType.ArgumentNull,
                                null))
                    },
                    new TokenReplayTheoryData
                    {
                        TestId = "Invalid_SecurityToken_Empty",
                        ExpirationTime = now,
                        SecurityToken = string.Empty,
                        ValidationParameters = new ValidationParameters(),
                        ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                        ReplayValidationResult = new ReplayValidationResult(
                            now,
                            ValidationFailureType.NullArgument,
                            new ExceptionDetail(
                                new MessageDetail(
                                    LogMessages.IDX10000,
                                    LogHelper.MarkAsNonPII("securityToken")),
                                ExceptionDetail.ExceptionType.ArgumentNull,
                                null))
                    },
                    new TokenReplayTheoryData
                    {
                        TestId = "Invalid_ValidationParameters_Null",
                        ExpirationTime = now,
                        SecurityToken = "token",
                        ValidationParameters = null,
                        ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                        ReplayValidationResult = new ReplayValidationResult(
                            now,
                            ValidationFailureType.NullArgument,
                            new ExceptionDetail(
                                new MessageDetail(
                                    LogMessages.IDX10000,
                                    LogHelper.MarkAsNonPII("validationParameters")),
                                ExceptionDetail.ExceptionType.ArgumentNull,
                                null))
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
                        ExpectedException = ExpectedException.SecurityTokenReplayDetected("IDX10227:"),
                        ReplayValidationResult = new ReplayValidationResult(
                            null,
                            ValidationFailureType.TokenReplayValidationFailed,
                            new ExceptionDetail(
                                new MessageDetail(
                                    LogMessages.IDX10227,
                                    LogHelper.MarkAsUnsafeSecurityArtifact("token", t => t.ToString())),
                                ExceptionDetail.ExceptionType.SecurityTokenReplayDetected,
                                null))
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
                        ExpectedException = ExpectedException.SecurityTokenReplayDetected("IDX10228:"),
                        ReplayValidationResult = new ReplayValidationResult(
                            oneHourFromNow,
                            ValidationFailureType.TokenReplayValidationFailed,
                            new ExceptionDetail(
                                new MessageDetail(
                                    LogMessages.IDX10228,
                                    LogHelper.MarkAsUnsafeSecurityArtifact("token", t => t.ToString())),
                                ExceptionDetail.ExceptionType.SecurityTokenReplayDetected,
                                null))
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
                        ReplayValidationResult = new ReplayValidationResult(
                            oneHourFromNow,
                            ValidationFailureType.TokenReplayValidationFailed,
                            new ExceptionDetail(
                                new MessageDetail(
                                    LogMessages.IDX10229,
                                    LogHelper.MarkAsUnsafeSecurityArtifact("token", t => t.ToString())),
                                ExceptionDetail.ExceptionType.SecurityTokenReplayDetected,
                                null))
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

        internal ReplayValidationResult ReplayValidationResult { get; set; }
    }
}
