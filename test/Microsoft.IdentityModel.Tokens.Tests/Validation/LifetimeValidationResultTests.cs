﻿// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Diagnostics;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.TestUtils;
using Xunit;

namespace Microsoft.IdentityModel.Tokens.Validation.Tests
{
    public class LifetimeValidationResultTests
    {
        [Theory, MemberData(nameof(ValidateLifetimeTestCases), DisableDiscoveryEnumeration = true)]
        public void ValidateLifetime(ValidateLifetimeTheoryData theoryData)
        {
            CompareContext context = TestUtilities.WriteHeader($"{this}.LifetimeValidatorTests", theoryData);

            LifetimeValidationResult lifetimeValidationResult = Validators.ValidateLifetime(
                theoryData.NotBefore,
                theoryData.Expires,
                theoryData.SecurityToken,
                theoryData.ValidationParameters,
                new CallContext());

            if (lifetimeValidationResult.Exception == null)
                theoryData.ExpectedException.ProcessNoException();
            else
                theoryData.ExpectedException.ProcessException(lifetimeValidationResult.Exception, context);

            IdentityComparer.AreLifetimeValidationResultsEqual(
                lifetimeValidationResult,
                theoryData.LifetimeValidationResult,
                context);

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<ValidateLifetimeTheoryData> ValidateLifetimeTestCases
        {
            get
            {
                DateTime now = DateTime.UtcNow;
                DateTime oneHourFromNow = DateTime.UtcNow.AddHours(1);
                DateTime twoHoursFromNow = DateTime.UtcNow.AddHours(2);
                DateTime twoMinutesFromNow = DateTime.UtcNow.AddMinutes(2);
                DateTime sixMinutesFromNow = DateTime.UtcNow.AddMinutes(6);
                DateTime oneHourAgo = DateTime.UtcNow.AddHours(-1);
                DateTime twoHoursAgo = DateTime.UtcNow.AddHours(-2);
                DateTime twoMinutesAgo = DateTime.UtcNow.AddMinutes(-2);
                DateTime oneMinuteAgo = DateTime.UtcNow.AddMinutes(-1);
                DateTime sixMinutesAgo = DateTime.UtcNow.AddMinutes(-6);

                return new TheoryData<ValidateLifetimeTheoryData>
                {
                    new ValidateLifetimeTheoryData("Valid")
                    {
                        Expires = oneHourFromNow,
                        NotBefore = oneHourAgo,
                        LifetimeValidationResult = new LifetimeValidationResult(oneHourAgo, oneHourFromNow),
                        ValidationParameters = new ValidationParameters()
                    },
                    new ValidateLifetimeTheoryData("Valid_NotBeforeIsNull")
                    {
                        Expires = oneHourFromNow,
                        NotBefore = null,
                        LifetimeValidationResult = new LifetimeValidationResult(null, oneHourFromNow),
                        ValidationParameters = new ValidationParameters()
                    },
                    new ValidateLifetimeTheoryData("Valid_SkewForward")
                    {
                        Expires = oneHourFromNow,
                        NotBefore = twoMinutesFromNow,
                        ValidationParameters = new ValidationParameters { ClockSkew = TimeSpan.FromMinutes(5) },
                        LifetimeValidationResult = new LifetimeValidationResult(twoMinutesFromNow, oneHourFromNow),
                    },
                    new ValidateLifetimeTheoryData("Valid_SkewBackward")
                    {
                        Expires = oneMinuteAgo,
                        NotBefore = twoMinutesAgo,
                        ValidationParameters = new ValidationParameters { ClockSkew = TimeSpan.FromMinutes(5) },
                        LifetimeValidationResult = new LifetimeValidationResult(twoMinutesAgo, oneMinuteAgo),
                    },
                    new ValidateLifetimeTheoryData("Invalid_ValidationParametersIsNull")
                    {
                        Expires = oneHourFromNow,
                        NotBefore = oneHourAgo,
                        ValidationParameters = null,
                        ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                        LifetimeValidationResult = new LifetimeValidationResult(
                            oneHourAgo,
                            oneHourFromNow,
                            ValidationFailureType.NullArgument,
                            new ExceptionDetail(
                                new MessageDetail(
                                    LogMessages.IDX10000,
                                    "validationParameters"),
                                ExceptionDetail.ExceptionType.ArgumentNull,
                                new StackFrame(true),
                                null)),
                    },
                    new ValidateLifetimeTheoryData("Invalid_ExpiresIsNull")
                    {
                        NotBefore = oneHourAgo,
                        ValidationParameters = new ValidationParameters(),
                        ExpectedException = ExpectedException.SecurityTokenNoExpirationException("IDX10225:"),
                        LifetimeValidationResult = new LifetimeValidationResult(
                            oneHourAgo,
                            null,
                            ValidationFailureType.LifetimeValidationFailed,
                            new ExceptionDetail(
                                new MessageDetail(
                                    LogMessages.IDX10225,
                                    "null"),
                                ExceptionDetail.ExceptionType.SecurityTokenNoExpiration,
                                new StackFrame(true),
                                null)),
                    },
                    new ValidateLifetimeTheoryData("Invalid_NotBeforeIsAfterExpires")
                    {
                        Expires = oneHourAgo,
                        NotBefore = oneHourFromNow,
                        ValidationParameters = new ValidationParameters(),
                        ExpectedException = ExpectedException.SecurityTokenInvalidLifetimeException("IDX10224:"),
                        LifetimeValidationResult = new LifetimeValidationResult(
                            oneHourFromNow, // notBefore
                            oneHourAgo, // expires
                            ValidationFailureType.LifetimeValidationFailed,
                            new ExceptionDetail(
                                new MessageDetail(
                                    LogMessages.IDX10224,
                                    LogHelper.MarkAsNonPII(oneHourFromNow),
                                    LogHelper.MarkAsNonPII(oneHourAgo)),
                                ExceptionDetail.ExceptionType.SecurityTokenInvalidLifetime,
                                new StackFrame(true),
                                null)),
                    },
                    new ValidateLifetimeTheoryData("Invalid_NotYetValid")
                    {
                        Expires = twoHoursFromNow,
                        NotBefore = oneHourFromNow,
                        ValidationParameters = new ValidationParameters(),
                        ExpectedException = ExpectedException.SecurityTokenNotYetValidException("IDX10222:"),
                        LifetimeValidationResult = new LifetimeValidationResult(
                            oneHourFromNow,
                            twoHoursFromNow,
                            ValidationFailureType.LifetimeValidationFailed,
                            new ExceptionDetail(
                                new MessageDetail(
                                    LogMessages.IDX10222,
                                    LogHelper.MarkAsNonPII(oneHourFromNow),
                                    LogHelper.MarkAsNonPII(now)),
                                ExceptionDetail.ExceptionType.SecurityTokenNotYetValid,
                                new StackFrame(true),
                                null)),
                    },
                    new ValidateLifetimeTheoryData("Invalid_Expired")
                    {
                        Expires = oneHourAgo,
                        NotBefore = twoHoursAgo,
                        ValidationParameters = new ValidationParameters(),
                        ExpectedException = ExpectedException.SecurityTokenExpiredException("IDX10223:"),
                        LifetimeValidationResult = new LifetimeValidationResult(
                            twoHoursAgo,
                            oneHourAgo,
                            ValidationFailureType.LifetimeValidationFailed,
                            new ExceptionDetail(
                                new MessageDetail(
                                    LogMessages.IDX10223,
                                    LogHelper.MarkAsNonPII(oneHourAgo),
                                    LogHelper.MarkAsNonPII(now)),
                                ExceptionDetail.ExceptionType.SecurityTokenExpired,
                                new StackFrame(true),
                                null)),
                    },
                    new ValidateLifetimeTheoryData("Invalid_NotYetValid_SkewForward")
                    {
                        Expires = oneHourFromNow,
                        NotBefore = sixMinutesFromNow,
                        ValidationParameters = new ValidationParameters { ClockSkew = TimeSpan.FromMinutes(5) },
                        ExpectedException = ExpectedException.SecurityTokenNotYetValidException("IDX10222:"),
                        LifetimeValidationResult = new LifetimeValidationResult(
                            sixMinutesFromNow,
                            oneHourFromNow,
                            ValidationFailureType.LifetimeValidationFailed,
                            new ExceptionDetail(
                                new MessageDetail(
                                    LogMessages.IDX10222,
                                    LogHelper.MarkAsNonPII(sixMinutesFromNow),
                                    LogHelper.MarkAsNonPII(now)),
                                ExceptionDetail.ExceptionType.SecurityTokenNotYetValid,
                                new StackFrame(true),
                                null)),
                    },
                    new ValidateLifetimeTheoryData("Invalid_Expired_SkewBackward")
                    {
                        Expires = sixMinutesAgo,
                        NotBefore = twoHoursAgo,
                        ValidationParameters = new ValidationParameters { ClockSkew = TimeSpan.FromMinutes(5) },
                        ExpectedException = ExpectedException.SecurityTokenExpiredException("IDX10223:"),
                        LifetimeValidationResult = new LifetimeValidationResult(
                            twoHoursAgo,
                            sixMinutesAgo,
                            ValidationFailureType.LifetimeValidationFailed,
                            new ExceptionDetail(
                                new MessageDetail(
                                    LogMessages.IDX10223,
                                    LogHelper.MarkAsNonPII(sixMinutesAgo),
                                    LogHelper.MarkAsNonPII(now)),
                                ExceptionDetail.ExceptionType.SecurityTokenExpired,
                                new StackFrame(true),
                                null)),
                    }
                };
            }
        }
    }

    public class ValidateLifetimeTheoryData : TheoryDataBase
    {
        public ValidateLifetimeTheoryData(string testId) : base(testId)
        {
        }

        public DateTime? NotBefore { get; set; }

        public DateTime? Expires { get; set; }

        public SecurityToken SecurityToken { get; set; }

        internal ValidationParameters ValidationParameters { get; set; }

        internal LifetimeValidationResult LifetimeValidationResult { get; set; }

        internal ValidationFailureType ValidationFailureType { get; set; }
    }
}
