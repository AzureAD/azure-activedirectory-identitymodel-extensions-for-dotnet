// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
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

            Result<ValidatedLifetime, ExceptionDetail> result = Validators.ValidateLifetime(
                theoryData.NotBefore,
                theoryData.Expires,
                theoryData.SecurityToken,
                theoryData.ValidationParameters,
                new CallContext());

            if (result.IsSuccess)
            {
                IdentityComparer.AreValidatedLifetimesEqual(
                    theoryData.Result.UnwrapResult(),
                    result.UnwrapResult(),
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
                        Result = new ValidatedLifetime(oneHourAgo, oneHourFromNow),
                        ValidationParameters = new ValidationParameters()
                    },
                    new ValidateLifetimeTheoryData("Valid_NotBeforeIsNull")
                    {
                        Expires = oneHourFromNow,
                        NotBefore = null,
                        Result = new ValidatedLifetime(null, oneHourFromNow),
                        ValidationParameters = new ValidationParameters()
                    },
                    new ValidateLifetimeTheoryData("Valid_SkewForward")
                    {
                        Expires = oneHourFromNow,
                        NotBefore = twoMinutesFromNow,
                        ValidationParameters = new ValidationParameters { ClockSkew = TimeSpan.FromMinutes(5) },
                        Result = new ValidatedLifetime(twoMinutesFromNow, oneHourFromNow),
                    },
                    new ValidateLifetimeTheoryData("Valid_SkewBackward")
                    {
                        Expires = oneMinuteAgo,
                        NotBefore = twoMinutesAgo,
                        ValidationParameters = new ValidationParameters { ClockSkew = TimeSpan.FromMinutes(5) },
                        Result = new ValidatedLifetime(twoMinutesAgo, oneMinuteAgo),
                    },
                    new ValidateLifetimeTheoryData("Invalid_ValidationParametersIsNull")
                    {
                        ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                        Expires = oneHourFromNow,
                        NotBefore = oneHourAgo,
                        ValidationParameters = null,
                        Result = new ExceptionDetail(
                            new MessageDetail(LogMessages.IDX10000, "validationParameters"),
                            ValidationFailureType.NullArgument,
                            ExceptionType.ArgumentNull,
                            null),
                    },
                    new ValidateLifetimeTheoryData("Invalid_ExpiresIsNull")
                    {
                        ExpectedException = ExpectedException.SecurityTokenNoExpirationException("IDX10225:"),
                        NotBefore = oneHourAgo,
                        ValidationParameters = new ValidationParameters(),
                        Result = new ExceptionDetail(
                            new MessageDetail(LogMessages.IDX10225, "null"),
                            ValidationFailureType.LifetimeValidationFailed,
                            ExceptionType.SecurityTokenNoExpiration,
                            null),
                    },
                    new ValidateLifetimeTheoryData("Invalid_NotBeforeIsAfterExpires")
                    {
                        ExpectedException = ExpectedException.SecurityTokenInvalidLifetimeException("IDX10224:"),
                        Expires = oneHourAgo,
                        NotBefore = oneHourFromNow,
                        ValidationParameters = new ValidationParameters(),
                        Result = new ExceptionDetail(
                            new MessageDetail(
                                LogMessages.IDX10224,
                                LogHelper.MarkAsNonPII(oneHourFromNow),
                                LogHelper.MarkAsNonPII(oneHourAgo)),
                            ValidationFailureType.LifetimeValidationFailed,
                            ExceptionType.SecurityTokenInvalidLifetime,
                            null),
                    },
                    new ValidateLifetimeTheoryData("Invalid_NotYetValid")
                    {
                        ExpectedException = ExpectedException.SecurityTokenNotYetValidException("IDX10222:"),
                        Expires = twoHoursFromNow,
                        NotBefore = oneHourFromNow,
                        ValidationParameters = new ValidationParameters(),
                        Result = new ExceptionDetail(
                            new MessageDetail(
                                LogMessages.IDX10222,
                                LogHelper.MarkAsNonPII(oneHourFromNow),
                                LogHelper.MarkAsNonPII(now)),
                            ValidationFailureType.LifetimeValidationFailed,
                            ExceptionType.SecurityTokenNotYetValid,
                            null),
                    },
                    new ValidateLifetimeTheoryData("Invalid_Expired")
                    {
                        ExpectedException = ExpectedException.SecurityTokenExpiredException("IDX10223:"),
                        Expires = oneHourAgo,
                        NotBefore = twoHoursAgo,
                        ValidationParameters = new ValidationParameters(),
                        Result = new ExceptionDetail(
                            new MessageDetail(
                                LogMessages.IDX10223,
                                LogHelper.MarkAsNonPII(oneHourAgo),
                                LogHelper.MarkAsNonPII(now)),
                            ValidationFailureType.LifetimeValidationFailed,
                            ExceptionType.SecurityTokenExpired,
                            null),
                    },
                    new ValidateLifetimeTheoryData("Invalid_NotYetValid_SkewForward")
                    {
                        ExpectedException = ExpectedException.SecurityTokenNotYetValidException("IDX10222:"),
                        Expires = oneHourFromNow,
                        NotBefore = sixMinutesFromNow,
                        ValidationParameters = new ValidationParameters { ClockSkew = TimeSpan.FromMinutes(5) },
                        Result = new ExceptionDetail(
                            new MessageDetail(
                                LogMessages.IDX10222,
                                LogHelper.MarkAsNonPII(sixMinutesFromNow),
                                LogHelper.MarkAsNonPII(now)),
                            ValidationFailureType.LifetimeValidationFailed,
                            ExceptionType.SecurityTokenNotYetValid,
                            null),
                    },
                    new ValidateLifetimeTheoryData("Invalid_Expired_SkewBackward")
                    {
                        ExpectedException = ExpectedException.SecurityTokenExpiredException("IDX10223:"),
                        Expires = sixMinutesAgo,
                        NotBefore = twoHoursAgo,
                        ValidationParameters = new ValidationParameters { ClockSkew = TimeSpan.FromMinutes(5) },
                        Result = new ExceptionDetail(
                            new MessageDetail(
                                LogMessages.IDX10223,
                                LogHelper.MarkAsNonPII(sixMinutesAgo),
                                LogHelper.MarkAsNonPII(now)),
                            ValidationFailureType.LifetimeValidationFailed,
                            ExceptionType.SecurityTokenExpired,
                            null),
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

        internal Result<ValidatedLifetime, ExceptionDetail> Result { get; set; }

        internal ValidationFailureType ValidationFailureType { get; set; }
    }
}
