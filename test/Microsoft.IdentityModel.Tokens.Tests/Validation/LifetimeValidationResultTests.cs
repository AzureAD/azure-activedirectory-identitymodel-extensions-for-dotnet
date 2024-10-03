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

            ValidationResult<ValidatedLifetime> result = Validators.ValidateLifetime(
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

        public static TheoryData<ValidateLifetimeTheoryData> ValidateLifetimeTestCases
        {
            get
            {
                MockTimeProvider timeProvider = new MockTimeProvider();
                DateTime utcNow = timeProvider.GetUtcNow().UtcDateTime;
                DateTime oneHourFromNow = utcNow.AddHours(1);
                DateTime twoHoursFromNow = utcNow.AddHours(2);
                DateTime twoMinutesFromNow = utcNow.AddMinutes(2);
                DateTime sixMinutesFromNow = utcNow.AddMinutes(6);
                DateTime oneHourAgo = utcNow.AddHours(-1);
                DateTime twoHoursAgo = utcNow.AddHours(-2);
                DateTime twoMinutesAgo = utcNow.AddMinutes(-2);
                DateTime oneMinuteAgo = utcNow.AddMinutes(-1);
                DateTime sixMinutesAgo = utcNow.AddMinutes(-6);

                return new TheoryData<ValidateLifetimeTheoryData>
                {
                    new ValidateLifetimeTheoryData("Valid")
                    {
                        Expires = oneHourFromNow,
                        NotBefore = oneHourAgo,
                        Result = new ValidatedLifetime(oneHourAgo, oneHourFromNow),
                        ValidationParameters = new ValidationParameters(){TimeProvider = timeProvider }
                    },
                    new ValidateLifetimeTheoryData("Valid_NotBeforeIsNull")
                    {
                        Expires = oneHourFromNow,
                        NotBefore = null,
                        Result = new ValidatedLifetime(null, oneHourFromNow),
                        ValidationParameters = new ValidationParameters(){ TimeProvider = timeProvider }
                    },
                    new ValidateLifetimeTheoryData("Valid_SkewForward")
                    {
                        Expires = oneHourFromNow,
                        NotBefore = twoMinutesFromNow,
                        ValidationParameters = new ValidationParameters {
                            ClockSkew = TimeSpan.FromMinutes(5),
                            TimeProvider = timeProvider
                        },
                        Result = new ValidatedLifetime(twoMinutesFromNow, oneHourFromNow),
                    },
                    new ValidateLifetimeTheoryData("Valid_SkewBackward")
                    {
                        Expires = oneMinuteAgo,
                        NotBefore = twoMinutesAgo,
                        ValidationParameters = new ValidationParameters {
                            ClockSkew = TimeSpan.FromMinutes(5),
                            TimeProvider = timeProvider
                        },
                        Result = new ValidatedLifetime(twoMinutesAgo, oneMinuteAgo),
                    },
                    new ValidateLifetimeTheoryData("Invalid_ValidationParametersIsNull")
                    {
                        ExpectedException = ExpectedException.SecurityTokenArgumentNullException("IDX10000:"),
                        Expires = oneHourFromNow,
                        NotBefore = oneHourAgo,
                        ValidationParameters = null,
                        Result = new ValidationError(
                            new MessageDetail(LogMessages.IDX10000, "validationParameters"),
                            ValidationFailureType.NullArgument,
                            typeof(SecurityTokenArgumentNullException),
                            null),
                    },
                    new ValidateLifetimeTheoryData("Invalid_ExpiresIsNull")
                    {
                        ExpectedException = ExpectedException.SecurityTokenNoExpirationException("IDX10225:"),
                        NotBefore = oneHourAgo,
                        ValidationParameters = new ValidationParameters() { TimeProvider = timeProvider },
                        Result = new ValidationError(
                            new MessageDetail(LogMessages.IDX10225, "null"),
                            ValidationFailureType.LifetimeValidationFailed,
                            typeof(SecurityTokenNoExpirationException),
                            null),
                    },
                    new ValidateLifetimeTheoryData("Invalid_NotBeforeIsAfterExpires")
                    {
                        ExpectedException = ExpectedException.SecurityTokenInvalidLifetimeException("IDX10224:"),
                        Expires = oneHourAgo,
                        NotBefore = oneHourFromNow,
                        ValidationParameters = new ValidationParameters() { TimeProvider = timeProvider },
                        Result = new ValidationError(
                            new MessageDetail(
                                LogMessages.IDX10224,
                                LogHelper.MarkAsNonPII(oneHourFromNow),
                                LogHelper.MarkAsNonPII(oneHourAgo)),
                            ValidationFailureType.LifetimeValidationFailed,
                            typeof(SecurityTokenInvalidLifetimeException),
                            null),
                    },
                    new ValidateLifetimeTheoryData("Invalid_NotYetValid")
                    {
                        ExpectedException = ExpectedException.SecurityTokenNotYetValidException("IDX10222:"),
                        Expires = twoHoursFromNow,
                        NotBefore = oneHourFromNow,
                        ValidationParameters = new ValidationParameters() { TimeProvider = timeProvider },
                        Result = new ValidationError(
                            new MessageDetail(
                                LogMessages.IDX10222,
                                LogHelper.MarkAsNonPII(oneHourFromNow),
                                LogHelper.MarkAsNonPII(utcNow)),
                            ValidationFailureType.LifetimeValidationFailed,
                            typeof(SecurityTokenNotYetValidException),
                            null),
                    },
                    new ValidateLifetimeTheoryData("Invalid_Expired")
                    {
                        ExpectedException = ExpectedException.SecurityTokenExpiredException("IDX10223:"),
                        Expires = oneHourAgo,
                        NotBefore = twoHoursAgo,
                        ValidationParameters = new ValidationParameters() { TimeProvider = timeProvider },
                        Result = new ValidationError(
                            new MessageDetail(
                                LogMessages.IDX10223,
                                LogHelper.MarkAsNonPII(oneHourAgo),
                                LogHelper.MarkAsNonPII(utcNow)),
                            ValidationFailureType.LifetimeValidationFailed,
                            typeof(SecurityTokenExpiredException),
                            null),
                    },
                    new ValidateLifetimeTheoryData("Invalid_NotYetValid_SkewForward")
                    {
                        ExpectedException = ExpectedException.SecurityTokenNotYetValidException("IDX10222:"),
                        Expires = oneHourFromNow,
                        NotBefore = sixMinutesFromNow,
                        ValidationParameters = new ValidationParameters {
                            ClockSkew = TimeSpan.FromMinutes(5),
                            TimeProvider = timeProvider
                        },
                        Result = new ValidationError(
                            new MessageDetail(
                                LogMessages.IDX10222,
                                LogHelper.MarkAsNonPII(sixMinutesFromNow),
                                LogHelper.MarkAsNonPII(utcNow)),
                            ValidationFailureType.LifetimeValidationFailed,
                            typeof(SecurityTokenNotYetValidException),
                            null),
                    },
                    new ValidateLifetimeTheoryData("Invalid_Expired_SkewBackward")
                    {
                        ExpectedException = ExpectedException.SecurityTokenExpiredException("IDX10223:"),
                        Expires = sixMinutesAgo,
                        NotBefore = twoHoursAgo,
                        ValidationParameters = new ValidationParameters {
                            ClockSkew = TimeSpan.FromMinutes(5),
                            TimeProvider = timeProvider
                        },
                        Result = new ValidationError(
                            new MessageDetail(
                                LogMessages.IDX10223,
                                LogHelper.MarkAsNonPII(sixMinutesAgo),
                                LogHelper.MarkAsNonPII(utcNow)),
                            ValidationFailureType.LifetimeValidationFailed,
                            typeof(SecurityTokenExpiredException),
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

        internal ValidationResult<ValidatedLifetime> Result { get; set; }

        internal ValidationFailureType ValidationFailureType { get; set; }
    }
}
