// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#nullable enable
using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Microsoft.IdentityModel.JsonWebTokens.Tests
{
    public partial class JsonWebTokenHandlerValidateTokenAsyncTests
    {
        [Theory, MemberData(nameof(ValidateTokenAsync_Lifetime_ExtensibilityTestCases), DisableDiscoveryEnumeration = true)]
        public async Task ValidateTokenAsync_Lifetime_Extensibility(ValidateTokenAsyncLifetimeExtensibilityTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.{nameof(ValidateTokenAsync_Lifetime_Extensibility)}", theoryData);

            string jwtString = CreateToken(theoryData.IssuedAt, theoryData.NotBefore, theoryData.Expires);
            var handler = new JsonWebTokenHandler();

            ValidationResult<ValidatedToken> validationResult;

            if (theoryData.ThrownException is null)
            {
                validationResult = await handler.ValidateTokenAsync(
                    jwtString, theoryData.ValidationParameters!, theoryData.CallContext, CancellationToken.None);
            }
            else
            {
                // The exception is thrown by the delegate, so we catch it here.
                // Outside of testing, this could be a catch block in the calling code.
                var exception = await Assert.ThrowsAsync<CustomInvalidLifetimeException>(async () =>
                {
                    validationResult = await handler.ValidateTokenAsync(
                        jwtString, theoryData.ValidationParameters!, theoryData.CallContext, CancellationToken.None);
                });

                theoryData.ThrownException.ProcessException(exception, context);
                return;
            }

            if (validationResult.IsValid != theoryData.ExpectedIsValid)
                context.AddDiff($"validationResult.IsValid != theoryData.ExpectedIsValid");

            if (validationResult.IsValid)
            {
                theoryData.ExpectedException.ProcessNoException(context);

                ValidatedLifetime? validatedLifetime = validationResult.UnwrapResult().ValidatedLifetime;

                if (validatedLifetime is not null)
                {
                    IdentityComparer.AreDateTimesEqualWithEpsilon(validatedLifetime.Value.NotBefore, theoryData.ValidatedLifetime.NotBefore, 3, context);
                    IdentityComparer.AreDateTimesEqualWithEpsilon(validatedLifetime.Value.Expires, theoryData.ValidatedLifetime.Expires, 3, context);
                }
            }
            else
            {
                theoryData.ExpectedException.ProcessException(validationResult.UnwrapError().GetException(), context);

                if (validationResult.UnwrapError().GetException() is SecurityTokenInvalidLifetimeException lifetimeException)
                {
                    if (theoryData.ExpectedInvalidNotBefore is not null)
                        IdentityComparer.AreDateTimesEqualWithEpsilon(lifetimeException.NotBefore, theoryData.ExpectedInvalidNotBefore, 3, context);

                    if (theoryData.ExpectedInvalidExpires is not null)
                        IdentityComparer.AreDateTimesEqualWithEpsilon(lifetimeException.Expires, theoryData.ExpectedInvalidExpires, 3, context);
                }

                TestUtilities.AssertFailIfErrors(context);
            }
        }

        public static TheoryData<ValidateTokenAsyncLifetimeExtensibilityTheoryData> ValidateTokenAsync_Lifetime_ExtensibilityTestCases
        {
            get
            {
                DateTime now = DateTime.UtcNow;
                DateTime nowPlus1Hour = now.AddHours(1);
                DateTime nowMinus1Hour = now.AddHours(-1);

                var theoryData = new TheoryData<ValidateTokenAsyncLifetimeExtensibilityTheoryData>();

                theoryData.Add(new ValidateTokenAsyncLifetimeExtensibilityTheoryData("DefaultDelegate_Valid_LifetimeIsValid")
                {
                    IssuedAt = now,
                    NotBefore = nowMinus1Hour,
                    Expires = nowPlus1Hour,
                    ValidationParameters = CreateValidationParameters(lifetimeValidationDelegate: null),
                });

                theoryData.Add(new ValidateTokenAsyncLifetimeExtensibilityTheoryData("DefaultDelegate_Invalid_TokenHasExpired")
                {
                    ValidationParameters = CreateValidationParameters(lifetimeValidationDelegate: null),
                    IssuedAt = nowMinus1Hour,
                    NotBefore = nowMinus1Hour,
                    Expires = nowMinus1Hour,
                    ExpectedIsValid = false,
                    ExpectedException = ExpectedException.SecurityTokenExpiredException("IDX10223:"),
                });

                theoryData.Add(new ValidateTokenAsyncLifetimeExtensibilityTheoryData("CustomDelegate_Valid_DelegateReturnsValidatedLifetime")
                {
                    IssuedAt = nowMinus1Hour,
                    NotBefore = nowMinus1Hour,
                    Expires = nowMinus1Hour,
                    ValidationParameters = CreateValidationParameters(lifetimeValidationDelegate: delegate
                    (DateTime? notBefore,
                    DateTime? expires,
                    SecurityToken? securityToken,
                    ValidationParameters validationParameters,
                    CallContext callContext)
                    {
                        return new ValidatedLifetime(notBefore, expires);
                    }),
                });

                theoryData.Add(new ValidateTokenAsyncLifetimeExtensibilityTheoryData("CustomDelegate_Valid_DelegateReturnsEmptyValidatedLifetime")
                {
                    IssuedAt = nowMinus1Hour,
                    NotBefore = nowMinus1Hour,
                    Expires = nowMinus1Hour,
                    ValidationParameters = CreateValidationParameters(lifetimeValidationDelegate: delegate
                    (DateTime? notBefore,
                    DateTime? expires,
                    SecurityToken? securityToken,
                    ValidationParameters validationParameters,
                    CallContext callContext)
                    {
                        return new ValidatedLifetime();
                    }),
                });

                theoryData.Add(new ValidateTokenAsyncLifetimeExtensibilityTheoryData(
                        "CustomDelegate_Invalid_DelegateReturnsValidationErrorWithDefaultExceptionType")
                {
                    IssuedAt = nowMinus1Hour,
                    NotBefore = nowMinus1Hour,
                    Expires = nowMinus1Hour,
                    ValidationParameters = CreateValidationParameters(lifetimeValidationDelegate: delegate
                    (DateTime? notBefore,
                    DateTime? expires,
                    SecurityToken? securityToken,
                    ValidationParameters validationParameters,
                    CallContext callContext)
                    {
                        return new LifetimeValidationError(new MessageDetail("Custom message from the delegate."),
                            typeof(SecurityTokenInvalidLifetimeException),
                            new System.Diagnostics.StackFrame(true),
                            (DateTime)notBefore!,
                            (DateTime)expires!);
                    }),
                    ExpectedIsValid = false,
                    ExpectedException = new ExpectedException(typeof(SecurityTokenInvalidLifetimeException), "Custom message from the delegate."),
                    ExpectedInvalidNotBefore = nowMinus1Hour,
                    ExpectedInvalidExpires = nowMinus1Hour,
                });

                theoryData.Add(new ValidateTokenAsyncLifetimeExtensibilityTheoryData(
                        "CustomDelegate_Invalid_DelegateReturnsValidationErrorWithCustomExceptionType_NoCustomValidationError")
                {
                    IssuedAt = nowMinus1Hour,
                    NotBefore = nowMinus1Hour,
                    Expires = nowMinus1Hour,
                    ValidationParameters = CreateValidationParameters(lifetimeValidationDelegate: delegate
                    (DateTime? notBefore,
                    DateTime? expires,
                    SecurityToken? securityToken,
                    ValidationParameters validationParameters,
                    CallContext callContext)
                    {
                        return new LifetimeValidationError(
                            new MessageDetail("Custom message from the delegate."),
                            typeof(CustomInvalidLifetimeException),
                            new System.Diagnostics.StackFrame(true),
                            (DateTime)notBefore!,
                            (DateTime)expires!);
                    }),
                    ExpectedIsValid = false,
                    // The delegate returns a custom exception but does not implement a custom ValidationError.
                    ExpectedException = ExpectedException.SecurityTokenException("IDX10002:"),
                    ExpectedInvalidNotBefore = nowMinus1Hour,
                    ExpectedInvalidExpires = nowMinus1Hour,
                });

                theoryData.Add(new ValidateTokenAsyncLifetimeExtensibilityTheoryData(
                        "CustomDelegate_Invalid_DelegateReturnsValidationErrorWithCustomExceptionType_CustomValidationErrorUsed")
                {
                    IssuedAt = nowMinus1Hour,
                    NotBefore = nowMinus1Hour,
                    Expires = nowMinus1Hour,
                    ValidationParameters = CreateValidationParameters(lifetimeValidationDelegate: delegate
                    (DateTime? notBefore,
                    DateTime? expires,
                    SecurityToken? securityToken,
                    ValidationParameters validationParameters,
                    CallContext callContext)
                    {
                        return new CustomLifetimeValidationError(
                            new MessageDetail("Custom message from the delegate."),
                            typeof(CustomInvalidLifetimeException),
                            new System.Diagnostics.StackFrame(true),
                            (DateTime)notBefore!,
                            (DateTime)expires!);
                    }),
                    ExpectedIsValid = false,
                    // The delegate uses a custom validation error that implements GetException to return the custom exception.
                    ExpectedException = new ExpectedException(typeof(CustomInvalidLifetimeException), "Custom message from the delegate."),
                    ExpectedInvalidNotBefore = nowMinus1Hour,
                    ExpectedInvalidExpires = nowMinus1Hour,
                });

                theoryData.Add(new ValidateTokenAsyncLifetimeExtensibilityTheoryData("CustomDelegate_Invalid_DelegateThrows")
                {
                    IssuedAt = nowMinus1Hour,
                    NotBefore = nowMinus1Hour,
                    Expires = nowMinus1Hour,
                    ValidationParameters = CreateValidationParameters(lifetimeValidationDelegate: delegate
                    (DateTime? notBefore,
                    DateTime? expires,
                    SecurityToken? securityToken,
                    ValidationParameters validationParameters,
                    CallContext callContext)
                    {
                        throw new CustomInvalidLifetimeException("Custom exception from the delegate.");
                    }),
                    ExpectedIsValid = false,
                    ThrownException = new ExpectedException(typeof(CustomInvalidLifetimeException), "Custom exception from the delegate."),
                });

                return theoryData;

                static ValidationParameters CreateValidationParameters(LifetimeValidationDelegate? lifetimeValidationDelegate)
                {
                    ValidationParameters validationParameters = new ValidationParameters();

                    if (lifetimeValidationDelegate is not null)
                        validationParameters.LifetimeValidator = lifetimeValidationDelegate;

                    // Skip all validations except lifetime
                    validationParameters.AlgorithmValidator = SkipValidationDelegates.SkipAlgorithmValidation;
                    validationParameters.AudienceValidator = SkipValidationDelegates.SkipAudienceValidation;
                    validationParameters.IssuerValidatorAsync = SkipValidationDelegates.SkipIssuerValidation;
                    validationParameters.IssuerSigningKeyValidator = SkipValidationDelegates.SkipIssuerSigningKeyValidation;
                    validationParameters.SignatureValidator = SkipValidationDelegates.SkipSignatureValidation;
                    validationParameters.TokenTypeValidator = SkipValidationDelegates.SkipTokenTypeValidation;

                    return validationParameters;
                }
            }
        }

        public class ValidateTokenAsyncLifetimeExtensibilityTheoryData : ValidateTokenAsyncBaseTheoryData
        {
            public ValidateTokenAsyncLifetimeExtensibilityTheoryData(string testId) : base(testId) { }

            public DateTime? IssuedAt { get; internal set; } = null;

            public DateTime? NotBefore { get; internal set; } = null;

            public DateTime? Expires { get; internal set; } = null;

            internal ValidatedLifetime ValidatedLifetime { get; set; } = default;

            public DateTime? ExpectedInvalidNotBefore { get; internal set; } = null;

            public DateTime? ExpectedInvalidExpires { get; internal set; } = null;

            public ExpectedException? ThrownException { get; internal set; } = null;
        }

        private class CustomInvalidLifetimeException : SecurityTokenInvalidLifetimeException
        {
            public CustomInvalidLifetimeException(string message)
                : base(message)
            {
            }
        }

        private class CustomLifetimeValidationError : LifetimeValidationError
        {
            public CustomLifetimeValidationError(MessageDetail messageDetail,
                Type exceptionType,
                StackFrame stackFrame,
                DateTime notBefore,
                DateTime expires) :
                base(messageDetail, exceptionType, stackFrame, notBefore, expires)
            {
            }

            internal override Exception GetException()
            {
                if (ExceptionType == typeof(CustomInvalidLifetimeException))
                    return new CustomInvalidLifetimeException(MessageDetail.Message) { NotBefore = _notBefore, Expires = _expires };

                return base.GetException();
            }
        }

        private static string CreateToken(DateTime? issuedAt, DateTime? notBefore, DateTime? expires)
        {
            JsonWebTokenHandler jsonWebTokenHandler = new JsonWebTokenHandler();
            jsonWebTokenHandler.SetDefaultTimesOnTokenCreation = false; // Allow for null values to be passed in to validate.

            SecurityTokenDescriptor securityTokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = Default.ClaimsIdentity,
                IssuedAt = issuedAt,
                NotBefore = notBefore,
                Expires = expires,
            };

            return jsonWebTokenHandler.CreateToken(securityTokenDescriptor);
        }
    }
}
#nullable restore
