// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#nullable enable
using System;
using System.Collections.Generic;
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
        [Theory, MemberData(nameof(ValidateTokenAsync_Audience_ExtensibilityTestCases), DisableDiscoveryEnumeration = true)]
        public async Task ValidateTokenAsync_Audience_Extensibility(ValidateTokenAsyncAudienceExtensibilityTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.{nameof(ValidateTokenAsync_Audience_Extensibility)}", theoryData);

            string jwtString = CreateTokenWithAudience(theoryData.Audience);
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
                var exception = await Assert.ThrowsAsync<CustomInvalidAudienceException>(async () =>
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

                IdentityComparer.AreStringsEqual(validationResult.UnwrapResult().ValidatedAudience, theoryData.Audience, context);
            }
            else
            {
                theoryData.ExpectedException.ProcessException(validationResult.UnwrapError().GetException(), context);

                if (validationResult.UnwrapError().GetException() is SecurityTokenInvalidAudienceException audienceException)
                {
                    if (theoryData.ExpectedInvalidAudience is not null)
                        IdentityComparer.AreStringsEqual(audienceException.InvalidAudience, theoryData.ExpectedInvalidAudience, context);
                }

                TestUtilities.AssertFailIfErrors(context);
            }
        }

        public static TheoryData<ValidateTokenAsyncAudienceExtensibilityTheoryData> ValidateTokenAsync_Audience_ExtensibilityTestCases
        {
            get
            {
                var theoryData = new TheoryData<ValidateTokenAsyncAudienceExtensibilityTheoryData>();
                theoryData.Add(new ValidateTokenAsyncAudienceExtensibilityTheoryData("DefaultDelegate_Valid_AudiencesMatch")
                {
                    ValidationParameters = CreateValidationParameters(audienceValidationDelegate: null),
                });

                theoryData.Add(new ValidateTokenAsyncAudienceExtensibilityTheoryData("DefaultDelegate_Invalid_AudiencesDontMatch")
                {
                    ValidationParameters = CreateValidationParameters(audienceValidationDelegate: null),
                    Audience = "CustomAudience",
                    ExpectedIsValid = false,
                    ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                });

                theoryData.Add(new ValidateTokenAsyncAudienceExtensibilityTheoryData("CustomDelegate_Valid_DelegateReturnsAudience")
                {
                    ValidationParameters = CreateValidationParameters(audienceValidationDelegate: delegate
                    (IList<string> audiences,
                    SecurityToken? securityToken,
                    ValidationParameters validationParameters,
                    CallContext callContext)
                    {
                        return "CustomAudience";
                    }),
                });

                theoryData.Add(new ValidateTokenAsyncAudienceExtensibilityTheoryData(
                        "CustomDelegate_Invalid_DelegateReturnsValidationErrorWithDefaultExceptionType")
                {
                    ValidationParameters = CreateValidationParameters(audienceValidationDelegate: delegate
                    (IList<string> audiences,
                    SecurityToken? securityToken,
                    ValidationParameters validationParameters,
                    CallContext callContext)
                    {
                        return new AudienceValidationError(
                            new MessageDetail("Custom message from the delegate."),
                            ValidationFailureType.AudienceValidationFailed,
                            typeof(SecurityTokenInvalidAudienceException),
                            new StackFrame(true),
                            [Default.Audience],
                            null);
                    }),
                    ExpectedIsValid = false,
                    ExpectedException = new ExpectedException(typeof(SecurityTokenInvalidAudienceException), "Custom message from the delegate."),
                    ExpectedInvalidAudience = Default.Audience,
                });

                theoryData.Add(new ValidateTokenAsyncAudienceExtensibilityTheoryData(
                        "CustomDelegate_Invalid_DelegateReturnsValidationErrorWithCustomExceptionType_NoCustomValidationError")
                {
                    ValidationParameters = CreateValidationParameters(audienceValidationDelegate: delegate
                    (IList<string> audiences,
                    SecurityToken? securityToken,
                    ValidationParameters validationParameters,
                    CallContext callContext)
                    {
                        return new AudienceValidationError(
                            new MessageDetail("Custom message from the delegate."),
                            ValidationFailureType.AudienceValidationFailed,
                            typeof(CustomInvalidAudienceException),
                            new StackFrame(true),
                            [Default.Audience],
                            null);
                    }),
                    ExpectedIsValid = false,
                    // The delegate returns a custom exception but does not implement a custom ValidationError.
                    ExpectedException = ExpectedException.SecurityTokenException("IDX10002:"),
                    ExpectedInvalidAudience = Default.Audience,
                });

                theoryData.Add(new ValidateTokenAsyncAudienceExtensibilityTheoryData(
                        "CustomDelegate_Invalid_DelegateReturnsValidationErrorWithCustomExceptionType_CustomValidationErrorUsed")
                {
                    ValidationParameters = CreateValidationParameters(audienceValidationDelegate: delegate
                    (IList<string> audiences,
                    SecurityToken? securityToken,
                    ValidationParameters validationParameters,
                    CallContext callContext)
                    {
                        return new CustomAudienceValidationError(
                            new MessageDetail("Custom message from the delegate."),
                            typeof(CustomInvalidAudienceException),
                            new StackFrame(true),
                            [Default.Audience]);
                    }),
                    ExpectedIsValid = false,
                    // The delegate uses a custom validation error that implements GetException to return the custom exception.
                    ExpectedException = new ExpectedException(typeof(CustomInvalidAudienceException), "Custom message from the delegate."),
                    ExpectedInvalidAudience = Default.Audience,
                });

                theoryData.Add(new ValidateTokenAsyncAudienceExtensibilityTheoryData("CustomDelegate_Invalid_DelegateThrows")
                {
                    ValidationParameters = CreateValidationParameters(audienceValidationDelegate: delegate
                    (IList<string> audiences,
                    SecurityToken? securityToken,
                    ValidationParameters validationParameters,
                    CallContext callContext)
                    {
                        throw new CustomInvalidAudienceException("Custom exception from the delegate.");
                    }),
                    ExpectedIsValid = false,
                    ThrownException = new ExpectedException(typeof(CustomInvalidAudienceException), "Custom exception from the delegate."),
                });

                return theoryData;

                static ValidationParameters CreateValidationParameters(
                    AudienceValidationDelegate? audienceValidationDelegate)
                {
                    ValidationParameters validationParameters = new ValidationParameters();
                    validationParameters.ValidAudiences.Add(Default.Audience);

                    if (audienceValidationDelegate is not null)
                        validationParameters.AudienceValidator = audienceValidationDelegate;

                    // Skip all validations except audience
                    validationParameters.AlgorithmValidator = SkipValidationDelegates.SkipAlgorithmValidation;
                    validationParameters.IssuerValidatorAsync = SkipValidationDelegates.SkipIssuerValidation;
                    validationParameters.IssuerSigningKeyValidator = SkipValidationDelegates.SkipIssuerSigningKeyValidation;
                    validationParameters.LifetimeValidator = SkipValidationDelegates.SkipLifetimeValidation;
                    validationParameters.SignatureValidator = SkipValidationDelegates.SkipSignatureValidation;
                    validationParameters.TypeValidator = SkipValidationDelegates.SkipTokenTypeValidation;

                    return validationParameters;
                }
            }
        }

        public class ValidateTokenAsyncAudienceExtensibilityTheoryData : ValidateTokenAsyncBaseTheoryData
        {
            public ValidateTokenAsyncAudienceExtensibilityTheoryData(string testId) : base(testId) { }

            public string? Audience { get; internal set; } = Default.Audience;

            public string? ExpectedInvalidAudience { get; internal set; } = null;

            internal AudienceValidationDelegate? AudienceValidationDelegate { get; set; }

            public ExpectedException? ThrownException { get; internal set; } = null;
        }

        private class CustomInvalidAudienceException : SecurityTokenInvalidAudienceException
        {
            public CustomInvalidAudienceException(string message)
                : base(message)
            {
            }
        }

        private class CustomAudienceValidationError : AudienceValidationError
        {
            public CustomAudienceValidationError(MessageDetail messageDetail,
                Type exceptionType,
                StackFrame stackFrame,
                IList<string>? tokenAudiences) :
                base(messageDetail, ValidationFailureType.AudienceValidationFailed, exceptionType, stackFrame, tokenAudiences, null)
            {
            }

            internal override Exception GetException()
            {
                if (ExceptionType == typeof(CustomInvalidAudienceException))
                    return new CustomInvalidAudienceException(MessageDetail.Message) { InvalidAudience = Utility.SerializeAsSingleCommaDelimitedString(TokenAudiences) };

                return base.GetException();
            }
        }
    }
}
#nullable restore
