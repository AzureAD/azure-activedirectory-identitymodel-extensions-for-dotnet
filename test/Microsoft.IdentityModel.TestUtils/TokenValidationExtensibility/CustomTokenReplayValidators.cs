// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Experimental;

#nullable enable
namespace Microsoft.IdentityModel.TestUtils
{
    internal class CustomTokenReplayValidationValidators
    {
        internal static ITokenReplayValidator CustomTokenReplayValidationFailed = new CustomTokenReplayValidationFailedValidator();
        internal static ITokenReplayValidator TokenReplayValidationFailed = new TokenReplayValidationFailedValidator();
        internal static ITokenReplayValidator UnknownValidationFailure = new UnknownValidationFailureValidator();
        internal static ITokenReplayValidator TokenReplayValidationDelegate = new TokenReplayValidationDelegateValidator();
        internal static ITokenReplayValidator TokenReplayValidatorThrows = new TokenReplayValidatorThrowsValidator();
        internal static ITokenReplayValidator TokenReplayValidatorCustomTokenReplayDetectedExceptionTypeDelegate = new TokenReplayValidatorCustomTokenReplayDetectedExceptionTypeDelegateValidator();
        internal static ITokenReplayValidator TokenReplayValidatorCustomExceptionTypeDelegate = new TokenReplayValidatorCustomExceptionTypeDelegateValidator();

        private class CustomTokenReplayValidationFailedValidator : ITokenReplayValidator
        {
            public ValidationResult<DateTime?, ValidationError> ValidateTokenReplay(
                DateTime? expirationTime,
                string securityToken,
                ValidationParameters validationParameters,
                CallContext callContext)
            {
                return new CustomTokenReplayValidationError(
                    new MessageDetail(nameof(CustomTokenReplayValidationFailed)),
                    CustomValidationFailure.TokenReplayValidationFailed,
                    Default.GetStackFrame(),
                    expirationTime);
            }
        }

        private class TokenReplayValidationFailedValidator : ITokenReplayValidator
        {
            public ValidationResult<DateTime?, ValidationError> ValidateTokenReplay(
                DateTime? expirationTime,
                string securityToken,
                ValidationParameters validationParameters,
                CallContext callContext)
            {
                return new CustomTokenReplayValidationError(
                    new MessageDetail(nameof(TokenReplayValidationFailed)),
                    TokenReplayValidationFailure.ValidationFailed,
                    Default.GetStackFrame(),
                    expirationTime);
            }
        }

        private class UnknownValidationFailureValidator : ITokenReplayValidator
        {
            public ValidationResult<DateTime?, ValidationError> ValidateTokenReplay(
                DateTime? expirationTime,
                string securityToken,
                ValidationParameters validationParameters,
                CallContext callContext)
            {
                return new CustomTokenReplayValidationError(
                    new MessageDetail(nameof(UnknownValidationFailure)),
                    AlgorithmValidationFailure.AlgorithmIsNotSupported,
                    Default.GetStackFrame(),
                    expirationTime);
            }
        }

        private class TokenReplayValidationDelegateValidator : ITokenReplayValidator
        {
            public ValidationResult<DateTime?, ValidationError> ValidateTokenReplay(
                DateTime? expirationTime,
                string securityToken,
                ValidationParameters validationParameters,
                CallContext callContext)
            {
                return new TokenReplayValidationError(
                    new MessageDetail(nameof(TokenReplayValidationDelegate)),
                    TokenReplayValidationFailure.ValidationFailed,
                    Default.GetStackFrame(),
                    expirationTime);
            }
        }

        private class TokenReplayValidatorThrowsValidator : ITokenReplayValidator
        {
            public ValidationResult<DateTime?, ValidationError> ValidateTokenReplay(
                DateTime? expirationTime,
                string securityToken,
                ValidationParameters validationParameters,
                CallContext callContext)
            {
                throw new CustomSecurityTokenReplayDetectedException(
                    nameof(TokenReplayValidatorThrows),
                    new TokenReplayValidationError(
                        new MessageDetail(nameof(TokenReplayValidatorThrows)),
                        TokenReplayValidationFailure.ValidationFailed,
                        Default.GetStackFrame(),
                        expirationTime),
                    null);
            }
        }

        private class TokenReplayValidatorCustomTokenReplayDetectedExceptionTypeDelegateValidator : ITokenReplayValidator
        {
            public ValidationResult<DateTime?, ValidationError> ValidateTokenReplay(
                DateTime? expirationTime,
                string securityToken,
                ValidationParameters validationParameters,
                CallContext callContext)
            {
                return new TokenReplayValidationError(
                    new MessageDetail(nameof(TokenReplayValidatorCustomTokenReplayDetectedExceptionTypeDelegate)),
                    TokenReplayValidationFailure.ValidationFailed,
                    Default.GetStackFrame(),
                    expirationTime);
            }
        }

        private class TokenReplayValidatorCustomExceptionTypeDelegateValidator : ITokenReplayValidator
        {
            public ValidationResult<DateTime?, ValidationError> ValidateTokenReplay(
                DateTime? expirationTime,
                string securityToken,
                ValidationParameters validationParameters,
                CallContext callContext)
            {
                return new TokenReplayValidationError(
                    new MessageDetail(nameof(TokenReplayValidatorCustomExceptionTypeDelegate)),
                    TokenReplayValidationFailure.ValidationFailed,
                    Default.GetStackFrame(),
                    expirationTime);
            }
        }
    }
}
#nullable restore
