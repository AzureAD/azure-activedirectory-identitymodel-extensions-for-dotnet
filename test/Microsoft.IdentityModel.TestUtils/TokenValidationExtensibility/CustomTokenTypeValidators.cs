// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Experimental;

#nullable enable
namespace Microsoft.IdentityModel.TestUtils
{
    internal class CustomTokenTypeValidationValidators
    {
        internal static ITokenTypeValidator CustomTokenTypeValidationFailed = new CustomTokenTypeValidationFailedValidator();
        internal static ITokenTypeValidator TokenTypeValidationFailed = new TokenTypeValidationFailedValidator();
        internal static ITokenTypeValidator UnknownValidationFailure = new UnknownValidationFailureValidator();
        internal static ITokenTypeValidator TokenTypeValidatorDelegate = new TokenTypeValidatorDelegateValidator();
        internal static ITokenTypeValidator TokenTypeValidatorThrows = new TokenTypeValidatorThrowsValidator();

        private class CustomTokenTypeValidationFailedValidator : ITokenTypeValidator
        {
            public ValidationResult<ValidatedTokenType, ValidationError> ValidateTokenType(
                string? type,
                SecurityToken? securityToken,
                ValidationParameters validationParameters,
                CallContext callContext)
            {
                return new CustomTokenTypeValidationError(
                    new MessageDetail(nameof(CustomTokenTypeValidationFailed)),
                    CustomValidationFailure.TokenTypeValidationFailed,
                    Default.GetStackFrame(),
                    type,
                    null);
            }
        }

        private class TokenTypeValidationFailedValidator : ITokenTypeValidator
        {
            public ValidationResult<ValidatedTokenType, ValidationError> ValidateTokenType(
                string? tokenType,
                SecurityToken? securityToken,
                ValidationParameters validationParameters,
                CallContext callContext)
            {
                return new CustomTokenTypeValidationError(
                    new MessageDetail(nameof(TokenTypeValidationFailed)),
                    TokenTypeValidationFailure.ValidationFailed,
                    Default.GetStackFrame(),
                    tokenType,
                    null);
            }
        }

        private class UnknownValidationFailureValidator : ITokenTypeValidator
        {
            public ValidationResult<ValidatedTokenType, ValidationError> ValidateTokenType(
                string? tokenType,
                SecurityToken? securityToken,
                ValidationParameters validationParameters,
                CallContext callContext)
            {
                return new CustomTokenTypeValidationError(
                    new MessageDetail(nameof(UnknownValidationFailure)),
                    AlgorithmValidationFailure.AlgorithmIsNotSupported,
                    Default.GetStackFrame(),
                    tokenType);
            }
        }

        private class TokenTypeValidatorDelegateValidator : ITokenTypeValidator
        {
            public ValidationResult<ValidatedTokenType, ValidationError> ValidateTokenType(
                string? tokenType,
                SecurityToken? securityToken,
                ValidationParameters validationParameters,
                CallContext callContext)
            {
                return new TokenTypeValidationError(
                    new MessageDetail(nameof(TokenTypeValidatorDelegate)),
                    TokenTypeValidationFailure.ValidationFailed,
                    Default.GetStackFrame(),
                    tokenType,
                    null);
            }
        }

        private class TokenTypeValidatorThrowsValidator : ITokenTypeValidator
        {
            public ValidationResult<ValidatedTokenType, ValidationError> ValidateTokenType(
                string? type,
                SecurityToken? securityToken,
                ValidationParameters validationParameters,
                CallContext callContext)
            {
                throw new CustomSecurityTokenInvalidTypeException(
                    nameof(TokenTypeValidatorThrows),
                    new TokenTypeValidationError(
                        new MessageDetail(nameof(TokenTypeValidatorThrows)),
                        TokenTypeValidationFailure.ValidationFailed,
                        Default.GetStackFrame(),
                        type,
                        null),
                    null);
            }
        }
    }
}
#nullable restore
