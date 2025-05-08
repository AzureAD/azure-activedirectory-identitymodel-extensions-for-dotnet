// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Experimental;

#nullable enable
namespace Microsoft.IdentityModel.TestUtils
{
    internal class CustomTokenTypeValidationDelegates
    {
        internal static ValidationResult<ValidatedTokenType, TokenTypeValidationError> CustomTokenTypeValidatorDelegate(
            string? type,
            SecurityToken? securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            // Returns a CustomTokenTypeValidationError : TokenTypeValidationError
            return new CustomTokenTypeValidationError(
                new MessageDetail(nameof(CustomTokenTypeValidatorDelegate), null),
                ValidationFailureType.TokenTypeValidationFailed,
                typeof(SecurityTokenInvalidTypeException),
                ValidationError.GetCurrentStackFrame(),
                type,
                null);
        }

        internal static ValidationResult<ValidatedTokenType, TokenTypeValidationError> CustomTokenTypeValidatorCustomExceptionDelegate(
            string? type,
            SecurityToken? securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            return new CustomTokenTypeValidationError(
                new MessageDetail(nameof(CustomTokenTypeValidatorCustomExceptionDelegate), null),
                ValidationFailureType.TokenTypeValidationFailed,
                typeof(CustomSecurityTokenInvalidTypeException),
                ValidationError.GetCurrentStackFrame(),
                type,
                null);
        }

        internal static ValidationResult<ValidatedTokenType, TokenTypeValidationError> CustomTokenTypeValidatorCustomExceptionCustomFailureTypeDelegate(
            string? type,
            SecurityToken? securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            return new CustomTokenTypeValidationError(
                new MessageDetail(nameof(CustomTokenTypeValidatorCustomExceptionCustomFailureTypeDelegate), null),
                CustomTokenTypeValidationError.CustomTokenTypeValidationFailureType,
                typeof(CustomSecurityTokenInvalidTypeException),
                ValidationError.GetCurrentStackFrame(),
                type);
        }

        internal static ValidationResult<ValidatedTokenType, TokenTypeValidationError> CustomTokenTypeValidatorUnknownExceptionDelegate(
            string? type,
            SecurityToken? securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            return new CustomTokenTypeValidationError(
                new MessageDetail(nameof(CustomTokenTypeValidatorUnknownExceptionDelegate), null),
                ValidationFailureType.TokenTypeValidationFailed,
                typeof(NotSupportedException),
                ValidationError.GetCurrentStackFrame(),
                type,
                null);
        }

        internal static ValidationResult<ValidatedTokenType, TokenTypeValidationError> CustomTokenTypeValidatorWithoutGetExceptionOverrideDelegate(
            string? type,
            SecurityToken? securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            return new CustomTokenTypeWithoutGetExceptionValidationOverrideError(
                new MessageDetail(nameof(CustomTokenTypeValidatorWithoutGetExceptionOverrideDelegate), null),
                typeof(CustomSecurityTokenInvalidTypeException),
                ValidationError.GetCurrentStackFrame(),
                type,
                null);
        }

        internal static ValidationResult<ValidatedTokenType, TokenTypeValidationError> TokenTypeValidatorDelegate(
            string? type,
            SecurityToken? securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            return new TokenTypeValidationError(
                new MessageDetail(nameof(TokenTypeValidatorDelegate), null),
                ValidationFailureType.TokenTypeValidationFailed,
                typeof(SecurityTokenInvalidTypeException),
                ValidationError.GetCurrentStackFrame(),
                type,
                null);
        }

        internal static ValidationResult<ValidatedTokenType, TokenTypeValidationError> TokenTypeValidatorThrows(
            string? type,
            SecurityToken? securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            throw new CustomSecurityTokenInvalidTypeException(nameof(TokenTypeValidatorThrows), null);
        }

        internal static ValidationResult<ValidatedTokenType, TokenTypeValidationError> TokenTypeValidatorCustomTokenTypeExceptionTypeDelegate(
            string? type,
            SecurityToken? securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            return new TokenTypeValidationError(
                new MessageDetail(nameof(TokenTypeValidatorCustomTokenTypeExceptionTypeDelegate), null),
                ValidationFailureType.TokenTypeValidationFailed,
                typeof(CustomSecurityTokenInvalidTypeException),
                ValidationError.GetCurrentStackFrame(),
                type,
                null);
        }

        internal static ValidationResult<ValidatedTokenType, TokenTypeValidationError> TokenTypeValidatorCustomExceptionTypeDelegate(
            string? type,
            SecurityToken? securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            return new TokenTypeValidationError(
                new MessageDetail(nameof(TokenTypeValidatorCustomExceptionTypeDelegate), null),
                ValidationFailureType.TokenTypeValidationFailed,
                typeof(CustomSecurityTokenException),
                ValidationError.GetCurrentStackFrame(),
                type,
                null);
        }
    }
}
#nullable restore
