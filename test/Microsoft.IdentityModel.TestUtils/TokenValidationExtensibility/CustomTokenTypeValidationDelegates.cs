// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using Microsoft.IdentityModel.Tokens;

#nullable enable
namespace Microsoft.IdentityModel.TestUtils
{
    internal class CustomTokenTypeValidationDelegates
    {
        internal static ValidationResult<ValidatedTokenType> CustomTokenTypeValidatorDelegate(
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

        internal static ValidationResult<ValidatedTokenType> CustomTokenTypeValidatorCustomExceptionDelegate(
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

        internal static ValidationResult<ValidatedTokenType> CustomTokenTypeValidatorCustomExceptionCustomFailureTypeDelegate(
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

        internal static ValidationResult<ValidatedTokenType> CustomTokenTypeValidatorUnknownExceptionDelegate(
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

        internal static ValidationResult<ValidatedTokenType> CustomTokenTypeValidatorWithoutGetExceptionOverrideDelegate(
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

        internal static ValidationResult<ValidatedTokenType> TokenTypeValidatorDelegate(
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

        internal static ValidationResult<ValidatedTokenType> TokenTypeValidatorThrows(
            string? type,
            SecurityToken? securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            throw new CustomSecurityTokenInvalidTypeException(nameof(TokenTypeValidatorThrows), null);
        }

        internal static ValidationResult<ValidatedTokenType> TokenTypeValidatorCustomTokenTypeExceptionTypeDelegate(
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

        internal static ValidationResult<ValidatedTokenType> TokenTypeValidatorCustomExceptionTypeDelegate(
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
