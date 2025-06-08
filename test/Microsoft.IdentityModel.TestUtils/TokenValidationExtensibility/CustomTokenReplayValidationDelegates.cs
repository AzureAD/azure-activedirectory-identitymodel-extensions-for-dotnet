// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Experimental;

#nullable enable
namespace Microsoft.IdentityModel.TestUtils
{
    internal class CustomTokenReplayValidationDelegates
    {
        internal static ValidationResult<DateTime?, TokenReplayValidationError> CustomTokenReplayValidationDelegate(
            DateTime? expirationTime,
            string securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            // Returns a CustomTokenReplayValidationError : IssuerValidationError
            return new CustomTokenReplayValidationError(
                new MessageDetail(nameof(CustomTokenReplayValidationDelegate), null),
                ValidationFailureType.TokenReplayValidationFailed,
                typeof(SecurityTokenReplayDetectedException),
                ValidationError.GetCurrentStackFrame(),
                expirationTime);
        }

        internal static ValidationResult<DateTime?, TokenReplayValidationError> CustomTokenReplayValidatorCustomExceptionDelegate(
            DateTime? expirationTime,
            string securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            return new CustomTokenReplayValidationError(
                new MessageDetail(nameof(CustomTokenReplayValidatorCustomExceptionDelegate), null),
                ValidationFailureType.TokenReplayValidationFailed,
                typeof(CustomSecurityTokenReplayDetectedException),
                ValidationError.GetCurrentStackFrame(),
                expirationTime);
        }

        internal static ValidationResult<DateTime?, TokenReplayValidationError> CustomTokenReplayValidatorCustomExceptionCustomFailureTypeDelegate(
            DateTime? expirationTime,
            string securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            return new CustomTokenReplayValidationError(
                new MessageDetail(nameof(CustomTokenReplayValidatorCustomExceptionCustomFailureTypeDelegate), null),
                CustomTokenReplayValidationError.CustomTokenReplayValidationFailureType,
                typeof(CustomSecurityTokenReplayDetectedException),
                ValidationError.GetCurrentStackFrame(),
                expirationTime,
                null);
        }

        internal static ValidationResult<DateTime?, TokenReplayValidationError> CustomTokenReplayValidatorUnknownExceptionDelegate(
            DateTime? expirationTime,
            string securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            return new CustomTokenReplayValidationError(
                new MessageDetail(nameof(CustomTokenReplayValidatorUnknownExceptionDelegate), null),
                ValidationFailureType.TokenReplayValidationFailed,
                typeof(NotSupportedException),
                ValidationError.GetCurrentStackFrame(),
                expirationTime);
        }

        internal static ValidationResult<DateTime?, TokenReplayValidationError> CustomTokenReplayValidatorWithoutGetExceptionOverrideDelegate(
            DateTime? expirationTime,
            string securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            return new CustomTokenReplayWithoutGetExceptionValidationOverrideError(
                new MessageDetail(nameof(CustomTokenReplayValidatorWithoutGetExceptionOverrideDelegate), null),
                typeof(CustomSecurityTokenReplayDetectedException),
                ValidationError.GetCurrentStackFrame(),
                expirationTime);
        }

        internal static ValidationResult<DateTime?, TokenReplayValidationError> TokenReplayValidationDelegate(
            DateTime? expirationTime,
            string securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            return new TokenReplayValidationError(
                new MessageDetail(nameof(TokenReplayValidationDelegate), null),
                ValidationFailureType.TokenReplayValidationFailed,
                typeof(SecurityTokenReplayDetectedException),
                ValidationError.GetCurrentStackFrame(),
                expirationTime);
        }

        internal static ValidationResult<DateTime?, TokenReplayValidationError> TokenReplayValidatorThrows(
            DateTime? expirationTime,
            string securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            throw new CustomSecurityTokenReplayDetectedException(nameof(TokenReplayValidatorThrows), null);
        }

        internal static ValidationResult<DateTime?, TokenReplayValidationError> TokenReplayValidatorCustomTokenReplayDetectedExceptionTypeDelegate(
            DateTime? expirationTime,
            string securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            return new TokenReplayValidationError(
                new MessageDetail(nameof(TokenReplayValidatorCustomTokenReplayDetectedExceptionTypeDelegate), null),
                ValidationFailureType.TokenReplayValidationFailed,
                typeof(CustomSecurityTokenReplayDetectedException),
                ValidationError.GetCurrentStackFrame(),
                expirationTime);
        }
        internal static ValidationResult<DateTime?, TokenReplayValidationError> TokenReplayValidatorCustomExceptionTypeDelegate(
            DateTime? expirationTime,
            string securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            return new TokenReplayValidationError(
                new MessageDetail(nameof(TokenReplayValidatorCustomExceptionTypeDelegate), null),
                ValidationFailureType.TokenReplayValidationFailed,
                typeof(CustomSecurityTokenException),
                ValidationError.GetCurrentStackFrame(),
                expirationTime);
        }
    }
}
#nullable restore
