// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using Microsoft.Identity.Abstractions;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Experimental;

#nullable enable
namespace Microsoft.IdentityModel.TestUtils
{
    internal class CustomTokenReplayValidationDelegates
    {
        internal static OperationResult<DateTime?, ValidationError> CustomTokenReplayValidationDelegate(
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

        internal static OperationResult<DateTime?, ValidationError> CustomTokenReplayValidatorCustomExceptionDelegate(
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

        internal static OperationResult<DateTime?, ValidationError> CustomTokenReplayValidatorCustomExceptionCustomFailureTypeDelegate(
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

        internal static OperationResult<DateTime?, ValidationError> CustomTokenReplayValidatorUnknownExceptionDelegate(
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

        internal static OperationResult<DateTime?, ValidationError> CustomTokenReplayValidatorWithoutGetExceptionOverrideDelegate(
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

        internal static OperationResult<DateTime?, ValidationError> TokenReplayValidationDelegate(
            DateTime? expirationTime,
            string securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            return new TokenReplayValidationError(
                new MessageDetail(nameof(TokenReplayValidationDelegate), null),
                ValidationFailureType.TokenReplayValidationFailed,
                ValidationError.GetCurrentStackFrame(),
                expirationTime);
        }

        internal static OperationResult<DateTime?, ValidationError> TokenReplayValidatorThrows(
            DateTime? expirationTime,
            string securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            throw new CustomSecurityTokenReplayDetectedException(
                nameof(TokenReplayValidatorThrows),
                new TokenReplayValidationError(
                    new MessageDetail(nameof(TokenReplayValidationDelegate), null),
                    ValidationFailureType.TokenReplayValidationFailed,
                    ValidationError.GetCurrentStackFrame(),
                    expirationTime),
                null);
        }

        internal static OperationResult<DateTime?, ValidationError> TokenReplayValidatorCustomTokenReplayDetectedExceptionTypeDelegate(
            DateTime? expirationTime,
            string securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            return new TokenReplayValidationError(
                new MessageDetail(nameof(TokenReplayValidatorCustomTokenReplayDetectedExceptionTypeDelegate), null),
                ValidationFailureType.TokenReplayValidationFailed,
                ValidationError.GetCurrentStackFrame(),
                expirationTime);
        }
        internal static OperationResult<DateTime?, ValidationError> TokenReplayValidatorCustomExceptionTypeDelegate(
            DateTime? expirationTime,
            string securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            return new TokenReplayValidationError(
                new MessageDetail(nameof(TokenReplayValidatorCustomExceptionTypeDelegate), null),
                ValidationFailureType.TokenReplayValidationFailed,
                ValidationError.GetCurrentStackFrame(),
                expirationTime);
        }
    }
}
#nullable restore
