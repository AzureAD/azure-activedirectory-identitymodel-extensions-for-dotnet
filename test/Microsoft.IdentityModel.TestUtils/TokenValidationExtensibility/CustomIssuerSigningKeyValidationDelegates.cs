// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Experimental;

#nullable enable
namespace Microsoft.IdentityModel.TestUtils
{
    internal class CustomIssuerSigningKeyValidationDelegates
    {
        internal static ValidationResult<ValidatedSigningKeyLifetime, IssuerSigningKeyValidationError> CustomIssuerSigningKeyValidatorDelegate(
            SecurityKey signingKey,
            SecurityToken securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            // Returns a CustomIssuerSigningKeyValidationError : IssuerSigningKeyValidationError
            return new CustomIssuerSigningKeyValidationError(
                new MessageDetail(nameof(CustomIssuerSigningKeyValidatorDelegate), null),
                ValidationFailureType.SigningKeyValidationFailed,
                typeof(SecurityTokenInvalidSigningKeyException),
                ValidationError.GetCurrentStackFrame(),
                signingKey,
                null);
        }

        internal static ValidationResult<ValidatedSigningKeyLifetime, IssuerSigningKeyValidationError> CustomIssuerSigningKeyValidatorCustomExceptionDelegate(
            SecurityKey signingKey,
            SecurityToken securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            return new CustomIssuerSigningKeyValidationError(
                new MessageDetail(nameof(CustomIssuerSigningKeyValidatorCustomExceptionDelegate), null),
                ValidationFailureType.SigningKeyValidationFailed,
                typeof(CustomSecurityTokenInvalidSigningKeyException),
                ValidationError.GetCurrentStackFrame(),
                signingKey,
                null);
        }

        internal static ValidationResult<ValidatedSigningKeyLifetime, IssuerSigningKeyValidationError> CustomIssuerSigningKeyValidatorCustomExceptionCustomFailureTypeDelegate(
            SecurityKey signingKey,
            SecurityToken securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            return new CustomIssuerSigningKeyValidationError(
                new MessageDetail(nameof(CustomIssuerSigningKeyValidatorCustomExceptionCustomFailureTypeDelegate), null),
                CustomIssuerSigningKeyValidationError.CustomIssuerSigningKeyValidationFailureType,
                typeof(CustomSecurityTokenInvalidSigningKeyException),
                ValidationError.GetCurrentStackFrame(),
                signingKey);
        }

        internal static ValidationResult<ValidatedSigningKeyLifetime, IssuerSigningKeyValidationError> CustomIssuerSigningKeyValidatorUnknownExceptionDelegate(
            SecurityKey signingKey,
            SecurityToken securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            return new CustomIssuerSigningKeyValidationError(
                new MessageDetail(nameof(CustomIssuerSigningKeyValidatorUnknownExceptionDelegate), null),
                ValidationFailureType.SigningKeyValidationFailed,
                typeof(NotSupportedException),
                ValidationError.GetCurrentStackFrame(),
                signingKey,
                null);
        }

        internal static ValidationResult<ValidatedSigningKeyLifetime, IssuerSigningKeyValidationError> CustomIssuerSigningKeyValidatorWithoutGetExceptionOverrideDelegate(
            SecurityKey signingKey,
            SecurityToken securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            return new CustomIssuerSigningKeyWithoutGetExceptionValidationOverrideError(
                new MessageDetail(nameof(CustomIssuerSigningKeyValidatorWithoutGetExceptionOverrideDelegate), null),
                typeof(CustomSecurityTokenInvalidSigningKeyException),
                ValidationError.GetCurrentStackFrame(),
                signingKey,
                null);
        }

        internal static ValidationResult<ValidatedSigningKeyLifetime, IssuerSigningKeyValidationError> IssuerSigningKeyValidatorDelegate(
            SecurityKey signingKey,
            SecurityToken securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            return new IssuerSigningKeyValidationError(
                new MessageDetail(nameof(IssuerSigningKeyValidatorDelegate), null),
                ValidationFailureType.SigningKeyValidationFailed,
                typeof(SecurityTokenInvalidSigningKeyException),
                ValidationError.GetCurrentStackFrame(),
                signingKey,
                null);
        }

        internal static ValidationResult<ValidatedSigningKeyLifetime, IssuerSigningKeyValidationError> IssuerSigningKeyValidatorThrows(
            SecurityKey signingKey,
            SecurityToken securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            throw new CustomSecurityTokenInvalidSigningKeyException(nameof(IssuerSigningKeyValidatorThrows), null);
        }

        internal static ValidationResult<ValidatedSigningKeyLifetime, IssuerSigningKeyValidationError> IssuerSigningKeyValidatorCustomIssuerSigningKeyExceptionTypeDelegate(
            SecurityKey signingKey,
            SecurityToken securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            return new IssuerSigningKeyValidationError(
                new MessageDetail(nameof(IssuerSigningKeyValidatorCustomIssuerSigningKeyExceptionTypeDelegate), null),
                ValidationFailureType.SigningKeyValidationFailed,
                typeof(CustomSecurityTokenInvalidSigningKeyException),
                ValidationError.GetCurrentStackFrame(),
                signingKey,
                null);
        }

        internal static ValidationResult<ValidatedSigningKeyLifetime, IssuerSigningKeyValidationError> IssuerSigningKeyValidatorCustomExceptionTypeDelegate(
            SecurityKey signingKey,
            SecurityToken securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            return new IssuerSigningKeyValidationError(
                new MessageDetail(nameof(IssuerSigningKeyValidatorCustomExceptionTypeDelegate), null),
                ValidationFailureType.SigningKeyValidationFailed,
                typeof(CustomSecurityTokenException),
                ValidationError.GetCurrentStackFrame(),
                signingKey,
                null);
        }
    }
}
#nullable restore
