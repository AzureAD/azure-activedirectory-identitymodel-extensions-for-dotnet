// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using Microsoft.IdentityModel.Tokens;

#nullable enable
namespace Microsoft.IdentityModel.TestUtils
{
    internal class CustomIssuerSigningKeyValidationDelegates
    {
        internal static ValidationResult<ValidatedSigningKeyLifetime> CustomIssuerSigningKeyValidatorDelegate(
            SecurityKey signingKey,
            SecurityToken securityToken,
            ValidationParameters validationParameters,
            BaseConfiguration? configuration,
            CallContext callContext)
        {
            // Returns a CustomIssuerSigningKeyValidationError : IssuerSigningKeyValidationError
            return new CustomIssuerSigningKeyValidationError(
                new MessageDetail(nameof(CustomIssuerSigningKeyValidatorDelegate), null),
                typeof(SecurityTokenInvalidSigningKeyException),
                ValidationError.GetCurrentStackFrame(),
                signingKey,
                null);
        }

        internal static ValidationResult<ValidatedSigningKeyLifetime> CustomIssuerSigningKeyValidatorCustomExceptionDelegate(
            SecurityKey signingKey,
            SecurityToken securityToken,
            ValidationParameters validationParameters,
            BaseConfiguration? configuration,
            CallContext callContext)
        {
            return new CustomIssuerSigningKeyValidationError(
                new MessageDetail(nameof(CustomIssuerSigningKeyValidatorCustomExceptionDelegate), null),
                typeof(CustomSecurityTokenInvalidSigningKeyException),
                ValidationError.GetCurrentStackFrame(),
                signingKey,
                null);
        }

        internal static ValidationResult<ValidatedSigningKeyLifetime> CustomIssuerSigningKeyValidatorCustomExceptionCustomFailureTypeDelegate(
            SecurityKey signingKey,
            SecurityToken securityToken,
            ValidationParameters validationParameters,
            BaseConfiguration? configuration,
            CallContext callContext)
        {
            return new CustomIssuerSigningKeyValidationError(
                new MessageDetail(nameof(CustomIssuerSigningKeyValidatorCustomExceptionCustomFailureTypeDelegate), null),
                typeof(CustomSecurityTokenInvalidSigningKeyException),
                ValidationError.GetCurrentStackFrame(),
                signingKey,
                CustomIssuerSigningKeyValidationError.CustomIssuerSigningKeyValidationFailureType);
        }

        internal static ValidationResult<ValidatedSigningKeyLifetime> CustomIssuerSigningKeyValidatorUnknownExceptionDelegate(
            SecurityKey signingKey,
            SecurityToken securityToken,
            ValidationParameters validationParameters,
            BaseConfiguration? configuration,
            CallContext callContext)
        {
            return new CustomIssuerSigningKeyValidationError(
                new MessageDetail(nameof(CustomIssuerSigningKeyValidatorUnknownExceptionDelegate), null),
                typeof(NotSupportedException),
                ValidationError.GetCurrentStackFrame(),
                signingKey,
                null);
        }

        internal static ValidationResult<ValidatedSigningKeyLifetime> CustomIssuerSigningKeyValidatorWithoutGetExceptionOverrideDelegate(
            SecurityKey signingKey,
            SecurityToken securityToken,
            ValidationParameters validationParameters,
            BaseConfiguration? configuration,
            CallContext callContext)
        {
            return new CustomIssuerSigningKeyWithoutGetExceptionValidationOverrideError(
                new MessageDetail(nameof(CustomIssuerSigningKeyValidatorWithoutGetExceptionOverrideDelegate), null),
                typeof(CustomSecurityTokenInvalidSigningKeyException),
                ValidationError.GetCurrentStackFrame(),
                signingKey,
                null);
        }

        internal static ValidationResult<ValidatedSigningKeyLifetime> IssuerSigningKeyValidatorDelegate(
            SecurityKey signingKey,
            SecurityToken securityToken,
            ValidationParameters validationParameters,
            BaseConfiguration? configuration,
            CallContext callContext)
        {
            return new IssuerSigningKeyValidationError(
                new MessageDetail(nameof(IssuerSigningKeyValidatorDelegate), null),
                typeof(SecurityTokenInvalidSigningKeyException),
                ValidationError.GetCurrentStackFrame(),
                signingKey,
                null);
        }

        internal static ValidationResult<ValidatedSigningKeyLifetime> IssuerSigningKeyValidatorThrows(
            SecurityKey signingKey,
            SecurityToken securityToken,
            ValidationParameters validationParameters,
            BaseConfiguration? configuration,
            CallContext callContext)
        {
            throw new CustomSecurityTokenInvalidSigningKeyException(nameof(IssuerSigningKeyValidatorThrows), null);
        }

        internal static ValidationResult<ValidatedSigningKeyLifetime> IssuerSigningKeyValidatorCustomIssuerSigningKeyExceptionTypeDelegate(
            SecurityKey signingKey,
            SecurityToken securityToken,
            ValidationParameters validationParameters,
            BaseConfiguration? configuration,
            CallContext callContext)
        {
            return new IssuerSigningKeyValidationError(
                new MessageDetail(nameof(IssuerSigningKeyValidatorCustomIssuerSigningKeyExceptionTypeDelegate), null),
                typeof(CustomSecurityTokenInvalidSigningKeyException),
                ValidationError.GetCurrentStackFrame(),
                signingKey,
                null);
        }

        internal static ValidationResult<ValidatedSigningKeyLifetime> IssuerSigningKeyValidatorCustomExceptionTypeDelegate(
            SecurityKey signingKey,
            SecurityToken securityToken,
            ValidationParameters validationParameters,
            BaseConfiguration? configuration,
            CallContext callContext)
        {
            return new IssuerSigningKeyValidationError(
                new MessageDetail(nameof(IssuerSigningKeyValidatorCustomExceptionTypeDelegate), null),
                typeof(CustomSecurityTokenException),
                ValidationError.GetCurrentStackFrame(),
                signingKey,
                null);
        }
    }
}
#nullable restore
