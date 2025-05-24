// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using Microsoft.IdentityModel.Tokens;

#nullable enable
namespace Microsoft.IdentityModel.TestUtils
{
    internal class CustomSignatureValidationDelegates
    {
        internal static ValidationResult<SecurityKey> CustomSignatureValidatorDelegate(
            SecurityToken? securityToken,
            ValidationParameters validationParameters,
            BaseConfiguration? configuration,
            CallContext callContext)
        {
            // Returns a CustomSignatureValidationError : SignatureValidationError
            return new CustomSignatureValidationError(
                new MessageDetail(nameof(CustomSignatureValidatorDelegate), null),
                ValidationFailureType.SignatureValidationFailed,
                typeof(SecurityTokenInvalidSignatureException),
                ValidationError.GetCurrentStackFrame());
        }

        internal static ValidationResult<SecurityKey> CustomSignatureValidatorCustomExceptionDelegate(
            SecurityToken? securityToken,
            ValidationParameters validationParameters,
            BaseConfiguration? configuration,
            CallContext callContext)
        {
            return new CustomSignatureValidationError(
                new MessageDetail(nameof(CustomSignatureValidatorCustomExceptionDelegate), null),
                ValidationFailureType.SignatureValidationFailed,
                typeof(CustomSecurityTokenInvalidSignatureException),
                ValidationError.GetCurrentStackFrame());
        }

        internal static ValidationResult<SecurityKey> CustomSignatureValidatorCustomExceptionCustomFailureTypeDelegate(
            SecurityToken? securityToken,
            ValidationParameters validationParameters,
            BaseConfiguration? configuration,
            CallContext callContext)
        {
            return new CustomSignatureValidationError(
                new MessageDetail(nameof(CustomSignatureValidatorCustomExceptionCustomFailureTypeDelegate), null),
                CustomSignatureValidationError.CustomSignatureValidationFailureType,
                typeof(CustomSecurityTokenInvalidSignatureException),
                ValidationError.GetCurrentStackFrame());
        }

        internal static ValidationResult<SecurityKey> CustomSignatureValidatorUnknownExceptionDelegate(
            SecurityToken? securityToken,
            ValidationParameters validationParameters,
            BaseConfiguration? configuration,
            CallContext callContext)
        {
            return new CustomSignatureValidationError(
                new MessageDetail(nameof(CustomSignatureValidatorUnknownExceptionDelegate), null),
                ValidationFailureType.SignatureValidationFailed,
                typeof(NotSupportedException),
                ValidationError.GetCurrentStackFrame());
        }

        internal static ValidationResult<SecurityKey> CustomSignatureValidatorWithoutGetExceptionOverrideDelegate(
            SecurityToken? securityToken,
            ValidationParameters validationParameters,
            BaseConfiguration? configuration,
            CallContext callContext)
        {
            return new CustomSignatureWithoutGetExceptionValidationOverrideError(
                new MessageDetail(nameof(CustomSignatureValidatorWithoutGetExceptionOverrideDelegate), null),
                ValidationFailureType.SignatureValidationFailed,
                typeof(CustomSecurityTokenInvalidSignatureException),
                ValidationError.GetCurrentStackFrame());
        }

        internal static ValidationResult<SecurityKey> SignatureValidatorDelegate(
            SecurityToken? securityToken,
            ValidationParameters validationParameters,
            BaseConfiguration? configuration,
            CallContext callContext)
        {
            return new SignatureValidationError(
                new MessageDetail(nameof(SignatureValidatorDelegate), null),
                ValidationFailureType.SignatureValidationFailed,
                typeof(SecurityTokenInvalidSignatureException),
                ValidationError.GetCurrentStackFrame());
        }

        internal static ValidationResult<SecurityKey> SignatureValidatorThrows(
            SecurityToken? securityToken,
            ValidationParameters validationParameters,
            BaseConfiguration? configuration,
            CallContext callContext)
        {
            throw new CustomSecurityTokenInvalidSignatureException(nameof(SignatureValidatorThrows), null);
        }

        internal static ValidationResult<SecurityKey> SignatureValidatorCustomSignatureExceptionTypeDelegate(
            SecurityToken? securityToken,
            ValidationParameters validationParameters,
            BaseConfiguration? configuration,
            CallContext callContext)
        {
            return new SignatureValidationError(
                new MessageDetail(nameof(SignatureValidatorCustomSignatureExceptionTypeDelegate), null),
                ValidationFailureType.SignatureValidationFailed,
                typeof(CustomSecurityTokenInvalidSignatureException),
                ValidationError.GetCurrentStackFrame());
        }

        internal static ValidationResult<SecurityKey> SignatureValidatorCustomExceptionTypeDelegate(
            SecurityToken? securityToken,
            ValidationParameters validationParameters,
            BaseConfiguration? configuration,
            CallContext callContext)
        {
            return new SignatureValidationError(
                new MessageDetail(nameof(SignatureValidatorCustomExceptionTypeDelegate), null),
                ValidationFailureType.SignatureValidationFailed,
                typeof(CustomSecurityTokenException),
                ValidationError.GetCurrentStackFrame());
        }
    }
}
#nullable restore
