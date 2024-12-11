// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using Microsoft.IdentityModel.Tokens;

#nullable enable
namespace Microsoft.IdentityModel.TestUtils
{
    internal class CustomAlgorithmValidationDelegates
    {
        internal static ValidationResult<string> CustomAlgorithmValidatorDelegate(
            string algorithm,
            SecurityKey securityKey,
            SecurityToken securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            // Returns a CustomAlgorithmValidationError : AlgorithmValidationError
            return new CustomAlgorithmValidationError(
                new MessageDetail(nameof(CustomAlgorithmValidatorDelegate), null),
                ValidationFailureType.AlgorithmValidationFailed,
                typeof(SecurityTokenInvalidAlgorithmException),
                ValidationError.GetCurrentStackFrame(),
                algorithm);
        }

        internal static ValidationResult<string> CustomAlgorithmValidatorCustomExceptionDelegate(
            string algorithm,
            SecurityKey securityKey,
            SecurityToken securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            return new CustomAlgorithmValidationError(
                new MessageDetail(nameof(CustomAlgorithmValidatorCustomExceptionDelegate), null),
                ValidationFailureType.AlgorithmValidationFailed,
                typeof(CustomSecurityTokenInvalidAlgorithmException),
                ValidationError.GetCurrentStackFrame(),
                algorithm);
        }

        internal static ValidationResult<string> CustomAlgorithmValidatorCustomExceptionCustomFailureTypeDelegate(
            string algorithm,
            SecurityKey securityKey,
            SecurityToken securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            return new CustomAlgorithmValidationError(
                new MessageDetail(nameof(CustomAlgorithmValidatorCustomExceptionCustomFailureTypeDelegate), null),
                CustomAlgorithmValidationError.CustomAlgorithmValidationFailureType,
                typeof(CustomSecurityTokenInvalidAlgorithmException),
                ValidationError.GetCurrentStackFrame(),
                algorithm);
        }

        internal static ValidationResult<string> CustomAlgorithmValidatorUnknownExceptionDelegate(
            string algorithm,
            SecurityKey securityKey,
            SecurityToken securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            return new CustomAlgorithmValidationError(
                new MessageDetail(nameof(CustomAlgorithmValidatorUnknownExceptionDelegate), null),
                ValidationFailureType.AlgorithmValidationFailed,
                typeof(NotSupportedException),
                ValidationError.GetCurrentStackFrame(),
                algorithm);
        }

        internal static ValidationResult<string> CustomAlgorithmValidatorWithoutGetExceptionOverrideDelegate(
            string algorithm,
            SecurityKey securityKey,
            SecurityToken securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            return new CustomAlgorithmWithoutGetExceptionValidationOverrideError(
                new MessageDetail(nameof(CustomAlgorithmValidatorWithoutGetExceptionOverrideDelegate), null),
                ValidationFailureType.AlgorithmValidationFailed,
                typeof(CustomSecurityTokenInvalidAlgorithmException),
                ValidationError.GetCurrentStackFrame(),
                algorithm);
        }

        internal static ValidationResult<string> AlgorithmValidatorDelegate(
            string algorithm,
            SecurityKey securityKey,
            SecurityToken securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            return new AlgorithmValidationError(
                new MessageDetail(nameof(AlgorithmValidatorDelegate), null),
                ValidationFailureType.AlgorithmValidationFailed,
                typeof(SecurityTokenInvalidAlgorithmException),
                ValidationError.GetCurrentStackFrame(),
                algorithm);
        }

        internal static ValidationResult<string> AlgorithmValidatorThrows(
            string algorithm,
            SecurityKey securityKey,
            SecurityToken securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            throw new CustomSecurityTokenInvalidAlgorithmException(nameof(AlgorithmValidatorThrows), null);
        }

        internal static ValidationResult<string> AlgorithmValidatorCustomAlgorithmExceptionTypeDelegate(
            string algorithm,
            SecurityKey securityKey,
            SecurityToken securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            return new AlgorithmValidationError(
                new MessageDetail(nameof(AlgorithmValidatorCustomAlgorithmExceptionTypeDelegate), null),
                ValidationFailureType.AlgorithmValidationFailed,
                typeof(CustomSecurityTokenInvalidAlgorithmException),
                ValidationError.GetCurrentStackFrame(),
                algorithm);
        }

        internal static ValidationResult<string> AlgorithmValidatorCustomExceptionTypeDelegate(
            string algorithm,
            SecurityKey securityKey,
            SecurityToken securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            return new AlgorithmValidationError(
                new MessageDetail(nameof(AlgorithmValidatorCustomExceptionTypeDelegate), null),
                ValidationFailureType.AlgorithmValidationFailed,
                typeof(CustomSecurityTokenException),
                ValidationError.GetCurrentStackFrame(),
                algorithm);
        }
    }
}
#nullable restore
