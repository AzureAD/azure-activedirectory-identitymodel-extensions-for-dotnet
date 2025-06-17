// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using Microsoft.Identity.Abstractions;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Experimental;

#nullable enable
namespace Microsoft.IdentityModel.TestUtils
{
    internal class CustomAlgorithmValidationDelegates
    {
        internal static OperationResult<string, ValidationError> CustomAlgorithmValidatorDelegate(
            string algorithm,
            SecurityKey securityKey,
            SecurityToken securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            // Returns a CustomAlgorithmValidationError : AlgorithmValidationError
            return new CustomAlgorithmValidationError(
                new MessageDetail(nameof(CustomAlgorithmValidatorDelegate), null),
                ValidationFailureType.InvalidAlgorithm,
                typeof(SecurityTokenInvalidAlgorithmException),
                ValidationError.GetCurrentStackFrame(),
                algorithm);
        }

        internal static OperationResult<string, ValidationError> CustomAlgorithmValidatorCustomExceptionDelegate(
            string algorithm,
            SecurityKey securityKey,
            SecurityToken securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            return new CustomAlgorithmValidationError(
                new MessageDetail(nameof(CustomAlgorithmValidatorCustomExceptionDelegate), null),
                ValidationFailureType.InvalidAlgorithm,
                typeof(CustomSecurityTokenInvalidAlgorithmException),
                ValidationError.GetCurrentStackFrame(),
                algorithm);
        }

        internal static OperationResult<string, ValidationError> CustomAlgorithmValidatorCustomExceptionCustomFailureTypeDelegate(
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

        internal static OperationResult<string, ValidationError> CustomAlgorithmValidatorUnknownExceptionDelegate(
            string algorithm,
            SecurityKey securityKey,
            SecurityToken securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            return new CustomAlgorithmValidationError(
                new MessageDetail(nameof(CustomAlgorithmValidatorUnknownExceptionDelegate), null),
                ValidationFailureType.InvalidAlgorithm,
                typeof(NotSupportedException),
                ValidationError.GetCurrentStackFrame(),
                algorithm);
        }

        internal static OperationResult<string, ValidationError> CustomAlgorithmValidatorWithoutGetExceptionOverrideDelegate(
            string algorithm,
            SecurityKey securityKey,
            SecurityToken securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            return new CustomAlgorithmWithoutGetExceptionValidationOverrideError(
                new MessageDetail(nameof(CustomAlgorithmValidatorWithoutGetExceptionOverrideDelegate), null),
                ValidationFailureType.InvalidAlgorithm,
                typeof(CustomSecurityTokenInvalidAlgorithmException),
                ValidationError.GetCurrentStackFrame(),
                algorithm);
        }

        internal static OperationResult<string, ValidationError> AlgorithmValidatorDelegate(
            string algorithm,
            SecurityKey securityKey,
            SecurityToken securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            return new AlgorithmValidationError(
                new MessageDetail(nameof(AlgorithmValidatorDelegate), null),
                ValidationFailureType.InvalidAlgorithm,
                ValidationError.GetCurrentStackFrame(),
                algorithm,
                null);
        }

        internal static OperationResult<string, ValidationError> AlgorithmValidatorThrows(
            string algorithm,
            SecurityKey securityKey,
            SecurityToken securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            throw new CustomSecurityTokenInvalidAlgorithmException(
                nameof(AlgorithmValidatorThrows),
                new AlgorithmValidationError(
                    new MessageDetail(nameof(AlgorithmValidatorDelegate), null),
                    ValidationFailureType.InvalidAlgorithm,
                    ValidationError.GetCurrentStackFrame(),
                    algorithm,
                    null),
                null);
        }

        internal static OperationResult<string, ValidationError> AlgorithmValidatorCustomAlgorithmExceptionTypeDelegate(
            string algorithm,
            SecurityKey securityKey,
            SecurityToken securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            return new AlgorithmValidationError(
                new MessageDetail(nameof(AlgorithmValidatorCustomAlgorithmExceptionTypeDelegate), null),
                ValidationFailureType.InvalidAlgorithm,
                ValidationError.GetCurrentStackFrame(),
                algorithm);
        }

        internal static OperationResult<string, ValidationError> AlgorithmValidatorCustomExceptionTypeDelegate(
            string algorithm,
            SecurityKey securityKey,
            SecurityToken securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            return new AlgorithmValidationError(
                new MessageDetail(nameof(AlgorithmValidatorCustomExceptionTypeDelegate), null),
                ValidationFailureType.InvalidAlgorithm,
                ValidationError.GetCurrentStackFrame(),
                algorithm);
        }
    }
}
#nullable restore
