// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Experimental;

#nullable enable
namespace Microsoft.IdentityModel.TestUtils
{
    internal class CustomAlgorithmValidationValidators
    {
        internal static IAlgorithmValidator CustomAlgorithmValidationFailed = new CustomAlgorithmValidationFailedValidator();
        internal static IAlgorithmValidator UnknownValidationFailure = new UnknownValidationFailureValidator();
        internal static IAlgorithmValidator AlgorithmValidationFailed = new AlgorithmValidationFailedValidator();
        internal static IAlgorithmValidator CustomWithoutGetExceptionOverride = new CustomWithoutGetExceptionOverrideValidator();
        internal static IAlgorithmValidator AlgorithmValidatorDelegate = new AlgorithmValidatorDelegateValidator();
        internal static IAlgorithmValidator AlgorithmValidatorThrows = new AlgorithmValidatorThrowsValidator();
        internal static IAlgorithmValidator AlgorithmValidatorCustomAlgorithmExceptionTypeDelegate = new AlgorithmValidatorCustomAlgorithmExceptionTypeDelegateValidator();
        internal static IAlgorithmValidator AlgorithmValidatorNotSupportedFailureDelegate = new AlgorithmValidatorNotSupportedFailureDelegateValidator();

        private class CustomAlgorithmValidationFailedValidator : IAlgorithmValidator
        {
            public ValidationResult<string, ValidationError> ValidateAlgorithm(
                string? algorithm,
                SecurityToken securityToken,
                ValidationParameters validationParameters,
                CallContext callContext)
            {
                // Returns a CustomAlgorithmValidationError : AlgorithmValidationError
                return new CustomAlgorithmValidationError(
                    new MessageDetail(nameof(CustomAlgorithmValidationFailed)),
                    CustomValidationFailure.AlgorithmValidationFailed,
                    Default.GetStackFrame(),
                    algorithm);
            }
        }

        private class UnknownValidationFailureValidator : IAlgorithmValidator
        {
            public ValidationResult<string, ValidationError> ValidateAlgorithm(
                string? algorithm,
                SecurityToken securityToken,
                ValidationParameters validationParameters,
                CallContext callContext)
            {
                return new CustomAlgorithmValidationError(
                    new MessageDetail(nameof(UnknownValidationFailure)),
                    AudienceValidationFailure.AudienceDidNotMatch,
                    Default.GetStackFrame(),
                    algorithm);
            }
        }

        private class AlgorithmValidationFailedValidator : IAlgorithmValidator
        {
            public ValidationResult<string, ValidationError> ValidateAlgorithm(
                string? algorithm,
                SecurityToken securityToken,
                ValidationParameters validationParameters,
                CallContext callContext)
            {
                return new CustomAlgorithmValidationError(
                    new MessageDetail(nameof(AlgorithmValidationFailed)),
                    AlgorithmValidationFailure.ValidationFailed,
                    Default.GetStackFrame(),
                    algorithm);
            }
        }

        private class CustomWithoutGetExceptionOverrideValidator : IAlgorithmValidator
        {
            public ValidationResult<string, ValidationError> ValidateAlgorithm(
                string? algorithm,
                SecurityToken securityToken,
                ValidationParameters validationParameters,
                CallContext callContext)
            {
                return new CustomAlgorithmWithoutGetExceptionValidationOverrideError(
                    new MessageDetail(nameof(CustomWithoutGetExceptionOverride), null),
                    AlgorithmValidationFailure.ValidationFailed,
                    Default.GetStackFrame(),
                    algorithm);
            }
        }

        private class AlgorithmValidatorDelegateValidator : IAlgorithmValidator
        {
            public ValidationResult<string, ValidationError> ValidateAlgorithm(
                string? algorithm,
                SecurityToken securityToken,
                ValidationParameters validationParameters,
                CallContext callContext)
            {
                return new AlgorithmValidationError(
                    new MessageDetail(nameof(AlgorithmValidatorDelegate)),
                    AlgorithmValidationFailure.ValidationFailed,
                    Default.GetStackFrame(),
                    algorithm);
            }
        }

        private class AlgorithmValidatorThrowsValidator : IAlgorithmValidator
        {
            public ValidationResult<string, ValidationError> ValidateAlgorithm(
                string? algorithm,
                SecurityToken securityToken,
                ValidationParameters validationParameters,
                CallContext callContext)
            {
                throw new CustomSecurityTokenInvalidAlgorithmException(
                    nameof(AlgorithmValidatorThrows),
                    new AlgorithmValidationError(
                        new MessageDetail(nameof(AlgorithmValidatorThrows), null),
                        AlgorithmValidationFailure.ValidationFailed,
                        Default.GetStackFrame(),
                        algorithm,
                        null),
                    null);
            }
        }

        private class AlgorithmValidatorCustomAlgorithmExceptionTypeDelegateValidator : IAlgorithmValidator
        {
            public ValidationResult<string, ValidationError> ValidateAlgorithm(
                string? algorithm,
                SecurityToken securityToken,
                ValidationParameters validationParameters,
                CallContext callContext)
            {
                return new AlgorithmValidationError(
                    new MessageDetail(nameof(AlgorithmValidatorCustomAlgorithmExceptionTypeDelegate)),
                    AlgorithmValidationFailure.ValidationFailed,
                    Default.GetStackFrame(),
                    algorithm);
            }
        }

        private class AlgorithmValidatorNotSupportedFailureDelegateValidator : IAlgorithmValidator
        {
            public ValidationResult<string, ValidationError> ValidateAlgorithm(
                string? algorithm,
                SecurityToken securityToken,
                ValidationParameters validationParameters,
                CallContext callContext)
            {
                return new AlgorithmValidationError(
                    new MessageDetail(nameof(AlgorithmValidatorNotSupportedFailureDelegate)),
                    AlgorithmValidationFailure.AlgorithmIsNotSupported,
                    Default.GetStackFrame(),
                    algorithm);
            }
        }
    }
}
#nullable restore
