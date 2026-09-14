// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Experimental;

#nullable enable
namespace Microsoft.IdentityModel.TestUtils
{
    internal class CustomSignatureValidationValidators
    {
        internal static ISignatureValidator CustomSignatureValidationFailed = new CustomSignatureValidationFailedValidator();
        internal static ISignatureValidator CustomSignatureValidatorCustomExceptionDelegate = new CustomSignatureValidatorCustomExceptionDelegateValidator();
        internal static ISignatureValidator UnknownValidationFailure = new UnknownValidationFailureValidator();
        internal static ISignatureValidator SignatureValidationFailed = new SignatureValidationFailedValidator();
        internal static ISignatureValidator SignatureValidatorDelegate = new SignatureValidatorDelegateValidator();
        internal static ISignatureValidator SignatureValidatorThrows = new SignatureValidatorThrowsValidator();

        private class CustomSignatureValidationFailedValidator : ISignatureValidator
        {
            public ValidationResult<SecurityKey, ValidationError> ValidateSignature(
                SecurityToken? securityToken,
                ValidationParameters validationParameters,
                BaseConfiguration? configuration,
                CallContext callContext)
            {
                return new CustomSignatureValidationError(
                    new MessageDetail(nameof(CustomSignatureValidationFailed)),
                    CustomValidationFailure.SignatureValidationFailed,
                    Default.GetStackFrame());
            }
        }

        private class CustomSignatureValidatorCustomExceptionDelegateValidator : ISignatureValidator
        {
            public ValidationResult<SecurityKey, ValidationError> ValidateSignature(
                SecurityToken? securityToken,
                ValidationParameters validationParameters,
                BaseConfiguration? configuration,
                CallContext callContext)
            {
                return new CustomSignatureValidationError(
                    new MessageDetail(nameof(CustomSignatureValidatorCustomExceptionDelegate)),
                    SignatureValidationFailure.ValidationFailed,
                    Default.GetStackFrame());
            }
        }

        private class UnknownValidationFailureValidator : ISignatureValidator
        {
            public ValidationResult<SecurityKey, ValidationError> ValidateSignature(
                SecurityToken? securityToken,
                ValidationParameters validationParameters,
                BaseConfiguration? configuration,
                CallContext callContext)
            {
                return new CustomSignatureValidationError(
                    new MessageDetail(nameof(UnknownValidationFailure)),
                    AlgorithmValidationFailure.AlgorithmIsNotSupported,
                    Default.GetStackFrame());
            }
        }

        private class SignatureValidationFailedValidator : ISignatureValidator
        {
            public ValidationResult<SecurityKey, ValidationError> ValidateSignature(
                SecurityToken? securityToken,
                ValidationParameters validationParameters,
                BaseConfiguration? configuration,
                CallContext callContext)
            {
                return new CustomSignatureValidationError(
                    new MessageDetail(nameof(SignatureValidationFailed)),
                    SignatureValidationFailure.ValidationFailed,
                    Default.GetStackFrame());
            }
        }

        private class SignatureValidatorDelegateValidator : ISignatureValidator
        {
            public ValidationResult<SecurityKey, ValidationError> ValidateSignature(
                SecurityToken? securityToken,
                ValidationParameters validationParameters,
                BaseConfiguration? configuration,
                CallContext callContext)
            {
                return new SignatureValidationError(
                    new MessageDetail(nameof(SignatureValidatorDelegate)),
                    SignatureValidationFailure.ValidationFailed,
                    Default.GetStackFrame());
            }
        }

        private class SignatureValidatorThrowsValidator : ISignatureValidator
        {
            public ValidationResult<SecurityKey, ValidationError> ValidateSignature(
                SecurityToken? securityToken,
                ValidationParameters validationParameters,
                BaseConfiguration? configuration,
                CallContext callContext)
            {
                throw new CustomSecurityTokenInvalidSignatureException(
                    nameof(SignatureValidatorThrows),
                    new SignatureValidationError(
                        new MessageDetail(nameof(SignatureValidatorThrows)),
                        SignatureValidationFailure.ValidationFailed,
                        Default.GetStackFrame()),
                    null);
            }
        }
    }
}
#nullable restore
