// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Experimental;

#nullable enable
namespace Microsoft.IdentityModel.TestUtils
{
    internal class CustomIssuerSigningKeyValidationValidators
    {
        internal static ISignatureKeyValidator CustomValidationFailed = new CustomValidationFailedValidator();
        internal static ISignatureKeyValidator IssuerSigningKeyValidationFailed = new IssuerSigningKeyValidationFailedValidator();
        internal static ISignatureKeyValidator UnknownValidationFailure = new UnknownValidationFailureValidator();
        internal static ISignatureKeyValidator IssuerSigningKeyDelegate = new IssuerSigningKeyDelegateValidator();
        internal static ISignatureKeyValidator IssuerSigningKeyValidatorThrows = new IssuerSigningKeyValidatorThrowsValidator();

        private class CustomValidationFailedValidator : ISignatureKeyValidator
        {
            public ValidationResult<ValidatedSignatureKey, ValidationError> ValidateSignatureKey(
                SecurityKey signingKey,
                SecurityToken securityToken,
                ValidationParameters validationParameters,
                CallContext callContext)
            {
                return new CustomIssuerSigningKeyValidationError(
                    new MessageDetail(nameof(CustomValidationFailed)),
                    CustomValidationFailure.IssuerSigningKeyValidationFailed,
                    Default.GetStackFrame(),
                    signingKey,
                    null);
            }
        }

        private class IssuerSigningKeyValidationFailedValidator : ISignatureKeyValidator
        {
            public ValidationResult<ValidatedSignatureKey, ValidationError> ValidateSignatureKey(
                SecurityKey signingKey,
                SecurityToken securityToken,
                ValidationParameters validationParameters,
                CallContext callContext)
            {
                return new CustomIssuerSigningKeyValidationError(
                    new MessageDetail(nameof(IssuerSigningKeyValidationFailed)),
                    SignatureKeyValidationFailure.ValidationFailed,
                    Default.GetStackFrame(),
                    signingKey,
                    null);
            }
        }

        private class UnknownValidationFailureValidator : ISignatureKeyValidator
        {
            public ValidationResult<ValidatedSignatureKey, ValidationError> ValidateSignatureKey(
                SecurityKey signingKey,
                SecurityToken securityToken,
                ValidationParameters validationParameters,
                CallContext callContext)
            {
                return new CustomIssuerSigningKeyValidationError(
                    new MessageDetail(nameof(UnknownValidationFailure)),
                    AlgorithmValidationFailure.AlgorithmIsNotSupported,
                    Default.GetStackFrame(),
                    signingKey);
            }
        }

        private class IssuerSigningKeyDelegateValidator : ISignatureKeyValidator
        {
            public ValidationResult<ValidatedSignatureKey, ValidationError> ValidateSignatureKey(
                SecurityKey signingKey,
                SecurityToken securityToken,
                ValidationParameters validationParameters,
                CallContext callContext)
            {
                return new CustomIssuerSigningKeyValidationError(
                    new MessageDetail(nameof(IssuerSigningKeyDelegate)),
                    SignatureKeyValidationFailure.ValidationFailed,
                    Default.GetStackFrame(),
                    signingKey,
                    null);
            }
        }

        private class IssuerSigningKeyValidatorThrowsValidator : ISignatureKeyValidator
        {
            public ValidationResult<ValidatedSignatureKey, ValidationError> ValidateSignatureKey(
                SecurityKey signingKey,
                SecurityToken securityToken,
                ValidationParameters validationParameters,
                CallContext callContext)
            {
                throw new CustomSecurityTokenInvalidSigningKeyException(
                    nameof(IssuerSigningKeyValidatorThrows),
                    new SignatureKeyValidationError(
                        new MessageDetail(nameof(IssuerSigningKeyValidatorThrows)),
                        SignatureKeyValidationFailure.ValidationFailed,
                        Default.GetStackFrame(),
                        signingKey,
                        null),
                    null);
            }
        }
    }
}
#nullable restore
