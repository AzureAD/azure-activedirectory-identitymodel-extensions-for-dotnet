// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using Microsoft.Identity.Abstractions;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Experimental;

#nullable enable
namespace Microsoft.IdentityModel.TestUtils
{
    public class CustomIssuerSigningKeyValidator
    {
        public ValidationFailureType _failureType;
        public string _message;
        public Type _exceptionType;
        public CustomIssuerSigningKeyValidator(
            ValidationFailureType failureType,
            string message,
            Type exceptionType)
        {
            _failureType = failureType;
            _message = message;
            _exceptionType = exceptionType;
        }

        public OperationResult<ValidatedSigningKeyLifetime, ValidationError> Delegate(
            SecurityKey signingKey,
            SecurityToken securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            // Returns a CustomIssuerSigningKeyValidationError : IssuerSigningKeyValidationError
            return new CustomIssuerSigningKeyValidationError(
                new MessageDetail(_message, null),
                _failureType,
                _exceptionType,
                ValidationError.GetCurrentStackFrame(),
                signingKey,
                null);
        }

    }

    internal class CustomIssuerSigningKeyValidationDelegates
    {
        internal static OperationResult<ValidatedSigningKeyLifetime, ValidationError> CustomIssuerSigningKeyValidatorDelegate(
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

        internal static OperationResult<ValidatedSigningKeyLifetime, ValidationError> CustomIssuerSigningKeyValidatorCustomExceptionDelegate(
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

        internal static OperationResult<ValidatedSigningKeyLifetime, ValidationError> CustomIssuerSigningKeyValidatorCustomExceptionCustomFailureTypeDelegate(
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

        internal static OperationResult<ValidatedSigningKeyLifetime, ValidationError> CustomIssuerSigningKeyValidatorUnknownExceptionDelegate(
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

        internal static OperationResult<ValidatedSigningKeyLifetime, ValidationError> CustomIssuerSigningKeyValidatorWithoutGetExceptionOverrideDelegate(
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

        internal static OperationResult<ValidatedSigningKeyLifetime, ValidationError> IssuerSigningKeyValidatorDelegate(
            SecurityKey signingKey,
            SecurityToken securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            return new IssuerSigningKeyValidationError(
                new MessageDetail(nameof(IssuerSigningKeyValidatorDelegate), null),
                ValidationFailureType.SigningKeyValidationFailed,
                ValidationError.GetCurrentStackFrame(),
                signingKey,
                null);
        }

        internal static OperationResult<ValidatedSigningKeyLifetime, ValidationError> IssuerSigningKeyValidatorThrows(
            SecurityKey signingKey,
            SecurityToken securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            throw new CustomSecurityTokenInvalidSigningKeyException(
                nameof(IssuerSigningKeyValidatorThrows),
                new IssuerSigningKeyValidationError(
                    new MessageDetail(nameof(IssuerSigningKeyValidatorDelegate), null),
                    ValidationFailureType.SigningKeyValidationFailed,
                    ValidationError.GetCurrentStackFrame(),
                    signingKey,
                    null),
                null);
        }

        internal static OperationResult<ValidatedSigningKeyLifetime, ValidationError> IssuerSigningKeyValidatorCustomIssuerSigningKeyExceptionTypeDelegate(
            SecurityKey signingKey,
            SecurityToken securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            return new IssuerSigningKeyValidationError(
                new MessageDetail(nameof(IssuerSigningKeyValidatorCustomIssuerSigningKeyExceptionTypeDelegate), null),
                ValidationFailureType.SigningKeyValidationFailed,
                ValidationError.GetCurrentStackFrame(),
                signingKey,
                null);
        }

        internal static OperationResult<ValidatedSigningKeyLifetime, ValidationError> IssuerSigningKeyValidatorCustomExceptionTypeDelegate(
            SecurityKey signingKey,
            SecurityToken securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            return new IssuerSigningKeyValidationError(
                new MessageDetail(nameof(IssuerSigningKeyValidatorCustomExceptionTypeDelegate), null),
                ValidationFailureType.SigningKeyValidationFailed,
                ValidationError.GetCurrentStackFrame(),
                signingKey,
                null);
        }
    }
}
#nullable restore
