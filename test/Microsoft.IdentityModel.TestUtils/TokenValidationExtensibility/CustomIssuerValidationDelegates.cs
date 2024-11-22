// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;

#nullable enable
namespace Microsoft.IdentityModel.TestUtils
{
    internal class CustomIssuerValidationDelegates
    {
        internal async static Task<ValidationResult<ValidatedIssuer>> CustomIssuerValidatorDelegateAsync(
            string issuer,
            SecurityToken securityToken,
            ValidationParameters validationParameters,
            CallContext callContext,
            CancellationToken cancellationToken)
        {
            // Returns a CustomIssuerValidationError : IssuerValidationError
            return await Task.FromResult(new ValidationResult<ValidatedIssuer>(
                new CustomIssuerValidationError(
                    new MessageDetail(nameof(CustomIssuerValidatorDelegateAsync), null),
                    ValidationFailureType.IssuerValidationFailed,
                    typeof(SecurityTokenInvalidIssuerException),
                    ValidationError.GetCurrentStackFrame(),
                    issuer)));
        }

        internal async static Task<ValidationResult<ValidatedIssuer>> CustomIssuerValidatorCustomExceptionDelegateAsync(
            string issuer,
            SecurityToken securityToken,
            ValidationParameters validationParameters,
            CallContext callContext,
            CancellationToken cancellationToken)
        {
            return await Task.FromResult(new ValidationResult<ValidatedIssuer>(
                new CustomIssuerValidationError(
                    new MessageDetail(nameof(CustomIssuerValidatorCustomExceptionDelegateAsync), null),
                    ValidationFailureType.IssuerValidationFailed,
                    typeof(CustomSecurityTokenInvalidIssuerException),
                    ValidationError.GetCurrentStackFrame(),
                    issuer)));
        }

        internal async static Task<ValidationResult<ValidatedIssuer>> CustomIssuerValidatorCustomExceptionCustomFailureTypeDelegateAsync(
            string issuer,
            SecurityToken securityToken,
            ValidationParameters validationParameters,
            CallContext callContext,
            CancellationToken cancellationToken)
        {
            return await Task.FromResult(new ValidationResult<ValidatedIssuer>(
                new CustomIssuerValidationError(
                    new MessageDetail(nameof(CustomIssuerValidatorCustomExceptionCustomFailureTypeDelegateAsync), null),
                    CustomIssuerValidationError.CustomIssuerValidationFailureType,
                    typeof(CustomSecurityTokenInvalidIssuerException),
                    ValidationError.GetCurrentStackFrame(),
                    issuer,
                    null)));
        }

        internal async static Task<ValidationResult<ValidatedIssuer>> CustomIssuerValidatorUnknownExceptionDelegateAsync(
            string issuer,
            SecurityToken securityToken,
            ValidationParameters validationParameters,
            CallContext callContext,
            CancellationToken cancellationToken)
        {
            return await Task.FromResult(new ValidationResult<ValidatedIssuer>(
                new CustomIssuerValidationError(
                    new MessageDetail(nameof(CustomIssuerValidatorUnknownExceptionDelegateAsync), null),
                    ValidationFailureType.IssuerValidationFailed,
                    typeof(NotSupportedException),
                    ValidationError.GetCurrentStackFrame(),
                    issuer)));
        }

        internal async static Task<ValidationResult<ValidatedIssuer>> CustomIssuerValidatorWithoutGetExceptionOverrideDelegateAsync(
            string issuer,
            SecurityToken securityToken,
            ValidationParameters validationParameters,
            CallContext callContext,
            CancellationToken cancellationToken)
        {
            return await Task.FromResult(new ValidationResult<ValidatedIssuer>(
                new CustomIssuerWithoutGetExceptionValidationOverrideError(
                    new MessageDetail(nameof(CustomIssuerValidatorWithoutGetExceptionOverrideDelegateAsync), null),
                    typeof(CustomSecurityTokenInvalidIssuerException),
                    ValidationError.GetCurrentStackFrame(),
                    issuer)));
        }

        internal async static Task<ValidationResult<ValidatedIssuer>> IssuerValidatorDelegateAsync(
            string issuer,
            SecurityToken securityToken,
            ValidationParameters validationParameters,
            CallContext callContext,
            CancellationToken cancellationToken)
        {
            return await Task.FromResult(new ValidationResult<ValidatedIssuer>(
                new IssuerValidationError(
                    new MessageDetail(nameof(IssuerValidatorDelegateAsync), null),
                    ValidationFailureType.IssuerValidationFailed,
                    typeof(SecurityTokenInvalidIssuerException),
                    ValidationError.GetCurrentStackFrame(),
                    issuer)));
        }

        internal static Task<ValidationResult<ValidatedIssuer>> IssuerValidatorThrows(
            string issuer,
            SecurityToken securityToken,
            ValidationParameters validationParameters,
            CallContext callContext,
            CancellationToken cancellationToken)
        {
            throw new CustomSecurityTokenInvalidIssuerException(nameof(IssuerValidatorThrows), null);
        }

        internal async static Task<ValidationResult<ValidatedIssuer>> IssuerValidatorCustomIssuerExceptionTypeDelegateAsync(
            string issuer,
            SecurityToken securityToken,
            ValidationParameters validationParameters,
            CallContext callContext,
            CancellationToken cancellationToken)
        {
            return await Task.FromResult(new ValidationResult<ValidatedIssuer>(
                new IssuerValidationError(
                    new MessageDetail(nameof(IssuerValidatorCustomIssuerExceptionTypeDelegateAsync), null),
                    ValidationFailureType.IssuerValidationFailed,
                    typeof(CustomSecurityTokenInvalidIssuerException),
                    ValidationError.GetCurrentStackFrame(),
                    issuer)));
        }
        internal async static Task<ValidationResult<ValidatedIssuer>> IssuerValidatorCustomExceptionTypeDelegateAsync(
            string issuer,
            SecurityToken securityToken,
            ValidationParameters validationParameters,
            CallContext callContext,
            CancellationToken cancellationToken)
        {
            return await Task.FromResult(new ValidationResult<ValidatedIssuer>(
                new IssuerValidationError(
                    new MessageDetail(nameof(IssuerValidatorCustomExceptionTypeDelegateAsync), null),
                    ValidationFailureType.IssuerValidationFailed,
                    typeof(CustomSecurityTokenException),
                    ValidationError.GetCurrentStackFrame(),
                    issuer)));
        }
    }
}
#nullable restore
