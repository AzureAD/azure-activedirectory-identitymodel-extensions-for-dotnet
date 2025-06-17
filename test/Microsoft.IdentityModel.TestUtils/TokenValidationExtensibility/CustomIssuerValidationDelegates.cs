// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Identity.Abstractions;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Experimental;

#nullable enable
namespace Microsoft.IdentityModel.TestUtils
{
    internal class CustomIssuerValidationDelegates
    {
        internal async static Task<OperationResult<ValidatedIssuer, ValidationError>> CustomIssuerValidatorDelegateAsync(
            string issuer,
            SecurityToken securityToken,
            ValidationParameters validationParameters,
            CallContext callContext,
            CancellationToken cancellationToken)
        {
            // Returns a CustomIssuerValidationError : ValidationError
            return await Task.FromResult(new OperationResult<ValidatedIssuer, ValidationError>(
                new CustomIssuerValidationError(
                    new MessageDetail(nameof(CustomIssuerValidatorDelegateAsync), null),
                    ValidationFailureType.IssuerValidationFailed,
                    typeof(SecurityTokenInvalidIssuerException),
                    ValidationError.GetCurrentStackFrame(),
                    issuer)));
        }

        internal async static Task<OperationResult<ValidatedIssuer, ValidationError>> CustomIssuerValidatorCustomExceptionDelegateAsync(
            string issuer,
            SecurityToken securityToken,
            ValidationParameters validationParameters,
            CallContext callContext,
            CancellationToken cancellationToken)
        {
            return await Task.FromResult(new OperationResult<ValidatedIssuer, ValidationError>(
                new CustomIssuerValidationError(
                    new MessageDetail(nameof(CustomIssuerValidatorCustomExceptionDelegateAsync), null),
                    ValidationFailureType.IssuerValidationFailed,
                    typeof(CustomSecurityTokenInvalidIssuerException),
                    ValidationError.GetCurrentStackFrame(),
                    issuer)));
        }

        internal async static Task<OperationResult<ValidatedIssuer, ValidationError>> CustomIssuerValidatorCustomExceptionCustomFailureTypeDelegateAsync(
            string issuer,
            SecurityToken securityToken,
            ValidationParameters validationParameters,
            CallContext callContext,
            CancellationToken cancellationToken)
        {
            return await Task.FromResult(new OperationResult<ValidatedIssuer, ValidationError>(
                new CustomIssuerValidationError(
                    new MessageDetail(nameof(CustomIssuerValidatorCustomExceptionCustomFailureTypeDelegateAsync), null),
                    CustomIssuerValidationError.CustomIssuerValidationFailureType,
                    typeof(CustomSecurityTokenInvalidIssuerException),
                    ValidationError.GetCurrentStackFrame(),
                    issuer,
                    null)));
        }

        internal async static Task<OperationResult<ValidatedIssuer, ValidationError>> CustomIssuerValidatorUnknownExceptionDelegateAsync(
            string issuer,
            SecurityToken securityToken,
            ValidationParameters validationParameters,
            CallContext callContext,
            CancellationToken cancellationToken)
        {
            return await Task.FromResult(new OperationResult<ValidatedIssuer, ValidationError>(
                new CustomIssuerValidationError(
                    new MessageDetail(nameof(CustomIssuerValidatorUnknownExceptionDelegateAsync), null),
                    ValidationFailureType.IssuerValidationFailed,
                    typeof(NotSupportedException),
                    ValidationError.GetCurrentStackFrame(),
                    issuer)));
        }

        internal async static Task<OperationResult<ValidatedIssuer, ValidationError>> CustomIssuerValidatorWithoutGetExceptionOverrideDelegateAsync(
            string issuer,
            SecurityToken securityToken,
            ValidationParameters validationParameters,
            CallContext callContext,
            CancellationToken cancellationToken)
        {
            return await Task.FromResult(new OperationResult<ValidatedIssuer, ValidationError>(
                new CustomIssuerWithoutGetExceptionValidationOverrideError(
                    new MessageDetail(nameof(CustomIssuerValidatorWithoutGetExceptionOverrideDelegateAsync), null),
                    typeof(CustomSecurityTokenInvalidIssuerException),
                    ValidationError.GetCurrentStackFrame(),
                    issuer)));
        }

        internal async static Task<OperationResult<ValidatedIssuer, ValidationError>> IssuerValidatorDelegateAsync(
            string issuer,
            SecurityToken securityToken,
            ValidationParameters validationParameters,
            CallContext callContext,
            CancellationToken cancellationToken)
        {
            return await Task.FromResult(new OperationResult<ValidatedIssuer, ValidationError>(
                new IssuerValidationError(
                    new MessageDetail(nameof(IssuerValidatorDelegateAsync), null),
                    ValidationFailureType.IssuerValidationFailed,
                    ValidationError.GetCurrentStackFrame(),
                    issuer)));
        }

        internal static Task<OperationResult<ValidatedIssuer, ValidationError>> IssuerValidatorThrows(
            string issuer,
            SecurityToken securityToken,
            ValidationParameters validationParameters,
            CallContext callContext,
            CancellationToken cancellationToken)
        {
            throw new CustomSecurityTokenInvalidIssuerException(
                nameof(IssuerValidatorThrows),
                new IssuerValidationError(
                    new MessageDetail(nameof(IssuerValidatorDelegateAsync), null),
                    ValidationFailureType.IssuerValidationFailed,
                    ValidationError.GetCurrentStackFrame(),
                    issuer),
                null);
        }

        internal async static Task<OperationResult<ValidatedIssuer, ValidationError>> IssuerValidatorCustomIssuerExceptionTypeDelegateAsync(
            string issuer,
            SecurityToken securityToken,
            ValidationParameters validationParameters,
            CallContext callContext,
            CancellationToken cancellationToken)
        {
            return await Task.FromResult(new OperationResult<ValidatedIssuer, ValidationError>(
                new IssuerValidationError(
                    new MessageDetail(nameof(IssuerValidatorCustomIssuerExceptionTypeDelegateAsync), null),
                    ValidationFailureType.IssuerValidationFailed,
                    ValidationError.GetCurrentStackFrame(),
                    issuer)));
        }
        internal async static Task<OperationResult<ValidatedIssuer, ValidationError>> IssuerValidatorCustomExceptionTypeDelegateAsync(
            string issuer,
            SecurityToken securityToken,
            ValidationParameters validationParameters,
            CallContext callContext,
            CancellationToken cancellationToken)
        {
            return await Task.FromResult(new OperationResult<ValidatedIssuer, ValidationError>(
                new IssuerValidationError(
                    new MessageDetail(nameof(IssuerValidatorCustomExceptionTypeDelegateAsync), null),
                    ValidationFailureType.IssuerValidationFailed,
                    ValidationError.GetCurrentStackFrame(),
                    issuer)));
        }
    }
}
#nullable restore
