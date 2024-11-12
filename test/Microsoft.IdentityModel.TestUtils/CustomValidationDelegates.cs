// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;

#nullable enable
namespace Microsoft.IdentityModel.TestUtils
{
    #region IssuerValidationDelegates
    internal class CustomIssuerValidatorDelegates
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
                    typeof(CustomSecurityTokenException),
                    ValidationError.GetCurrentStackFrame(),
                    issuer)));
        }
    }
    #endregion

    #region AudienceValidationDelegates
    internal class CustomAudienceValidatorDelegates
    {
        internal static ValidationResult<string> CustomAudienceValidatorDelegate(
            IList<string> tokenAudiences,
            SecurityToken? securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            // Returns a CustomAudienceValidationError : AudienceValidationError
            return new CustomAudienceValidationError(
                new MessageDetail(nameof(CustomAudienceValidatorDelegate), null),
                ValidationFailureType.AudienceValidationFailed,
                typeof(SecurityTokenInvalidAudienceException),
                ValidationError.GetCurrentStackFrame(),
                tokenAudiences,
                null);
        }

        internal static ValidationResult<string> CustomAudienceValidatorCustomExceptionDelegate(
            IList<string> tokenAudiences,
            SecurityToken? securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            return new CustomAudienceValidationError(
                new MessageDetail(nameof(CustomAudienceValidatorCustomExceptionDelegate), null),
                ValidationFailureType.AudienceValidationFailed,
                typeof(CustomSecurityTokenInvalidAudienceException),
                ValidationError.GetCurrentStackFrame(),
                tokenAudiences,
                null);
        }

        internal static ValidationResult<string> CustomAudienceValidatorCustomExceptionCustomFailureTypeDelegate(
            IList<string> tokenAudiences,
            SecurityToken? securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            return new CustomAudienceValidationError(
                new MessageDetail(nameof(CustomAudienceValidatorCustomExceptionCustomFailureTypeDelegate), null),
                CustomAudienceValidationError.CustomAudienceValidationFailureType,
                typeof(CustomSecurityTokenInvalidAudienceException),
                ValidationError.GetCurrentStackFrame(),
                tokenAudiences,
                null);
        }

        internal static ValidationResult<string> CustomAudienceValidatorUnknownExceptionDelegate(
            IList<string> tokenAudiences,
            SecurityToken? securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            return new CustomAudienceValidationError(
                new MessageDetail(nameof(CustomAudienceValidatorUnknownExceptionDelegate), null),
                ValidationFailureType.AudienceValidationFailed,
                typeof(NotSupportedException),
                ValidationError.GetCurrentStackFrame(),
                tokenAudiences,
                null);
        }

        internal static ValidationResult<string> CustomAudienceValidatorWithoutGetExceptionOverrideDelegate(
            IList<string> tokenAudiences,
            SecurityToken? securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            return new CustomAudienceWithoutGetExceptionValidationOverrideError(
                new MessageDetail(nameof(CustomAudienceValidatorWithoutGetExceptionOverrideDelegate), null),
                ValidationFailureType.AudienceValidationFailed,
                typeof(CustomSecurityTokenInvalidAudienceException),
                ValidationError.GetCurrentStackFrame(),
                tokenAudiences,
                null);
        }

        internal static ValidationResult<string> AudienceValidatorDelegate(
            IList<string> tokenAudiences,
            SecurityToken? securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            return new AudienceValidationError(
                new MessageDetail(nameof(AudienceValidatorDelegate), null),
                ValidationFailureType.AudienceValidationFailed,
                typeof(SecurityTokenInvalidAudienceException),
                ValidationError.GetCurrentStackFrame(),
                tokenAudiences,
                null);
        }

        internal static ValidationResult<string> AudienceValidatorThrows(
            IList<string> tokenAudiences,
            SecurityToken? securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            throw new CustomSecurityTokenInvalidAudienceException(nameof(AudienceValidatorThrows), null);
        }

        internal static ValidationResult<string> AudienceValidatorCustomAudienceExceptionTypeDelegate(
            IList<string> tokenAudiences,
            SecurityToken? securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            return new AudienceValidationError(
                new MessageDetail(nameof(AudienceValidatorCustomAudienceExceptionTypeDelegate), null),
                ValidationFailureType.AudienceValidationFailed,
                typeof(CustomSecurityTokenInvalidAudienceException),
                ValidationError.GetCurrentStackFrame(),
                tokenAudiences,
                null);
        }

        internal static ValidationResult<string> AudienceValidatorCustomExceptionTypeDelegate(
            IList<string> tokenAudiences,
            SecurityToken? securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            return new AudienceValidationError(
                new MessageDetail(nameof(AudienceValidatorCustomExceptionTypeDelegate), null),
                ValidationFailureType.AudienceValidationFailed,
                typeof(CustomSecurityTokenException),
                ValidationError.GetCurrentStackFrame(),
                tokenAudiences,
                null);
        }
    }
    #endregion
}
#nullable restore
